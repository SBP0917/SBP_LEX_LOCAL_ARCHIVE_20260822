from __future__ import annotations

import importlib.metadata as metadata
import json
import os
import platform
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from packaging.requirements import Requirement

from sbp_lex.runtime.measured_startup import approved_baseline, load_baseline_store, validate_baseline_store
from sbp_lex.security.pqc import generate_digest, pqc_provider_status

from .common import DESKTOP_SCOPE, HEX40, HEX64, R2_VERSION, SupplyChainError, file_sha256, portable_path, resolve_file

EXPECTED_REPOSITORY_IDENTITY = "github.com/SBP0917/SBP_LEX_DUAL_V6"
CANONICAL_BRANCH = "main"


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise SupplyChainError("git_unavailable") from exc
    if result.returncode != 0 or result.stderr.strip():
        raise SupplyChainError("git_provenance_unavailable")
    return result.stdout.strip()


def normalize_repository_identity(remote: str) -> str:
    value = remote.strip().replace("\\", "/")
    if value.startswith("git@github.com:"):
        value = "github.com/" + value.split(":", 1)[1]
    elif value.startswith("https://"):
        value = value[len("https://"):]
    elif value.startswith("http://"):
        value = value[len("http://"):]
    if value.endswith(".git"):
        value = value[:-4]
    return value.rstrip("/")


def collect_repository_provenance(root: Path) -> dict[str, Any]:
    commit = _git(root, "rev-parse", "HEAD")
    branch = _git(root, "branch", "--show-current")
    remote = _git(root, "remote", "get-url", "origin")
    identity = normalize_repository_identity(remote)
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    lineage = _git(root, "rev-list", "--first-parent", "--max-count=32", "HEAD").splitlines()
    record = {
        "provenance_version": R2_VERSION,
        "desktop_scope": DESKTOP_SCOPE,
        "repository_identity": identity,
        "canonical_branch": branch,
        "repository_commit": commit,
        "repository_tree": tree,
        "parent_lineage": lineage,
        "lineage_depth_recorded": len(lineage),
        "origin_kind": "canonical_origin",
    }
    record["repository_digest"] = generate_digest(record)
    validate_repository_provenance(record, root)
    return record


def validate_repository_provenance(record: Mapping[str, Any], root: Path) -> None:
    digest = record.get("repository_digest")
    core = {key: value for key, value in record.items() if key != "repository_digest"}
    if not HEX64.fullmatch(str(digest)) or digest != generate_digest(core):
        raise SupplyChainError("repository_digest_mismatch")
    if record.get("repository_identity") != EXPECTED_REPOSITORY_IDENTITY:
        raise SupplyChainError("unknown_repository")
    if record.get("canonical_branch") != CANONICAL_BRANCH:
        raise SupplyChainError("noncanonical_branch")
    commit = str(record.get("repository_commit", ""))
    lineage = record.get("parent_lineage")
    if not HEX40.fullmatch(commit) or not isinstance(lineage, list) or not lineage or lineage[0] != commit:
        raise SupplyChainError("detached_lineage")
    if len(lineage) != len(set(lineage)) or any(not HEX40.fullmatch(str(item)) for item in lineage):
        raise SupplyChainError("ambiguous_lineage")
    if normalize_repository_identity(_git(root, "remote", "get-url", "origin")) != record["repository_identity"]:
        raise SupplyChainError("foreign_repository")
    if _git(root, "merge-base", "--is-ancestor", commit, "HEAD") != "":
        raise SupplyChainError("rewritten_history")
    if _git(root, "rev-parse", f"{commit}^{{tree}}") != record.get("repository_tree"):
        raise SupplyChainError("repository_tree_mismatch")


def _requirement_lines(root: Path) -> list[Requirement]:
    path = resolve_file(root, "requirements.txt", label="requirements")
    requirements: list[Requirement] = []
    for raw in path.read_text("utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            requirements.append(Requirement(line))
        except Exception as exc:
            raise SupplyChainError("dependency_declaration_invalid") from exc
    if not requirements:
        raise SupplyChainError("dependency_declaration_empty")
    return requirements


def _distribution(name: str) -> metadata.Distribution:
    try:
        return metadata.distribution(name)
    except metadata.PackageNotFoundError as exc:
        raise SupplyChainError(f"missing_dependency:{name.lower()}") from exc


def _distribution_hash(distribution: metadata.Distribution) -> tuple[str, int, int]:
    records: list[dict[str, Any]] = []
    for item in sorted(distribution.files or (), key=lambda value: str(value).lower()):
        path = Path(distribution.locate_file(item))
        if not path.is_file() or path.is_symlink():
            raise SupplyChainError(f"dependency_file_missing:{distribution.metadata.get('Name', 'unknown').lower()}")
        records.append({
            "path": str(item).replace("\\", "/"),
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        })
    if not records:
        raise SupplyChainError("dependency_files_unavailable")
    return generate_digest({"files": records}), len(records), sum(item["size_bytes"] for item in records)


def _licence(distribution: metadata.Distribution) -> str:
    expression = distribution.metadata.get("License-Expression")
    if expression:
        return expression.strip()
    classifiers = distribution.metadata.get_all("Classifier") or []
    licences = sorted(item.split(" :: ")[-1] for item in classifiers if item.startswith("License ::"))
    raw = distribution.metadata.get("License")
    return "; ".join(licences) or (raw.strip() if raw and len(raw.strip()) <= 256 else "UNKNOWN")


def _source(distribution: metadata.Distribution) -> str:
    urls = sorted(distribution.metadata.get_all("Project-URL") or [])
    home = distribution.metadata.get("Home-page")
    installer = "UNKNOWN"
    try:
        installer = (distribution.read_text("INSTALLER") or "UNKNOWN").strip()
    except OSError:
        pass
    return f"installer:{installer};metadata:{(urls[0] if urls else home) or 'UNSPECIFIED'}"


def collect_dependency_provenance(root: Path) -> dict[str, Any]:
    direct = _requirement_lines(root)
    queue: list[tuple[str, str | None]] = [(item.name, None) for item in direct]
    direct_by_name = {item.name.lower(): item for item in direct}
    parents: dict[str, set[str]] = {item.name.lower(): set() for item in direct}
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    while queue:
        raw_name, parent = queue.pop(0)
        name = raw_name.lower()
        if parent:
            parents.setdefault(name, set()).add(parent)
        if name in seen:
            continue
        distribution = _distribution(raw_name)
        canonical_name = str(distribution.metadata.get("Name") or raw_name)
        version = distribution.version
        declared = direct_by_name.get(name)
        if declared is not None and version not in declared.specifier:
            raise SupplyChainError(f"unapproved_dependency_version:{name}")
        aggregate, file_count, size = _distribution_hash(distribution)
        record = {
            "package": canonical_name,
            "normalized_name": name,
            "version": version,
            "relationship": "DIRECT" if declared is not None else "TRANSITIVE",
            "declared_requirement": str(declared) if declared is not None else None,
            "required_by": sorted(parents.get(name, set())),
            "source": _source(distribution),
            "licence": _licence(distribution),
            "distribution_sha256": aggregate,
            "distribution_file_count": file_count,
            "distribution_size_bytes": size,
            "approval_status": "APPROVED",
            "integrity_status": "VERIFIED",
        }
        records.append(record)
        seen.add(name)
        for raw_requirement in distribution.requires or ():
            requirement = Requirement(raw_requirement)
            if requirement.marker is not None and not requirement.marker.evaluate():
                continue
            queue.append((requirement.name, name))
    for record in records:
        record["required_by"] = sorted(parents.get(record["normalized_name"], set()))
    records.sort(key=lambda item: (item["normalized_name"], item["version"]))
    result = {
        "sbom_version": "R2_DESKTOP_V1_SBOM_V1",
        "desktop_scope": DESKTOP_SCOPE,
        "dependency_count": len(records),
        "direct_dependency_count": sum(item["relationship"] == "DIRECT" for item in records),
        "transitive_dependency_count": sum(item["relationship"] == "TRANSITIVE" for item in records),
        "dependencies": records,
    }
    result["dependency_digest"] = generate_digest(result)
    validate_dependency_provenance(result)
    return result


def validate_dependency_provenance(sbom: Mapping[str, Any], *, verify_installed: bool = True) -> None:
    digest = sbom.get("dependency_digest")
    core = {key: value for key, value in sbom.items() if key != "dependency_digest"}
    if not HEX64.fullmatch(str(digest)) or digest != generate_digest(core):
        raise SupplyChainError("dependency_digest_mismatch")
    records = sbom.get("dependencies")
    if not isinstance(records, list) or not records:
        raise SupplyChainError("dependency_provenance_missing")
    names = [item.get("normalized_name") for item in records if isinstance(item, Mapping)]
    if len(names) != len(records) or len(names) != len(set(names)):
        raise SupplyChainError("duplicate_dependency_identity")
    if names != sorted(names):
        raise SupplyChainError("dependency_order_nondeterministic")
    for item in records:
        if item.get("approval_status") != "APPROVED" or item.get("integrity_status") != "VERIFIED":
            raise SupplyChainError("dependency_unapproved")
        if not HEX64.fullmatch(str(item.get("distribution_sha256", ""))):
            raise SupplyChainError("dependency_hash_invalid")
        if verify_installed:
            distribution = _distribution(str(item["package"]))
            if distribution.version != item.get("version"):
                raise SupplyChainError(f"dependency_version_mismatch:{item['normalized_name']}")
            aggregate, count, size = _distribution_hash(distribution)
            if (aggregate, count, size) != (item["distribution_sha256"], item["distribution_file_count"], item["distribution_size_bytes"]):
                raise SupplyChainError(f"dependency_substitution:{item['normalized_name']}")


def measured_linkage(root: Path) -> dict[str, Any]:
    store = load_baseline_store(root / "sbp_lex/runtime/approved_runtime_baselines.json")
    payload = validate_baseline_store(store)
    baseline = approved_baseline(payload)
    return {
        "measured_baseline_identifier": baseline["baseline_identifier"],
        "measured_baseline_sequence": baseline["sequence"],
        "measurement_digest": baseline["measurement_digest"],
        "runtime_identity": baseline["runtime_identity"],
    }


def collect_build_provenance(root: Path, repository: Mapping[str, Any]) -> dict[str, Any]:
    executable = Path(sys.executable)
    linkage = measured_linkage(root)
    toolchain = resolve_file(root, "outputs/local_toolchain_guard.json", label="toolchain_guard")
    record = {
        "build_provenance_version": R2_VERSION,
        "desktop_scope": DESKTOP_SCOPE,
        "repository_commit": repository["repository_commit"],
        **linkage,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "architecture": platform.machine(),
            "executable_name": executable.name,
            "executable_sha256": file_sha256(executable),
        },
        "operating_system": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "toolchain_guard_sha256": file_sha256(toolchain),
        "pqc_provider": pqc_provider_status(),
        "cryptographic_provider": {"package": "cryptography", "version": metadata.version("cryptography")},
        "environment_policy": "LOCAL_OFFLINE_APPROVED_TOOLCHAIN_ONLY",
    }
    record["build_identity"] = generate_digest(record)
    validate_build_provenance(record, root, repository)
    return record


def validate_build_provenance(record: Mapping[str, Any], root: Path, repository: Mapping[str, Any]) -> None:
    identity = record.get("build_identity")
    core = {key: value for key, value in record.items() if key != "build_identity"}
    if identity != generate_digest(core):
        raise SupplyChainError("build_identity_mismatch")
    if record.get("repository_commit") != repository.get("repository_commit"):
        raise SupplyChainError("foreign_build")
    linkage = measured_linkage(root)
    for key, value in linkage.items():
        if record.get(key) != value:
            raise SupplyChainError(f"{key}_mismatch")
    python = record.get("python")
    if not isinstance(python, Mapping) or python.get("executable_sha256") != file_sha256(Path(sys.executable)):
        raise SupplyChainError("interpreter_substitution")
    if record.get("toolchain_guard_sha256") != file_sha256(resolve_file(root, "outputs/local_toolchain_guard.json", label="toolchain_guard")):
        raise SupplyChainError("toolchain_substitution")
    provider = record.get("pqc_provider")
    if not isinstance(provider, Mapping) or provider.get("provider_available") is not True or provider.get("fail_closed") is not True:
        raise SupplyChainError("pqc_provider_unapproved")


def artifact_records(root: Path, paths: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    identities: set[str] = set()
    for raw in sorted(set(paths)):
        relative = portable_path(raw, label="artifact_path")
        path = resolve_file(root, relative, label="artifact")
        identity = relative.lower().replace("/", ".")
        if identity in identities:
            raise SupplyChainError("duplicate_artifact_identity")
        identities.add(identity)
        suffix = path.suffix.lower()
        relationship = "GENERATED_EVIDENCE" if relative.startswith("outputs/") else "REPOSITORY_SOURCE"
        if relative.startswith("reports/"):
            relationship = "PROTECTED_REPORT"
        records.append({
            "logical_identity": identity,
            "path": relative,
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
            "repository_origin": EXPECTED_REPOSITORY_IDENTITY,
            "creation_relationship": relationship,
            "artefact_type": suffix[1:] if suffix else "binary",
        })
    return records


def validate_artifact_records(records: Any, root: Path) -> None:
    if not isinstance(records, list) or not records:
        raise SupplyChainError("artifact_inventory_missing")
    identities: set[str] = set()
    paths: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise SupplyChainError("artifact_record_invalid")
        identity = record.get("logical_identity")
        relative = record.get("path")
        if identity in identities or relative in paths:
            raise SupplyChainError("duplicate_artifact_identity")
        identities.add(str(identity)); paths.add(str(relative))
        path = resolve_file(root, str(relative), label="artifact")
        if record.get("repository_origin") != EXPECTED_REPOSITORY_IDENTITY:
            raise SupplyChainError("artifact_foreign_origin")
        if record.get("sha256") != file_sha256(path) or record.get("size_bytes") != path.stat().st_size:
            raise SupplyChainError(f"artifact_substitution:{relative}")
