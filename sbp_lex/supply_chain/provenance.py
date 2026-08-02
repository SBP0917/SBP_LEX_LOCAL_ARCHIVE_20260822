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

from sbp_lex.local_trust.git_provenance import (
    generated_evidence_lineage_is_bounded,
)
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.runtime.measured_startup import (
    approved_baseline,
    configured_baseline_path,
    load_baseline_store,
    validate_baseline_store,
)
from sbp_lex.security.pqc import generate_digest, pqc_provider_status

from .common import DESKTOP_SCOPE, HEX40, HEX64, R2_VERSION, SupplyChainError, file_sha256, portable_path, resolve_file

EXPECTED_REPOSITORY_IDENTITY = "github.com/SBP0917/SBP_LEX_DUAL_V6"
CANONICAL_BRANCH = "main"
CANONICAL_UPSTREAM = "origin/main"
PRODUCTION_TRUSTED_REPOSITORY_ANCHOR_COMMIT = (
    "1f6d63422aeab848a8d4f26a6f8a46e3125c780a"
)
TRUSTED_REPOSITORY_ANCHOR_COMMIT = (
    PRODUCTION_TRUSTED_REPOSITORY_ANCHOR_COMMIT
)
REPOSITORY_PROVENANCE_FIELDS = frozenset({
    "provenance_version",
    "desktop_scope",
    "repository_identity",
    "canonical_branch",
    "repository_commit",
    "repository_tree",
    "parent_lineage",
    "lineage_depth_recorded",
    "trusted_repository_anchor_commit",
    "trusted_repository_anchor_tree",
    "upstream_reference",
    "tracked_working_tree_clean",
    "untracked_files_checked",
    "origin_kind",
    "repository_digest",
})
DEPENDENCY_SBOM_FIELDS = frozenset({
    "sbom_version",
    "desktop_scope",
    "dependency_count",
    "direct_dependency_count",
    "transitive_dependency_count",
    "dependencies",
    "dependency_digest",
})
DEPENDENCY_RECORD_FIELDS = frozenset({
    "package",
    "normalized_name",
    "version",
    "relationship",
    "declared_requirement",
    "required_by",
    "source",
    "licence",
    "distribution_sha256",
    "distribution_file_count",
    "distribution_size_bytes",
    "approval_status",
    "integrity_status",
})
BUILD_PROVENANCE_FIELDS = frozenset({
    "build_provenance_version",
    "desktop_scope",
    "repository_commit",
    "measured_baseline_identifier",
    "measured_baseline_sequence",
    "measurement_digest",
    "runtime_identity",
    "python",
    "operating_system",
    "toolchain_guard_sha256",
    "pqc_provider",
    "cryptographic_provider",
    "environment_policy",
    "build_identity",
})
ARTIFACT_RECORD_FIELDS = frozenset({
    "logical_identity",
    "path",
    "sha256",
    "size_bytes",
    "repository_origin",
    "repository_blob",
    "repository_blob_sha256",
    "repository_blob_size_bytes",
    "tracked_at_repository_commit",
    "creation_relationship",
    "artefact_type",
})


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise SupplyChainError("git_unavailable") from exc
    if result.returncode != 0 or result.stderr.strip():
        raise SupplyChainError("git_provenance_unavailable")
    return result.stdout.strip()


def _git_bytes(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=False,
            check=False,
        )
    except OSError as exc:
        raise SupplyChainError("git_unavailable") from exc
    if result.returncode != 0 or result.stderr.strip():
        raise SupplyChainError("git_provenance_unavailable")
    return result.stdout


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
    anchor_tree = _git(
        root, "rev-parse", f"{TRUSTED_REPOSITORY_ANCHOR_COMMIT}^{{tree}}",
    )
    upstream = _git(
        root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}",
    )
    tracked_status = _git(
        root, "status", "--porcelain=v1", "--untracked-files=all",
    )
    if tracked_status:
        raise SupplyChainError("tracked_working_tree_dirty")
    _git(
        root, "merge-base", "--is-ancestor",
        TRUSTED_REPOSITORY_ANCHOR_COMMIT, commit,
    )
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
        "trusted_repository_anchor_commit": TRUSTED_REPOSITORY_ANCHOR_COMMIT,
        "trusted_repository_anchor_tree": anchor_tree,
        "upstream_reference": upstream,
        "tracked_working_tree_clean": True,
        "untracked_files_checked": True,
        "origin_kind": "canonical_origin",
    }
    record["repository_digest"] = generate_digest(record)
    validate_repository_provenance(record, root)
    return record


def validate_repository_provenance(record: Mapping[str, Any], root: Path) -> None:
    if set(record) != REPOSITORY_PROVENANCE_FIELDS:
        raise SupplyChainError("repository_provenance_schema_invalid")
    digest = record.get("repository_digest")
    core = {key: value for key, value in record.items() if key != "repository_digest"}
    if not HEX64.fullmatch(str(digest)) or digest != generate_digest(core):
        raise SupplyChainError("repository_digest_mismatch")
    if record.get("repository_identity") != EXPECTED_REPOSITORY_IDENTITY:
        raise SupplyChainError("unknown_repository")
    if record.get("canonical_branch") != CANONICAL_BRANCH:
        raise SupplyChainError("noncanonical_branch")
    if record.get("upstream_reference") != CANONICAL_UPSTREAM:
        raise SupplyChainError("noncanonical_upstream")
    if record.get("trusted_repository_anchor_commit") != TRUSTED_REPOSITORY_ANCHOR_COMMIT:
        raise SupplyChainError("repository_anchor_mismatch")
    if record.get("tracked_working_tree_clean") is not True:
        raise SupplyChainError("tracked_working_tree_dirty")
    if record.get("untracked_files_checked") is not True:
        raise SupplyChainError("untracked_files_not_checked")
    if (
        record.get("provenance_version") != R2_VERSION
        or record.get("desktop_scope") != DESKTOP_SCOPE
        or record.get("origin_kind") != "canonical_origin"
    ):
        raise SupplyChainError("repository_provenance_scope_invalid")
    commit = str(record.get("repository_commit", ""))
    lineage = record.get("parent_lineage")
    if not HEX40.fullmatch(commit) or not isinstance(lineage, list) or not lineage or lineage[0] != commit:
        raise SupplyChainError("detached_lineage")
    if len(lineage) != len(set(lineage)) or any(not HEX40.fullmatch(str(item)) for item in lineage):
        raise SupplyChainError("ambiguous_lineage")
    if record.get("lineage_depth_recorded") != len(lineage):
        raise SupplyChainError("repository_lineage_depth_mismatch")
    if not HEX40.fullmatch(str(record.get("repository_tree", ""))):
        raise SupplyChainError("repository_tree_mismatch")
    if normalize_repository_identity(_git(root, "remote", "get-url", "origin")) != record["repository_identity"]:
        raise SupplyChainError("foreign_repository")
    if _git(root, "branch", "--show-current") != CANONICAL_BRANCH:
        raise SupplyChainError("noncanonical_branch")
    if _git(
        root, "status", "--porcelain=v1", "--untracked-files=all",
    ):
        raise SupplyChainError("tracked_working_tree_dirty")
    if _git(
        root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}",
    ) != CANONICAL_UPSTREAM:
        raise SupplyChainError("noncanonical_upstream")
    _git(
        root, "merge-base", "--is-ancestor",
        TRUSTED_REPOSITORY_ANCHOR_COMMIT, commit,
    )
    anchor_tree = _git(
        root, "rev-parse", f"{TRUSTED_REPOSITORY_ANCHOR_COMMIT}^{{tree}}",
    )
    if (
        not HEX40.fullmatch(str(record.get("trusted_repository_anchor_tree", "")))
        or record.get("trusted_repository_anchor_tree") != anchor_tree
    ):
        raise SupplyChainError("repository_anchor_tree_mismatch")
    if _git(root, "merge-base", "--is-ancestor", commit, "HEAD") != "":
        raise SupplyChainError("rewritten_history")
    current_commit = _git(root, "rev-parse", "HEAD")
    if (
        current_commit != commit
        and not generated_evidence_lineage_is_bounded(
            root,
            commit,
            current_commit=current_commit,
        )
    ):
        raise SupplyChainError("repository_head_mismatch")
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
    if set(sbom) != DEPENDENCY_SBOM_FIELDS:
        raise SupplyChainError("dependency_schema_invalid")
    digest = sbom.get("dependency_digest")
    core = {key: value for key, value in sbom.items() if key != "dependency_digest"}
    if not HEX64.fullmatch(str(digest)) or digest != generate_digest(core):
        raise SupplyChainError("dependency_digest_mismatch")
    records = sbom.get("dependencies")
    if not isinstance(records, list) or not records:
        raise SupplyChainError("dependency_provenance_missing")
    if (
        sbom.get("sbom_version") != "R2_DESKTOP_V1_SBOM_V1"
        or sbom.get("desktop_scope") != DESKTOP_SCOPE
        or sbom.get("dependency_count") != len(records)
        or sbom.get("direct_dependency_count")
        != sum(
            isinstance(item, Mapping)
            and item.get("relationship") == "DIRECT"
            for item in records
        )
        or sbom.get("transitive_dependency_count")
        != sum(
            isinstance(item, Mapping)
            and item.get("relationship") == "TRANSITIVE"
            for item in records
        )
    ):
        raise SupplyChainError("dependency_count_mismatch")
    names = [item.get("normalized_name") for item in records if isinstance(item, Mapping)]
    if len(names) != len(records) or len(names) != len(set(names)):
        raise SupplyChainError("duplicate_dependency_identity")
    if names != sorted(names):
        raise SupplyChainError("dependency_order_nondeterministic")
    for item in records:
        if set(item) != DEPENDENCY_RECORD_FIELDS:
            raise SupplyChainError("dependency_record_schema_invalid")
        if item.get("approval_status") != "APPROVED" or item.get("integrity_status") != "VERIFIED":
            raise SupplyChainError("dependency_unapproved")
        if not HEX64.fullmatch(str(item.get("distribution_sha256", ""))):
            raise SupplyChainError("dependency_hash_invalid")
        if (
            not all(
                isinstance(item.get(field), str) and item[field].strip()
                for field in (
                    "package",
                    "normalized_name",
                    "version",
                    "source",
                    "licence",
                )
            )
            or item.get("relationship") not in {"DIRECT", "TRANSITIVE"}
            or not isinstance(item.get("required_by"), list)
            or item["required_by"] != sorted(set(item["required_by"]))
            or any(
                not isinstance(parent, str) or not parent
                for parent in item["required_by"]
            )
            or item.get("normalized_name") in item["required_by"]
            or not isinstance(item.get("distribution_file_count"), int)
            or isinstance(item.get("distribution_file_count"), bool)
            or item["distribution_file_count"] <= 0
            or not isinstance(item.get("distribution_size_bytes"), int)
            or isinstance(item.get("distribution_size_bytes"), bool)
            or item["distribution_size_bytes"] <= 0
        ):
            raise SupplyChainError("dependency_record_invalid")
        if (
            item["relationship"] == "DIRECT"
            and not isinstance(item.get("declared_requirement"), str)
        ) or (
            item["relationship"] == "TRANSITIVE"
            and item.get("declared_requirement") is not None
        ):
            raise SupplyChainError("dependency_relationship_invalid")
        if verify_installed:
            distribution = _distribution(str(item["package"]))
            if distribution.version != item.get("version"):
                raise SupplyChainError(f"dependency_version_mismatch:{item['normalized_name']}")
            aggregate, count, size = _distribution_hash(distribution)
            if (aggregate, count, size) != (item["distribution_sha256"], item["distribution_file_count"], item["distribution_size_bytes"]):
                raise SupplyChainError(f"dependency_substitution:{item['normalized_name']}")


def measured_linkage(root: Path) -> dict[str, Any]:
    del root
    store = load_baseline_store(configured_baseline_path())
    payload = validate_baseline_store(store)
    baseline = approved_baseline(payload)
    return {
        "measured_baseline_identifier": baseline["baseline_identifier"],
        "measured_baseline_sequence": baseline["sequence"],
        "measurement_digest": baseline["measurement_digest"],
        "runtime_identity": baseline["runtime_identity"],
    }


def collect_build_provenance(
    root: Path,
    repository: Mapping[str, Any],
    *,
    artifact_sources: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    executable = Path(sys.executable)
    linkage = measured_linkage(root)
    toolchain = _artifact_source(
        root,
        "outputs/local_toolchain_guard.json",
        artifact_sources=artifact_sources,
        label="toolchain_guard",
    )
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


def validate_build_provenance(
    record: Mapping[str, Any],
    root: Path,
    repository: Mapping[str, Any],
    *,
    artifact_sources: Mapping[str, Path] | None = None,
) -> None:
    if set(record) != BUILD_PROVENANCE_FIELDS:
        raise SupplyChainError("build_provenance_schema_invalid")
    identity = record.get("build_identity")
    core = {key: value for key, value in record.items() if key != "build_identity"}
    if identity != generate_digest(core):
        raise SupplyChainError("build_identity_mismatch")
    if record.get("repository_commit") != repository.get("repository_commit"):
        raise SupplyChainError("foreign_build")
    if (
        record.get("build_provenance_version") != R2_VERSION
        or record.get("desktop_scope") != DESKTOP_SCOPE
        or record.get("environment_policy")
        != "LOCAL_OFFLINE_APPROVED_TOOLCHAIN_ONLY"
    ):
        raise SupplyChainError("build_provenance_scope_invalid")
    linkage = measured_linkage(root)
    for key, value in linkage.items():
        if record.get(key) != value:
            raise SupplyChainError(f"{key}_mismatch")
    python = record.get("python")
    executable = Path(sys.executable)
    expected_python = {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "architecture": platform.machine(),
        "executable_name": executable.name,
        "executable_sha256": file_sha256(executable),
    }
    if (
        not isinstance(python, Mapping)
        or set(python) != {
            "implementation",
            "version",
            "architecture",
            "executable_name",
            "executable_sha256",
        }
        or dict(python) != expected_python
    ):
        raise SupplyChainError("interpreter_substitution")
    operating_system = record.get("operating_system")
    cryptographic_provider = record.get("cryptographic_provider")
    expected_operating_system = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    }
    if (
        not isinstance(operating_system, Mapping)
        or set(operating_system) != {"system", "release", "machine"}
        or dict(operating_system) != expected_operating_system
        or not isinstance(cryptographic_provider, Mapping)
        or set(cryptographic_provider) != {"package", "version"}
        or cryptographic_provider.get("package") != "cryptography"
        or cryptographic_provider.get("version")
        != metadata.version("cryptography")
    ):
        raise SupplyChainError("build_environment_invalid")
    toolchain = _artifact_source(
        root,
        "outputs/local_toolchain_guard.json",
        artifact_sources=artifact_sources,
        label="toolchain_guard",
    )
    if record.get("toolchain_guard_sha256") != file_sha256(toolchain):
        raise SupplyChainError("toolchain_substitution")
    provider = record.get("pqc_provider")
    if (
        not isinstance(provider, Mapping)
        or dict(provider) != pqc_provider_status()
    ):
        raise SupplyChainError("pqc_provider_unapproved")


def _artifact_source(
    root: Path,
    relative: str,
    *,
    artifact_sources: Mapping[str, Path] | None,
    label: str,
) -> Path:
    portable = portable_path(relative, label=label)
    override = artifact_sources.get(portable) if artifact_sources else None
    if override is not None:
        candidate = Path(override)
        if not candidate.is_absolute():
            candidate = root / candidate
        cursor = candidate
        while cursor != cursor.parent:
            if cursor.is_symlink():
                raise SupplyChainError(f"{label}_symlink")
            cursor = cursor.parent
        target = candidate.resolve(strict=False)
    else:
        try:
            target = resolve_local_trust_path(root, portable)
        except ValueError as exc:
            if "symlink" in str(exc):
                raise SupplyChainError(f"{label}_symlink") from exc
            raise SupplyChainError(f"{label}_escape") from exc
        ordinary = (root.resolve() / Path(portable)).resolve(strict=False)
        if target == ordinary:
            return resolve_file(root, portable, label=label)
    if not target.is_file():
        raise SupplyChainError(f"{label}_missing")
    cursor = target
    while cursor != cursor.parent:
        if cursor.is_symlink():
            raise SupplyChainError(f"{label}_symlink")
        cursor = cursor.parent
    return target


def artifact_records(
    root: Path,
    paths: Iterable[str],
    *,
    artifact_sources: Mapping[str, Path] | None = None,
    require_repository_tracking: bool = False,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    identities: set[str] = set()
    for raw in sorted(set(paths)):
        relative = portable_path(raw, label="artifact_path")
        path = _artifact_source(
            root,
            relative,
            artifact_sources=artifact_sources,
            label="artifact",
        )
        identity = relative.lower().replace("/", ".")
        if identity in identities:
            raise SupplyChainError("duplicate_artifact_identity")
        identities.add(identity)
        suffix = path.suffix.lower()
        relationship = "GENERATED_EVIDENCE" if relative.startswith("outputs/") else "REPOSITORY_SOURCE"
        if relative.startswith("reports/"):
            relationship = "PROTECTED_REPORT"
        repository_blob: str | None = None
        repository_blob_sha256: str | None = None
        repository_blob_size_bytes: int | None = None
        tracked = False
        if relationship != "GENERATED_EVIDENCE" and require_repository_tracking:
            repository_blob = _git(root, "rev-parse", f"HEAD:{relative}")
            if not HEX40.fullmatch(repository_blob):
                raise SupplyChainError(
                    f"artifact_not_tracked_at_commit:{relative}"
                )
            blob = _git_bytes(root, "cat-file", "blob", repository_blob)
            repository_blob_sha256 = sha256(blob).hexdigest()
            repository_blob_size_bytes = len(blob)
            tracked = True
        records.append({
            "logical_identity": identity,
            "path": relative,
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
            "repository_origin": EXPECTED_REPOSITORY_IDENTITY,
            "repository_blob": repository_blob,
            "repository_blob_sha256": repository_blob_sha256,
            "repository_blob_size_bytes": repository_blob_size_bytes,
            "tracked_at_repository_commit": tracked,
            "creation_relationship": relationship,
            "artefact_type": suffix[1:] if suffix else "binary",
        })
    return records


def validate_artifact_records(
    records: Any,
    root: Path,
    *,
    artifact_sources: Mapping[str, Path] | None = None,
    require_repository_tracking: bool = False,
) -> None:
    if not isinstance(records, list) or not records:
        raise SupplyChainError("artifact_inventory_missing")
    identities: set[str] = set()
    paths: set[str] = set()
    for record in records:
        if (
            not isinstance(record, Mapping)
            or set(record) != ARTIFACT_RECORD_FIELDS
        ):
            raise SupplyChainError("artifact_record_invalid")
        identity = record.get("logical_identity")
        relative = portable_path(record.get("path"), label="artifact_path")
        if identity in identities or relative in paths:
            raise SupplyChainError("duplicate_artifact_identity")
        identities.add(str(identity)); paths.add(str(relative))
        if (
            identity != relative.lower().replace("/", ".")
            or record.get("repository_origin")
            != EXPECTED_REPOSITORY_IDENTITY
            or not HEX64.fullmatch(str(record.get("sha256", "")))
            or not isinstance(record.get("size_bytes"), int)
            or isinstance(record.get("size_bytes"), bool)
            or record["size_bytes"] < 0
            or not isinstance(record.get("artefact_type"), str)
            or not record["artefact_type"]
        ):
            raise SupplyChainError("artifact_record_invalid")
        path = _artifact_source(
            root,
            relative,
            artifact_sources=artifact_sources,
            label="artifact",
        )
        relationship = record.get("creation_relationship")
        expected_relationship = (
            "GENERATED_EVIDENCE"
            if relative.startswith("outputs/")
            else (
                "PROTECTED_REPORT"
                if relative.startswith("reports/")
                else "REPOSITORY_SOURCE"
            )
        )
        if relationship != expected_relationship:
            raise SupplyChainError("artifact_relationship_invalid")
        if require_repository_tracking and relationship != "GENERATED_EVIDENCE":
            repository_blob = _git(
                root, "rev-parse", f"HEAD:{relative}",
            )
            blob = _git_bytes(root, "cat-file", "blob", repository_blob)
            if (
                not HEX40.fullmatch(str(record.get("repository_blob", "")))
                or record.get("repository_blob") != repository_blob
                or record.get("repository_blob_sha256")
                != sha256(blob).hexdigest()
                or record.get("repository_blob_size_bytes") != len(blob)
                or record.get("tracked_at_repository_commit") is not True
            ):
                raise SupplyChainError(
                    f"artifact_not_tracked_at_commit:{relative}"
                )
        elif relationship == "GENERATED_EVIDENCE":
            if (
                record.get("repository_blob") is not None
                or record.get("repository_blob_sha256") is not None
                or record.get("repository_blob_size_bytes") is not None
                or record.get("tracked_at_repository_commit") is not False
            ):
                raise SupplyChainError(
                    f"generated_artifact_origin_ambiguous:{relative}"
                )
        elif not (
            (
                record.get("repository_blob") is None
                and record.get("repository_blob_sha256") is None
                and record.get("repository_blob_size_bytes") is None
                and record.get("tracked_at_repository_commit") is False
            )
            or (
                HEX40.fullmatch(str(record.get("repository_blob", "")))
                and HEX64.fullmatch(
                    str(record.get("repository_blob_sha256", ""))
                )
                and isinstance(
                    record.get("repository_blob_size_bytes"), int,
                )
                and not isinstance(
                    record.get("repository_blob_size_bytes"), bool,
                )
                and record["repository_blob_size_bytes"] >= 0
                and record.get("tracked_at_repository_commit") is True
            )
        ):
            raise SupplyChainError(
                f"repository_artifact_origin_ambiguous:{relative}"
            )
        if record.get("sha256") != file_sha256(path) or record.get("size_bytes") != path.stat().st_size:
            raise SupplyChainError(f"artifact_substitution:{relative}")
