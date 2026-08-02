from __future__ import annotations

import argparse
import json
import math
import unicodedata
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.critical_paths import (
    CRITICAL_FILE_PATHS,
    PHASE_BASELINE,
    TRUSTED_OUTPUT_PATHS,
    TRUSTED_REPORT_PATHS,
    VERIFICATION_COMMANDS,
)
from sbp_lex.local_trust.file_digest import collect_file_hashes
from sbp_lex.local_trust.git_provenance import collect_git_provenance
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.python_provenance import collect_python_provenance
from sbp_lex.local_trust.signing import (
    LOCAL_TRUST_SIGNATURE_MODE,
    local_trust_binding_digest,
    sign_local_trust_digest,
)

LOCAL_TRUST_SIGNATURE_DOMAIN = "SBP_LEX_LOCAL_TRUST_ROOT_MANIFEST"
MANIFEST_VERSION = "18.7B"
DEFAULT_OUTPUT_PATH = Path("outputs/local_trust_root_manifest.json")

_DIGEST_EXCLUDED_FIELDS = {
    "local_trust_status",
    "validation_failures",
    "manifest_payload_digest",
    "manifest_digest",
    "manifest_signature",
}


def repository_root_from(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


def build_local_trust_manifest(
    repository_root: Path | str | None = None,
    *,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    git = collect_git_provenance(root)
    python = collect_python_provenance()
    manifest: dict[str, Any] = {
        "manifest_type": "local_trust_root_manifest",
        "manifest_version": MANIFEST_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "repository_root_digest_scope": "relative_paths_only",
        "git_branch": git.get("git_branch"),
        "git_commit": git.get("git_commit"),
        "git_status_short": git.get("git_status_short", ""),
        "working_tree_clean": git.get("working_tree_clean") is True,
        "python_executable": python["python_executable"],
        "python_version": python["python_version"],
        "python_runtime_digest_if_available": python["python_runtime_digest_if_available"],
        "command_provenance": collect_runtime_command_provenance(root, python),
        "critical_file_hashes": collect_critical_file_hashes(root),
        "trusted_report_hashes": collect_trusted_report_hashes(root),
        "trusted_output_hashes": collect_trusted_output_hashes(root),
        "integrity_store_status_if_available": _artifact_status(root, "runtime_artifacts/integrity_store.jsonl"),
        "quarantine_evidence_status_if_available": _directory_status(root, "runtime_artifacts/quarantine"),
        "test_baseline": {
            "expected_suite": "pytest",
            "latest_verified_count": 1785,
        },
        "runtime_baseline": {"latest_verified_runtime": "RECORDED_OUTSIDE_LOCAL_TRUST"},
        "replay_baseline": {"latest_verified_replay": "MATCHED_RECORDED_OUTSIDE_LOCAL_TRUST"},
        "phase_baseline": list(PHASE_BASELINE),
        "signature_mode": LOCAL_TRUST_SIGNATURE_MODE,
    }
    payload_digest = hash_manifest_payload(manifest)
    signature = manifest_signature_for(payload_digest)
    manifest["manifest_payload_digest"] = payload_digest
    manifest["manifest_signature"] = signature
    manifest["manifest_digest"] = manifest_digest_for(payload_digest, signature)
    validation = validate_local_trust_manifest(manifest, repository_root=root, clean_required=clean_required)
    manifest["local_trust_status"] = validation["local_trust_status"]
    manifest["validation_failures"] = validation["validation_failures"]
    return manifest


def collect_critical_file_hashes(repository_root: Path) -> list[dict[str, Any]]:
    return collect_file_hashes(repository_root, CRITICAL_FILE_PATHS)


def collect_trusted_report_hashes(repository_root: Path) -> list[dict[str, Any]]:
    return collect_file_hashes(repository_root, TRUSTED_REPORT_PATHS)


def collect_trusted_output_hashes(repository_root: Path) -> list[dict[str, Any]]:
    return collect_file_hashes(repository_root, TRUSTED_OUTPUT_PATHS)


def collect_runtime_command_provenance(repository_root: Path, python: Mapping[str, Any] | None = None) -> dict[str, Any]:
    python_provenance = python or collect_python_provenance()
    return {
        "working_directory": str(repository_root),
        "commands": [{"command": command, "executed_by_manifest": False} for command in VERIFICATION_COMMANDS],
        "python_executable_path": python_provenance["python_executable"],
        "python_version": python_provenance["python_version"],
        "path_note": "Manifest records intended verification commands only; it does not execute them.",
    }


def canonicalise_manifest(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("local_trust_key_must_be_string")
            key = unicodedata.normalize("NFC", raw_key)
            if key in result:
                raise ValueError("local_trust_key_collision_after_normalization")
            result[key] = canonicalise_manifest(item)
        return result
    if isinstance(value, (list, tuple)):
        return [canonicalise_manifest(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("local_trust_non_finite_number")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"local_trust_unsupported_type:{type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonicalise_manifest(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def payload_for_digest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in manifest.items()
        if key not in _DIGEST_EXCLUDED_FIELDS
    }


def hash_manifest_payload(manifest: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(manifest)).encode("utf-8")).hexdigest()


def manifest_signature_for(payload_digest: str) -> dict[str, Any]:
    return sign_local_trust_digest(LOCAL_TRUST_SIGNATURE_DOMAIN, payload_digest)


def manifest_digest_for(payload_digest: str, signature: Mapping[str, Any]) -> str:
    return local_trust_binding_digest(
        LOCAL_TRUST_SIGNATURE_DOMAIN, payload_digest, signature,
    )


def write_local_trust_manifest(
    manifest: Mapping[str, Any],
    path: Path | str = DEFAULT_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = resolve_local_trust_path(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_local_trust_manifest(path: Path | str = DEFAULT_OUTPUT_PATH, *, repository_root: Path | str | None = None) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = resolve_local_trust_path(root, path)
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("local_trust_manifest_must_be_object")
    return loaded


def validate_local_trust_manifest(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest as _validate

    return _validate(*args, **kwargs)


def _artifact_status(repository_root: Path, relative_path: str) -> dict[str, Any]:
    path = repository_root / relative_path
    if not path.exists():
        return {"path": relative_path, "status": "MISSING"}
    return {"path": relative_path, "status": "PRESENT", "size_bytes": path.stat().st_size}


def _directory_status(repository_root: Path, relative_path: str) -> dict[str, Any]:
    path = repository_root / relative_path
    if not path.exists():
        return {"path": relative_path, "status": "MISSING"}
    if not path.is_dir():
        return {"path": relative_path, "status": "NOT_DIRECTORY"}
    return {"path": relative_path, "status": "PRESENT", "entry_count": sum(1 for _ in path.iterdir())}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX local trust root manifest")
    parser.add_argument("--path", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--clean-required", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "validate", "show"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--path", dest="command_path")
        subparser.add_argument("--clean-required", dest="command_clean_required", action="store_true")
    args = parser.parse_args(argv)
    path_arg = args.command_path or args.path
    clean_required = args.clean_required or args.command_clean_required

    root = repository_root_from()
    if args.command == "build":
        manifest = build_local_trust_manifest(root, clean_required=clean_required)
        path = write_local_trust_manifest(manifest, path_arg, repository_root=root)
        print(manifest["local_trust_status"])
        print(path)
        return 0
    if args.command == "validate":
        manifest = load_local_trust_manifest(path_arg, repository_root=root)
        validation = validate_local_trust_manifest(manifest, repository_root=root, clean_required=clean_required)
        print(validation["local_trust_status"])
        return 0 if validation["local_trust_status"] == "LOCAL_TRUST_VALID" else 1
    if args.command == "show":
        manifest = load_local_trust_manifest(path_arg, repository_root=root)
        validation = validate_local_trust_manifest(manifest, repository_root=root, clean_required=clean_required)
        print(validation["local_trust_status"])
        print(f"commit={manifest.get('git_commit')}")
        print(f"branch={manifest.get('git_branch')}")
        print(f"working_tree_clean={manifest.get('working_tree_clean')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
