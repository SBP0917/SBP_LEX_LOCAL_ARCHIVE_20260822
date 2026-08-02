from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.command_capture import (
    capture_supported_commands,
    command_skeletons,
    path_digest_or_summary,
    shell_type_if_available,
    summarize_replay_result,
    summarize_runtime_result,
)
from sbp_lex.local_trust.git_provenance import collect_git_provenance
from sbp_lex.local_trust.manifest import (
    DEFAULT_OUTPUT_PATH as DEFAULT_MANIFEST_PATH,
    canonical_json,
    load_local_trust_manifest,
    repository_root_from,
)
from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.python_provenance import collect_python_provenance
from sbp_lex.local_trust.signing import (
    LOCAL_TRUST_SIGNATURE_MODE,
    local_trust_binding_digest,
    sign_local_trust_digest,
)

ENVELOPE_SIGNATURE_MODE = LOCAL_TRUST_SIGNATURE_MODE
ENVELOPE_SIGNATURE_DOMAIN = "SBP_LEX_LOCAL_EXECUTION_ENVIRONMENT"
ENVELOPE_VERSION = "18.7C"
DEFAULT_ENVELOPE_OUTPUT_PATH = Path("outputs/local_execution_environment_trust_envelope.json")

_DIGEST_EXCLUDED_FIELDS = {
    "verification_status",
    "validation_failures",
    "envelope_payload_digest",
    "envelope_digest",
    "envelope_signature",
}


def build_execution_environment_envelope(
    repository_root: Path | str | None = None,
    *,
    manifest_path: Path | str = DEFAULT_MANIFEST_PATH,
    capture: bool = False,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    git = collect_git_provenance(root)
    python = collect_python_provenance()
    manifest_binding = bind_local_trust_manifest(root, manifest_path)
    command_results = capture_supported_commands(root) if capture else command_skeletons(root)
    envelope: dict[str, Any] = {
        "envelope_type": "local_execution_environment_trust_envelope",
        "envelope_version": ENVELOPE_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "working_tree_clean": git.get("working_tree_clean") is True,
        "bound_local_trust_manifest_digest": manifest_binding["manifest_digest"],
        "bound_local_trust_manifest_path": manifest_binding["manifest_path"],
        "bound_local_trust_manifest_status": manifest_binding["manifest_status"],
        "python_executable": python["python_executable"],
        "python_version": python["python_version"],
        "working_directory": str(root),
        "shell_type_if_available": shell_type_if_available(),
        "path_digest_or_path_summary": path_digest_or_summary(),
        "command_results": command_results,
        "runtime_result_summary": summarize_runtime_result(command_results),
        "replay_result_summary": summarize_replay_result(command_results),
        "signature_mode": ENVELOPE_SIGNATURE_MODE,
    }
    payload_digest = hash_envelope_payload(envelope)
    signature = envelope_signature_for(payload_digest)
    envelope["envelope_payload_digest"] = payload_digest
    envelope["envelope_signature"] = signature
    envelope["envelope_digest"] = envelope_digest_for(payload_digest, signature)
    validation = validate_execution_envelope(envelope, repository_root=root, clean_required=clean_required)
    envelope["verification_status"] = validation["verification_status"]
    envelope["validation_failures"] = validation["validation_failures"]
    return envelope


def bind_local_trust_manifest(repository_root: Path, manifest_path: Path | str = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    resolved = resolve_local_trust_path(repository_root, manifest_path)
    if not resolved.exists():
        return {
            "manifest_digest": "LOCAL_TRUST_MANIFEST_MISSING",
            "manifest_path": str(resolved),
            "manifest_status": "LOCAL_TRUST_MANIFEST_MISSING",
        }
    try:
        manifest = load_local_trust_manifest(resolved, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError):
        return {
            "manifest_digest": "LOCAL_TRUST_MANIFEST_INVALID",
            "manifest_path": str(resolved),
            "manifest_status": "LOCAL_TRUST_MANIFEST_INVALID",
        }
    digest = manifest.get("manifest_digest")
    payload_digest = manifest.get("manifest_payload_digest")
    signature = manifest.get("manifest_signature")
    if not digest or not payload_digest or not signature:
        return {
            "manifest_digest": "LOCAL_TRUST_MANIFEST_INVALID",
            "manifest_path": str(resolved),
            "manifest_status": "LOCAL_TRUST_MANIFEST_INVALID",
        }
    validation = validate_local_trust_manifest(manifest, repository_root=repository_root)
    if validation["local_trust_status"] != "LOCAL_TRUST_VALID":
        return {
            "manifest_digest": "LOCAL_TRUST_MANIFEST_INVALID",
            "manifest_path": str(resolved),
            "manifest_status": "LOCAL_TRUST_MANIFEST_INVALID",
        }
    return {
        "manifest_digest": str(digest),
        "manifest_path": str(resolved),
        "manifest_status": "LOCAL_TRUST_MANIFEST_BOUND",
    }


def payload_for_digest(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in envelope.items()
        if key not in _DIGEST_EXCLUDED_FIELDS
    }


def hash_envelope_payload(envelope: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(envelope)).encode("utf-8")).hexdigest()


def envelope_signature_for(payload_digest: str) -> dict[str, Any]:
    return sign_local_trust_digest(ENVELOPE_SIGNATURE_DOMAIN, payload_digest)


def envelope_digest_for(payload_digest: str, signature: Mapping[str, Any]) -> str:
    return local_trust_binding_digest(
        ENVELOPE_SIGNATURE_DOMAIN, payload_digest, signature,
    )


def write_execution_envelope(
    envelope: Mapping[str, Any],
    path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = resolve_local_trust_path(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_execution_envelope(
    path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = resolve_local_trust_path(root, path)
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("execution_envelope_must_be_object")
    return loaded


def validate_execution_envelope(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope as _validate

    return _validate(*args, **kwargs)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX local execution environment trust envelope")
    parser.add_argument("--path", default=str(DEFAULT_ENVELOPE_OUTPUT_PATH))
    parser.add_argument("--manifest-path", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--clean-required", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "validate", "show", "capture"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--path", dest="command_path")
        subparser.add_argument("--manifest-path", dest="command_manifest_path")
        subparser.add_argument("--clean-required", dest="command_clean_required", action="store_true")
    args = parser.parse_args(argv)
    path_arg = args.command_path or args.path
    manifest_path_arg = args.command_manifest_path or args.manifest_path
    clean_required = args.clean_required or args.command_clean_required

    root = repository_root_from()
    if args.command in {"build", "capture"}:
        envelope = build_execution_environment_envelope(
            root,
            manifest_path=manifest_path_arg,
            capture=args.command == "capture",
            clean_required=clean_required,
        )
        path = write_execution_envelope(envelope, path_arg, repository_root=root)
        print(envelope["verification_status"])
        print(path)
        return 0
    if args.command == "validate":
        envelope = load_execution_envelope(path_arg, repository_root=root)
        validation = validate_execution_envelope(envelope, repository_root=root, clean_required=clean_required)
        print(validation["verification_status"])
        return 0 if validation["verification_status"] == "EXECUTION_ENV_VALID" else 1
    if args.command == "show":
        envelope = load_execution_envelope(path_arg, repository_root=root)
        validation = validate_execution_envelope(envelope, repository_root=root, clean_required=clean_required)
        print(validation["verification_status"])
        print(f"commit={envelope.get('git_commit')}")
        print(f"branch={envelope.get('git_branch')}")
        print(f"manifest_digest={envelope.get('bound_local_trust_manifest_digest')}")
        print(f"commands={len(envelope.get('command_results', []))}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
