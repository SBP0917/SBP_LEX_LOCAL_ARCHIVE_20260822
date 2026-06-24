from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.evidence_registry import EXCLUDED_PATHS, REQUIRED_EVIDENCE_SPECS
from sbp_lex.local_trust.execution_envelope import (
    DEFAULT_ENVELOPE_OUTPUT_PATH,
    load_execution_envelope,
)
from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope
from sbp_lex.local_trust.git_provenance import collect_git_provenance
from sbp_lex.local_trust.manifest import (
    DEFAULT_OUTPUT_PATH as DEFAULT_MANIFEST_PATH,
    canonical_json,
    load_local_trust_manifest,
    repository_root_from,
)
from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest
from sbp_lex.local_trust.report_attestation import (
    collect_evidence_items,
    missing_evidence_items,
    validate_evidence_item_hashes,
)

EVIDENCE_CHAIN_SIGNATURE_MODE = "EVIDENCE_CHAIN_DETERMINISTIC_PLACEHOLDER"
CHAIN_VERSION = "18.7D"
DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH = Path("outputs/local_evidence_chain.json")

_DIGEST_EXCLUDED_FIELDS = {
    "evidence_chain_status",
    "validation_failures",
    "chain_payload_digest",
    "chain_digest",
    "chain_signature",
}


def build_local_evidence_chain(
    repository_root: Path | str | None = None,
    *,
    manifest_path: Path | str = DEFAULT_MANIFEST_PATH,
    envelope_path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    evidence_specs: Sequence[Mapping[str, Any]] = REQUIRED_EVIDENCE_SPECS,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.evidence_chain_validator import validate_local_evidence_chain

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    git = collect_git_provenance(root)
    manifest_binding = bind_local_trust_manifest(root, manifest_path)
    envelope_binding = bind_execution_envelope(root, envelope_path, manifest_binding["manifest_digest"])
    evidence_items = collect_evidence_items(root, evidence_specs)
    chain: dict[str, Any] = {
        "chain_type": "local_evidence_chain_report_integrity_attestation",
        "chain_version": CHAIN_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "working_tree_clean": git.get("working_tree_clean") is True,
        "bound_local_trust_manifest_path": manifest_binding["manifest_path"],
        "bound_local_trust_manifest_digest": manifest_binding["manifest_digest"],
        "bound_local_trust_manifest_status": manifest_binding["manifest_status"],
        "bound_execution_envelope_path": envelope_binding["envelope_path"],
        "bound_execution_envelope_digest": envelope_binding["envelope_digest"],
        "bound_execution_envelope_status": envelope_binding["envelope_status"],
        "evidence_scope": evidence_scope(evidence_items),
        "evidence_items": evidence_items,
        "missing_evidence_items": missing_evidence_items(evidence_items),
        "excluded_paths": list(EXCLUDED_PATHS),
        "signature_mode": EVIDENCE_CHAIN_SIGNATURE_MODE,
    }
    payload_digest = hash_chain_payload(chain)
    signature = chain_signature_for(payload_digest)
    chain["chain_payload_digest"] = payload_digest
    chain["chain_signature"] = signature
    chain["chain_digest"] = chain_digest_for(payload_digest, signature)
    validation = validate_local_evidence_chain(chain, repository_root=root, clean_required=clean_required)
    chain["evidence_chain_status"] = validation["evidence_chain_status"]
    chain["validation_failures"] = validation["validation_failures"]
    return chain


def bind_local_trust_manifest(repository_root: Path, manifest_path: Path | str = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    path = Path(manifest_path)
    resolved = path if path.is_absolute() else repository_root / path
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
    validation = validate_local_trust_manifest(manifest, repository_root=repository_root)
    if validation["local_trust_status"] != "LOCAL_TRUST_VALID":
        return {
            "manifest_digest": "LOCAL_TRUST_MANIFEST_INVALID",
            "manifest_path": str(resolved),
            "manifest_status": "LOCAL_TRUST_MANIFEST_INVALID",
        }
    return {
        "manifest_digest": str(manifest["manifest_digest"]),
        "manifest_path": str(resolved),
        "manifest_status": "LOCAL_TRUST_MANIFEST_BOUND",
    }


def bind_execution_envelope(
    repository_root: Path,
    envelope_path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    manifest_digest: str | None = None,
) -> dict[str, Any]:
    path = Path(envelope_path)
    resolved = path if path.is_absolute() else repository_root / path
    if not resolved.exists():
        return {
            "envelope_digest": "EXECUTION_ENVELOPE_MISSING",
            "envelope_path": str(resolved),
            "envelope_status": "EXECUTION_ENVELOPE_MISSING",
        }
    try:
        envelope = load_execution_envelope(resolved, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError):
        return {
            "envelope_digest": "EXECUTION_ENVELOPE_INVALID",
            "envelope_path": str(resolved),
            "envelope_status": "EXECUTION_ENVELOPE_INVALID",
        }
    validation = validate_execution_envelope(envelope, repository_root=repository_root)
    if validation["verification_status"] != "EXECUTION_ENV_VALID":
        return {
            "envelope_digest": "EXECUTION_ENVELOPE_INVALID",
            "envelope_path": str(resolved),
            "envelope_status": "EXECUTION_ENVELOPE_INVALID",
        }
    if manifest_digest and envelope.get("bound_local_trust_manifest_digest") != manifest_digest:
        return {
            "envelope_digest": "EXECUTION_ENVELOPE_MANIFEST_MISMATCH",
            "envelope_path": str(resolved),
            "envelope_status": "EXECUTION_ENVELOPE_MANIFEST_MISMATCH",
        }
    return {
        "envelope_digest": str(envelope["envelope_digest"]),
        "envelope_path": str(resolved),
        "envelope_status": "EXECUTION_ENVELOPE_BOUND",
    }


def evidence_scope(evidence_items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    categories = sorted({str(item["category"]) for item in evidence_items})
    present_count = sum(1 for item in evidence_items if item.get("exists") is True)
    missing_count = len(evidence_items) - present_count
    return {
        "scope_name": "phase_reports_manifests_envelopes_and_trusted_outputs",
        "categories": categories,
        "expected_item_count": len(evidence_items),
        "present_item_count": present_count,
        "missing_item_count": missing_count,
    }


def compare_evidence_chain_to_current_files(
    chain: Mapping[str, Any],
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    validation = validate_local_evidence_chain(chain, repository_root=root)
    if validation["evidence_chain_status"] != "EVIDENCE_CHAIN_VALID":
        return {
            "evidence_chain_status": validation["evidence_chain_status"],
            "validation_failures": validation["validation_failures"],
            "changed_evidence_items": [],
        }
    changed = validate_evidence_item_hashes(root, chain.get("evidence_items", []))
    return {
        "evidence_chain_status": "EVIDENCE_CHAIN_VALID" if not changed else "EVIDENCE_CHAIN_INVALID",
        "validation_failures": [] if not changed else ["evidence_items_changed"],
        "changed_evidence_items": changed,
    }


def canonicalise_evidence_chain(value: Any) -> Any:
    from sbp_lex.local_trust.manifest import canonicalise_manifest

    return canonicalise_manifest(value)


def payload_for_digest(chain: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in chain.items()
        if key not in _DIGEST_EXCLUDED_FIELDS
    }


def hash_chain_payload(chain: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(chain)).encode("utf-8")).hexdigest()


def chain_signature_for(payload_digest: str) -> str:
    return sha256(f"{EVIDENCE_CHAIN_SIGNATURE_MODE}:{payload_digest}".encode("utf-8")).hexdigest()


def chain_digest_for(payload_digest: str, signature: str) -> str:
    return sha256(
        canonical_json(
            {
                "chain_payload_digest": payload_digest,
                "chain_signature": signature,
                "signature_mode": EVIDENCE_CHAIN_SIGNATURE_MODE,
            }
        ).encode("utf-8")
    ).hexdigest()


def write_local_evidence_chain(
    chain: Mapping[str, Any],
    path: Path | str = DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = Path(path)
    if not output.is_absolute():
        output = root / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(chain, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_local_evidence_chain(
    path: Path | str = DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = Path(path)
    if not source.is_absolute():
        source = root / source
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("local_evidence_chain_must_be_object")
    return loaded


def validate_local_evidence_chain(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from sbp_lex.local_trust.evidence_chain_validator import validate_local_evidence_chain as _validate

    return _validate(*args, **kwargs)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX local evidence chain integrity attestation")
    parser.add_argument("--path", default=str(DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH))
    parser.add_argument("--manifest-path", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--envelope-path", default=str(DEFAULT_ENVELOPE_OUTPUT_PATH))
    parser.add_argument("--clean-required", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "validate", "show", "compare"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--path", dest="command_path")
        subparser.add_argument("--manifest-path", dest="command_manifest_path")
        subparser.add_argument("--envelope-path", dest="command_envelope_path")
        subparser.add_argument("--clean-required", dest="command_clean_required", action="store_true")
    args = parser.parse_args(argv)
    path_arg = args.command_path or args.path
    manifest_path_arg = args.command_manifest_path or args.manifest_path
    envelope_path_arg = args.command_envelope_path or args.envelope_path
    clean_required = args.clean_required or args.command_clean_required

    root = repository_root_from()
    if args.command == "build":
        chain = build_local_evidence_chain(
            root,
            manifest_path=manifest_path_arg,
            envelope_path=envelope_path_arg,
            clean_required=clean_required,
        )
        path = write_local_evidence_chain(chain, path_arg, repository_root=root)
        print(chain["evidence_chain_status"])
        print(path)
        return 0
    if args.command == "validate":
        chain = load_local_evidence_chain(path_arg, repository_root=root)
        validation = validate_local_evidence_chain(chain, repository_root=root, clean_required=clean_required)
        print(validation["evidence_chain_status"])
        return 0 if validation["evidence_chain_status"] == "EVIDENCE_CHAIN_VALID" else 1
    if args.command == "show":
        chain = load_local_evidence_chain(path_arg, repository_root=root)
        validation = validate_local_evidence_chain(chain, repository_root=root, clean_required=clean_required)
        print(validation["evidence_chain_status"])
        print(f"commit={chain.get('git_commit')}")
        print(f"branch={chain.get('git_branch')}")
        print(f"manifest_digest={chain.get('bound_local_trust_manifest_digest')}")
        print(f"envelope_digest={chain.get('bound_execution_envelope_digest')}")
        print(f"evidence_items={len(chain.get('evidence_items', []))}")
        print(f"missing_evidence_items={len(chain.get('missing_evidence_items', []))}")
        return 0
    if args.command == "compare":
        chain = load_local_evidence_chain(path_arg, repository_root=root)
        comparison = compare_evidence_chain_to_current_files(chain, repository_root=root)
        print(comparison["evidence_chain_status"])
        print(f"changed_evidence_items={len(comparison['changed_evidence_items'])}")
        return 0 if comparison["evidence_chain_status"] == "EVIDENCE_CHAIN_VALID" else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
