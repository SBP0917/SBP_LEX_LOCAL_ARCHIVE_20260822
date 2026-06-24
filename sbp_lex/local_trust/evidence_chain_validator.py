from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.git_provenance import current_git_commit

EVIDENCE_CHAIN_VALID = "EVIDENCE_CHAIN_VALID"
EVIDENCE_CHAIN_INVALID = "EVIDENCE_CHAIN_INVALID"
EVIDENCE_CHAIN_INCOMPLETE = "EVIDENCE_CHAIN_INCOMPLETE"
EVIDENCE_CHAIN_STALE = "EVIDENCE_CHAIN_STALE"
EVIDENCE_CHAIN_DIRTY = "EVIDENCE_CHAIN_DIRTY"

REQUIRED_SECTIONS = {
    "chain_type",
    "chain_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "working_tree_clean",
    "bound_local_trust_manifest_path",
    "bound_local_trust_manifest_digest",
    "bound_local_trust_manifest_status",
    "bound_execution_envelope_path",
    "bound_execution_envelope_digest",
    "bound_execution_envelope_status",
    "evidence_scope",
    "evidence_items",
    "missing_evidence_items",
    "excluded_paths",
    "chain_payload_digest",
    "chain_digest",
    "chain_signature",
    "signature_mode",
}

REQUIRED_EVIDENCE_ITEM_FIELDS = {
    "evidence_id",
    "path",
    "category",
    "required",
    "exists",
    "size_bytes",
    "sha256",
    "last_modified_utc",
    "content_type",
    "source_phase",
    "attestation_status",
}

FORBIDDEN_KEYS = {
    "execution_permission",
    "governance_result",
    "runtime_authority",
    "allow_execution",
    "external_allow",
    "external_deny",
    "external_escalate",
    "external_" + "governance_result",
}


def validate_local_evidence_chain(
    chain: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.evidence_chain import (
        EVIDENCE_CHAIN_SIGNATURE_MODE,
        chain_digest_for,
        chain_signature_for,
        hash_chain_payload,
    )
    from sbp_lex.local_trust.manifest import canonicalise_manifest

    failures: list[str] = []
    if not isinstance(chain, Mapping):
        return {"evidence_chain_status": EVIDENCE_CHAIN_INVALID, "validation_failures": ["chain_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(chain))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"evidence_chain_status": EVIDENCE_CHAIN_INCOMPLETE, "validation_failures": failures}

    if chain.get("chain_type") != "local_evidence_chain_report_integrity_attestation":
        failures.append("invalid_chain_type")
    if chain.get("signature_mode") != EVIDENCE_CHAIN_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if chain.get("bound_local_trust_manifest_status") != "LOCAL_TRUST_MANIFEST_BOUND":
        failures.append("local_trust_manifest_not_bound")
    if chain.get("bound_execution_envelope_status") != "EXECUTION_ENVELOPE_BOUND":
        failures.append("execution_envelope_not_bound")

    try:
        canonicalise_manifest(chain)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_chain_payload(chain)
    if not hmac.compare_digest(str(chain.get("chain_payload_digest")), expected_payload_digest):
        failures.append("chain_payload_digest_mismatch")

    expected_signature = chain_signature_for(expected_payload_digest)
    if not hmac.compare_digest(str(chain.get("chain_signature")), expected_signature):
        failures.append("chain_signature_mismatch")

    expected_chain_digest = chain_digest_for(expected_payload_digest, expected_signature)
    if not hmac.compare_digest(str(chain.get("chain_digest")), expected_chain_digest):
        failures.append("chain_digest_mismatch")

    failures.extend(_evidence_item_failures(chain.get("evidence_items")))
    failures.extend(_forbidden_failures(chain))

    if failures:
        incomplete_markers = {"local_trust_manifest_not_bound", "execution_envelope_not_bound"}
        status = EVIDENCE_CHAIN_INCOMPLETE if any(item in incomplete_markers for item in failures) else EVIDENCE_CHAIN_INVALID
        return {"evidence_chain_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        if current_commit and chain.get("git_commit") != current_commit:
            return {"evidence_chain_status": EVIDENCE_CHAIN_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and chain.get("working_tree_clean") is not True:
        return {"evidence_chain_status": EVIDENCE_CHAIN_DIRTY, "validation_failures": ["working_tree_dirty"]}

    return {"evidence_chain_status": EVIDENCE_CHAIN_VALID, "validation_failures": []}


def _evidence_item_failures(value: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, list):
        return ["evidence_items_not_list"]
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            failures.append(f"evidence_item_not_mapping:{index}")
            continue
        missing = sorted(REQUIRED_EVIDENCE_ITEM_FIELDS - set(item))
        failures.extend(f"evidence_item_missing_field:{index}:{field}" for field in missing)
        if item.get("exists") is True and not item.get("sha256"):
            failures.append(f"evidence_item_missing_hash:{index}")
        if item.get("exists") is not True and item.get("attestation_status") not in {"MISSING", "NOT_FILE"}:
            failures.append(f"evidence_item_invalid_missing_status:{index}")
    return failures


def _forbidden_failures(value: Any, path: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_path = f"{path}.{key_text}"
            if key_text in FORBIDDEN_KEYS:
                failures.append(f"forbidden_authority_key:{next_path}")
            failures.extend(_forbidden_failures(item, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_forbidden_failures(item, f"{path}[{index}]"))
    return failures
