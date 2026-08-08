from __future__ import annotations

import re
from typing import Any, Mapping

from sbp_lex.execution.terminal_assurance import verify_terminal_state_seal
from sbp_lex.pipeline.hard_ingress import verify_hard_entry_rejection_audit
from sbp_lex.security.pqc import generate_digest


TERMINAL_CUSTODY_VERSION = "PASS7_TERMINAL_CUSTODY_V1"
TERMINAL_CUSTODY_FIELDS = frozenset(
    {
        "terminal_custody_version",
        "terminal_state_digest",
        "terminal_seal_digest",
    }
)
REJECTION_CUSTODY_VERSION = "PASS7_HARD_ENTRY_REJECTION_CUSTODY_V1"
REJECTION_CUSTODY_FIELDS = frozenset(
    {
        "rejection_custody_version",
        "denial_evidence_digest",
        "rejection_audit_hash",
    }
)
_DENIAL_PAYLOAD_FIELDS = frozenset(
    {
        "object_type",
        "schema_version",
        "accepted",
        "governed_state_formed",
        "authority_token_issued",
        "governance_result_issued",
        "downstream_stage_reached",
        "stopped_at",
        "failures",
        "normalized_request_digest",
        "request_fingerprint",
        "eie_digest",
    }
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def terminal_custody_bindings(
    state: Mapping[str, Any], *, require: bool = False
) -> dict[str, str] | None:
    """Return verified terminal-state custody bindings for a sealed state.

    Records created before Pass 7 did not carry a terminal seal.  They remain
    readable when ``require`` is false, but any state carrying a runtime
    traversal receipt is contemporary and must have an exact valid seal.
    """

    if not isinstance(state, Mapping):
        raise ValueError("terminal_custody_state_mapping_required")
    seal = state.get("terminal_state_seal")
    receipt_present = "runtime_traversal_receipt" in state
    if seal is None:
        if require or receipt_present:
            raise ValueError("terminal_custody_seal_required")
        return None
    valid, failures = verify_terminal_state_seal(state, seal)
    if not valid:
        raise ValueError(
            "terminal_custody_seal_invalid:" + ",".join(failures)
        )
    payload = seal.get("payload") if isinstance(seal, Mapping) else None
    terminal_state_digest = (
        payload.get("pre_seal_state_digest")
        if isinstance(payload, Mapping)
        else None
    )
    terminal_seal_digest = (
        seal.get("seal_digest") if isinstance(seal, Mapping) else None
    )
    if not _is_digest(terminal_state_digest):
        raise ValueError("terminal_custody_state_digest_invalid")
    if not _is_digest(terminal_seal_digest):
        raise ValueError("terminal_custody_seal_digest_invalid")
    return {
        "terminal_custody_version": TERMINAL_CUSTODY_VERSION,
        "terminal_state_digest": str(terminal_state_digest),
        "terminal_seal_digest": str(terminal_seal_digest),
    }


def rejection_custody_bindings(
    state: Mapping[str, Any], *, require: bool = False
) -> dict[str, str] | None:
    """Return custody for a pre-state Hard Entry rejection."""

    if not isinstance(state, Mapping):
        raise ValueError("rejection_custody_evidence_mapping_required")
    is_rejection = (
        state.get("object_type") == "HardEntryDenialEvidence"
        and state.get("accepted") is False
    )
    if not is_rejection:
        if require:
            raise ValueError("hard_entry_rejection_evidence_required")
        return None
    if (
        state.get("governed_state_formed") is not False
        or state.get("authority_token_issued") is not False
        or state.get("governance_result_issued") is not False
        or state.get("downstream_stage_reached") is not False
    ):
        raise ValueError("hard_entry_rejection_boundary_invalid")
    if not _DENIAL_PAYLOAD_FIELDS.issubset(state):
        raise ValueError("hard_entry_rejection_schema_invalid")
    denial_payload = {
        field: state.get(field) for field in _DENIAL_PAYLOAD_FIELDS
    }
    denial_digest = state.get("denial_evidence_digest")
    if (
        not _is_digest(denial_digest)
        or denial_digest != generate_digest(denial_payload)
    ):
        raise ValueError("hard_entry_denial_evidence_digest_invalid")
    rejection_audit = state.get("hard_entry_rejection_audit")
    rejection_audit_hash = state.get("audit_hash")
    if (
        not isinstance(rejection_audit, Mapping)
        or not verify_hard_entry_rejection_audit(
            rejection_audit, denial_evidence=state
        )
        or not _is_digest(rejection_audit_hash)
        or rejection_audit.get("audit_hash") != rejection_audit_hash
    ):
        raise ValueError("hard_entry_rejection_audit_invalid")
    return {
        "rejection_custody_version": REJECTION_CUSTODY_VERSION,
        "denial_evidence_digest": str(denial_digest),
        "rejection_audit_hash": str(rejection_audit_hash),
    }


def durable_custody_bindings(
    state: Mapping[str, Any], *, require: bool = False
) -> dict[str, str] | None:
    """Return the one valid durable-custody form for this result."""

    if (
        state.get("object_type") == "HardEntryDenialEvidence"
        and state.get("accepted") is False
    ):
        return rejection_custody_bindings(state, require=True)
    return terminal_custody_bindings(state, require=require)


def verify_terminal_custody_fields(
    evidence: Mapping[str, Any],
) -> tuple[bool, bool, list[str]]:
    """Validate persisted custody fields.

    The second result identifies a custody-aware record.  Absence of all three
    fields is the sole migration-safe legacy form; partial or malformed custody
    material always fails closed.
    """

    if not isinstance(evidence, Mapping):
        return False, False, ["terminal_custody_evidence_mapping_required"]
    terminal_present = TERMINAL_CUSTODY_FIELDS.intersection(evidence)
    rejection_present = REJECTION_CUSTODY_FIELDS.intersection(evidence)
    if not terminal_present and not rejection_present:
        return True, False, []
    failures: list[str] = []
    if terminal_present and rejection_present:
        failures.append("custody_forms_mixed")
    elif terminal_present:
        if terminal_present != TERMINAL_CUSTODY_FIELDS:
            failures.append("terminal_custody_fields_incomplete")
        if (
            evidence.get("terminal_custody_version")
            != TERMINAL_CUSTODY_VERSION
        ):
            failures.append("terminal_custody_version_invalid")
        if not _is_digest(evidence.get("terminal_state_digest")):
            failures.append("terminal_state_digest_invalid")
        if not _is_digest(evidence.get("terminal_seal_digest")):
            failures.append("terminal_seal_digest_invalid")
    else:
        if rejection_present != REJECTION_CUSTODY_FIELDS:
            failures.append("rejection_custody_fields_incomplete")
        if (
            evidence.get("rejection_custody_version")
            != REJECTION_CUSTODY_VERSION
        ):
            failures.append("rejection_custody_version_invalid")
        if not _is_digest(evidence.get("denial_evidence_digest")):
            failures.append("denial_evidence_digest_invalid")
        if not _is_digest(evidence.get("rejection_audit_hash")):
            failures.append("rejection_audit_hash_invalid")
    return not failures, True, failures


__all__ = [
    "REJECTION_CUSTODY_FIELDS",
    "REJECTION_CUSTODY_VERSION",
    "TERMINAL_CUSTODY_FIELDS",
    "TERMINAL_CUSTODY_VERSION",
    "durable_custody_bindings",
    "rejection_custody_bindings",
    "terminal_custody_bindings",
    "verify_terminal_custody_fields",
]
