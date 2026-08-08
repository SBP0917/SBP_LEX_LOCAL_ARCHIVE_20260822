from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Mapping

from sbp_lex.runtime.traversal_receipt import (
    TRAVERSAL_RECEIPT_PURPOSES,
    verify_traversal_receipt,
)
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


TERMINAL_STATE_SEAL_VERSION = "PASS7_TERMINAL_STATE_SEAL_V1"
TERMINAL_STATE_SEAL_DOMAIN = "SBP_LEX_DESKTOP_V1_TERMINAL_STATE_SEAL"
TERMINAL_STATE_SEAL_FIELD = "terminal_state_seal"

_SEAL_FIELDS = frozenset({"payload", "seal_digest", "signature"})
_SEAL_PAYLOAD_FIELDS = frozenset(
    {
        "seal_version",
        "pre_seal_state_digest",
        "request_fingerprint",
        "eie_identifier",
        "eie_digest",
        "canonical_state_hash",
        "hash_chain_tail",
        "hash_chain_length",
        "execution_gate_convergence_hash",
        "execution_gate_convergence_digest",
        "decision",
        "execution_result",
        "execution_verified",
        "audit_hash",
        "audit_record_digest",
        "audit_complete",
        "controlled_outcome_hash",
        "controlled_outcome_digest",
        "dual_convergence_hash",
        "dual_convergence_digest",
        "runtime_receipt_digest",
        "runtime_receipt_purpose",
    }
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _pre_seal_state(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in state.items()
        if key != TERMINAL_STATE_SEAL_FIELD
    }


def pre_seal_state_digest(state: Mapping[str, Any]) -> str:
    """Digest the complete state with only the seal itself excluded."""

    return generate_digest(_pre_seal_state(state))


def _record_digest(value: object) -> str:
    return generate_digest(deepcopy(dict(value))) if isinstance(value, Mapping) else generate_digest(None)


def _hash_chain_values(state: Mapping[str, Any]) -> tuple[object, int]:
    chain = state.get("hash_chain")
    if not isinstance(chain, list):
        return None, -1
    if not chain:
        return "GENESIS", 0
    tail = chain[-1]
    return (
        tail.get("hash") if isinstance(tail, Mapping) else None,
        len(chain),
    )


def _receipt_from(
    state: Mapping[str, Any], receipt: Mapping[str, Any] | None
) -> Mapping[str, Any] | None:
    if receipt is not None:
        return receipt
    embedded = state.get("runtime_traversal_receipt")
    return embedded if isinstance(embedded, Mapping) else None


def _terminal_projection(
    state: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    hash_chain_tail, hash_chain_length = _hash_chain_values(state)
    execution_convergence = state.get("execution_convergence")
    audit_record = state.get("audit_record")
    audit_finalisation = state.get("audit_finalisation")
    controlled_outcome = state.get("controlled_outcome")
    dual_convergence = state.get("pipeline_convergence")
    receipt_payload = receipt.get("payload")
    receipt_payload = (
        receipt_payload if isinstance(receipt_payload, Mapping) else {}
    )
    return {
        "seal_version": TERMINAL_STATE_SEAL_VERSION,
        "pre_seal_state_digest": pre_seal_state_digest(state),
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_identifier": state.get("traversal_id"),
        "eie_digest": state.get("eie_hash"),
        "canonical_state_hash": state.get("state_hash"),
        "hash_chain_tail": hash_chain_tail,
        "hash_chain_length": hash_chain_length,
        "execution_gate_convergence_hash": state.get("convergence_hash"),
        "execution_gate_convergence_digest": _record_digest(
            execution_convergence
        ),
        "decision": state.get("decision"),
        "execution_result": state.get("execution_result"),
        "execution_verified": state.get("execution_verified"),
        "audit_hash": state.get("audit_hash"),
        "audit_record_digest": _record_digest(audit_record),
        "audit_complete": (
            audit_finalisation.get("audit_complete")
            if isinstance(audit_finalisation, Mapping)
            else None
        ),
        "controlled_outcome_hash": (
            controlled_outcome.get("outcome_hash")
            if isinstance(controlled_outcome, Mapping)
            else None
        ),
        "controlled_outcome_digest": _record_digest(controlled_outcome),
        "dual_convergence_hash": (
            dual_convergence.get("convergence_hash")
            if isinstance(dual_convergence, Mapping)
            else None
        ),
        "dual_convergence_digest": _record_digest(dual_convergence),
        "runtime_receipt_digest": receipt.get("receipt_digest"),
        "runtime_receipt_purpose": receipt_payload.get("purpose"),
    }


def _bound_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "integrity_domain": TERMINAL_STATE_SEAL_DOMAIN,
        "payload": deepcopy(dict(payload)),
    }


def build_terminal_state_seal(
    state: Mapping[str, Any],
    *,
    runtime_receipt: Mapping[str, Any] | None = None,
    expected_receipt_purpose: str | None = None,
) -> dict[str, Any]:
    """Seal the complete pre-seal terminal state and explicit key surfaces."""

    if not isinstance(state, Mapping):
        raise ValueError("terminal_state_mapping_required")
    if TERMINAL_STATE_SEAL_FIELD in state:
        raise ValueError("terminal_state_already_sealed")
    receipt = _receipt_from(state, runtime_receipt)
    if not isinstance(receipt, Mapping):
        raise ValueError("terminal_state_runtime_receipt_required")
    receipt_payload = receipt.get("payload")
    purpose = (
        receipt_payload.get("purpose")
        if isinstance(receipt_payload, Mapping)
        else None
    )
    expected = expected_receipt_purpose or purpose
    if expected not in TRAVERSAL_RECEIPT_PURPOSES or purpose != expected:
        raise ValueError("terminal_state_runtime_receipt_purpose_invalid")
    receipt_valid, receipt_failures = verify_traversal_receipt(
        receipt,
        expected_purpose=str(expected),
        expected_request_fingerprint=str(
            state.get("request_fingerprint", "")
        ),
    )
    if not receipt_valid:
        raise ValueError(
            "terminal_state_runtime_receipt_invalid:"
            + ",".join(receipt_failures)
        )
    payload = _terminal_projection(state, receipt)
    bound = _bound_payload(payload)
    return {
        "payload": payload,
        "seal_digest": generate_digest(bound),
        "signature": sign_payload(bound),
    }


def verify_terminal_state_seal(
    state: object,
    seal: object | None = None,
    *,
    runtime_receipt: Mapping[str, Any] | None = None,
    expected_receipt_purpose: str | None = None,
) -> tuple[bool, list[str]]:
    """Verify the exact seal and recompute the full pre-seal state digest."""

    try:
        if not isinstance(state, Mapping):
            return False, ["terminal_state_mapping_required"]
        candidate = seal if seal is not None else state.get(TERMINAL_STATE_SEAL_FIELD)
        if not isinstance(candidate, Mapping) or set(candidate) != _SEAL_FIELDS:
            return False, ["terminal_state_seal_schema_invalid"]
        payload = candidate.get("payload")
        if not isinstance(payload, Mapping) or set(payload) != _SEAL_PAYLOAD_FIELDS:
            return False, ["terminal_state_seal_payload_schema_invalid"]
        failures: list[str] = []
        if payload.get("seal_version") != TERMINAL_STATE_SEAL_VERSION:
            failures.append("terminal_state_seal_version_invalid")
        bound = _bound_payload(payload)
        if not _is_digest(candidate.get("seal_digest")):
            failures.append("terminal_state_seal_digest_invalid")
        elif candidate.get("seal_digest") != generate_digest(bound):
            failures.append("terminal_state_seal_digest_mismatch")
        if not verify_signature(bound, candidate.get("signature", {})):
            failures.append("terminal_state_seal_signature_invalid")

        receipt = _receipt_from(state, runtime_receipt)
        if not isinstance(receipt, Mapping):
            failures.append("terminal_state_runtime_receipt_required")
            return False, sorted(set(failures))
        receipt_payload = receipt.get("payload")
        receipt_purpose = (
            receipt_payload.get("purpose")
            if isinstance(receipt_payload, Mapping)
            else None
        )
        expected = expected_receipt_purpose or receipt_purpose
        if expected not in TRAVERSAL_RECEIPT_PURPOSES:
            failures.append("terminal_state_runtime_receipt_purpose_invalid")
        else:
            receipt_valid, receipt_failures = verify_traversal_receipt(
                receipt,
                expected_purpose=str(expected),
                expected_request_fingerprint=str(
                    state.get("request_fingerprint", "")
                ),
            )
            if not receipt_valid:
                failures.extend(
                    f"terminal_state_{failure}" for failure in receipt_failures
                )
        if payload.get("runtime_receipt_purpose") != receipt_purpose:
            failures.append("terminal_state_runtime_receipt_purpose_mismatch")
        if payload.get("runtime_receipt_digest") != receipt.get(
            "receipt_digest"
        ):
            failures.append("terminal_state_runtime_receipt_digest_mismatch")

        expected_payload = _terminal_projection(state, receipt)
        if payload.get("pre_seal_state_digest") != pre_seal_state_digest(state):
            failures.append("terminal_state_pre_seal_digest_mismatch")
        for field in _SEAL_PAYLOAD_FIELDS - {
            "seal_version",
            "pre_seal_state_digest",
        }:
            if payload.get(field) != expected_payload.get(field):
                failures.append(f"terminal_state_seal_binding_mismatch:{field}")
        return not failures, sorted(set(failures))
    except Exception:
        return False, ["terminal_state_seal_structure_invalid"]


__all__ = [
    "TERMINAL_STATE_SEAL_DOMAIN",
    "TERMINAL_STATE_SEAL_FIELD",
    "TERMINAL_STATE_SEAL_VERSION",
    "build_terminal_state_seal",
    "pre_seal_state_digest",
    "verify_terminal_state_seal",
]
