from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

VALID_OUTCOMES = {"ALLOW", "DENY", "ESCALATE", "PERSISTENT_INOPERABILITY"}


def build_controlled_outcome(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    decision = execution_state.get("decision", "DENY")
    if decision not in VALID_OUTCOMES:
        decision = "DENY"

    payload = {
        "request_fingerprint": execution_state.get("request_fingerprint"),
        "decision": decision,
        "execution_verified": execution_state.get("execution_verified", False),
        "audit_hash": execution_state.get("audit_hash"),
        "convergence_hash": execution_state.get("convergence_hash"),
        "pipeline_mode": execution_state.get("pipeline_mode"),
    }
    signature = sign_payload(payload)

    return {
        "valid": verify_signature(payload, signature),
        "outcome_hash": generate_digest(payload),
        "signature": signature,
        "payload": payload,
    }


def verify_controlled_outcome(outcome_record: Mapping[str, Any]) -> bool:
    if not isinstance(outcome_record, Mapping):
        return False

    payload = outcome_record.get("payload")
    if not isinstance(payload, Mapping):
        return False

    if outcome_record.get("outcome_hash") != generate_digest(payload):
        return False

    if not verify_signature(payload, outcome_record.get("signature", {})):
        return False

    if payload.get("decision") not in VALID_OUTCOMES:
        return False

    if payload.get("decision") == "ALLOW":
        if payload.get("execution_verified") is not True:
            return False
        if not payload.get("audit_hash"):
            return False
        if not payload.get("convergence_hash"):
            return False

    return True


def finalise_outcome(outcome_record: Mapping[str, Any]) -> Dict[str, Any]:
    if not verify_controlled_outcome(outcome_record):
        return {"allowed": False, "decision": "DENY", "reason": "OUTCOME_INVALID"}

    payload = outcome_record.get("payload", {})
    return {
        "allowed": payload.get("decision") == "ALLOW",
        "decision": payload.get("decision"),
        "outcome_locked": True,
    }
