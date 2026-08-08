from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

REQUIRED_AUDIT_FIELDS = [
    "request_fingerprint",
    "state_hash",
    "decision",
    "execution_result",
    "execution_verified",
    "convergence_hash",
    "audit_chain",
    "pipeline_mode",
    "integration_evidence",
]

AUDIT_WRAPPER_FIELDS = {"valid", "audit_hash", "signature", "payload"}

VALID_AUDIT_DECISIONS = {"ALLOW", "DENY", "ESCALATE", "PERSISTENT_INOPERABILITY"}


def _terminal_semantics_failures(payload: Mapping[str, Any]) -> list[str]:
    """Return exact decision/result/verification inconsistencies."""

    decision = payload.get("decision")
    execution_result = payload.get("execution_result")
    execution_verified = payload.get("execution_verified")
    failures: list[str] = []
    if decision not in VALID_AUDIT_DECISIONS:
        failures.append("AUDIT_DECISION_INVALID")
    if execution_result not in {"EXECUTE", "HALT"}:
        failures.append("AUDIT_EXECUTION_RESULT_INVALID")
    if not isinstance(execution_verified, bool):
        failures.append("AUDIT_EXECUTION_VERIFICATION_INVALID")
    if decision == "ALLOW":
        if execution_result != "EXECUTE":
            failures.append("ALLOW_REQUIRES_EXECUTE")
        if execution_verified is not True:
            failures.append("ALLOW_REQUIRES_EXECUTION_VERIFIED")
    elif decision in VALID_AUDIT_DECISIONS:
        if execution_result != "HALT":
            failures.append("NON_ALLOW_REQUIRES_HALT")
        if execution_verified is not False:
            failures.append("NON_ALLOW_REQUIRES_EXECUTION_UNVERIFIED")
    return failures


def build_audit_record(audit_state: Mapping[str, Any]) -> Dict[str, Any]:
    missing = [field for field in REQUIRED_AUDIT_FIELDS if audit_state.get(field) is None]
    if missing:
        return {"valid": False, "reason": "AUDIT_FIELDS_MISSING", "missing": missing}

    semantic_failures = _terminal_semantics_failures(audit_state)
    if semantic_failures:
        return {
            "valid": False,
            "reason": "AUDIT_TERMINAL_SEMANTICS_INVALID",
            "failures": semantic_failures,
        }

    payload = {field: audit_state.get(field) for field in REQUIRED_AUDIT_FIELDS}
    digest = generate_digest(payload)
    signature = sign_payload(payload)

    return {
        "valid": verify_signature(payload, signature),
        "audit_hash": digest,
        "signature": signature,
        "payload": payload,
    }


def verify_audit_record(audit_record: Mapping[str, Any]) -> bool:
    if not isinstance(audit_record, Mapping):
        return False

    if set(audit_record) != AUDIT_WRAPPER_FIELDS:
        return False

    if audit_record.get("valid") is not True:
        return False

    payload = audit_record.get("payload")
    if not isinstance(payload, Mapping):
        return False

    if set(payload) != set(REQUIRED_AUDIT_FIELDS):
        return False

    if _terminal_semantics_failures(payload):
        return False

    if audit_record.get("audit_hash") != generate_digest(payload):
        return False

    return verify_signature(payload, audit_record.get("signature", {}))


def finalise_audit(audit_record: Mapping[str, Any]) -> Dict[str, Any]:
    if not verify_audit_record(audit_record):
        return {"audit_complete": False, "reason": "AUDIT_VERIFICATION_FAILED"}

    payload = audit_record.get("payload", {})
    if _terminal_semantics_failures(payload):
        return {
            "audit_complete": False,
            "reason": "AUDIT_TERMINAL_SEMANTICS_INVALID",
        }

    return {"audit_complete": True, "audit_locked": True, "audit_verified": True}
