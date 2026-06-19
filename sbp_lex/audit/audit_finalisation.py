from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

REQUIRED_AUDIT_FIELDS = [
    "request_fingerprint",
    "state_hash",
    "decision",
    "execution_verified",
    "convergence_hash",
    "audit_chain",
    "pipeline_mode",
    "integration_evidence",
]

VALID_AUDIT_DECISIONS = {"ALLOW", "DENY", "ESCALATE", "PERSISTENT_INOPERABILITY"}


def build_audit_record(audit_state: Mapping[str, Any]) -> Dict[str, Any]:
    missing = [field for field in REQUIRED_AUDIT_FIELDS if audit_state.get(field) is None]
    if missing:
        return {"valid": False, "reason": "AUDIT_FIELDS_MISSING", "missing": missing}

    if audit_state.get("decision") not in VALID_AUDIT_DECISIONS:
        return {"valid": False, "reason": "AUDIT_DECISION_INVALID", "decision": audit_state.get("decision")}

    if audit_state.get("decision") == "ALLOW" and audit_state.get("execution_verified") is not True:
        return {"valid": False, "reason": "ALLOW_REQUIRES_EXECUTION_VERIFIED"}

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

    payload = audit_record.get("payload")
    if not isinstance(payload, Mapping):
        return False

    if audit_record.get("audit_hash") != generate_digest(payload):
        return False

    return verify_signature(payload, audit_record.get("signature", {}))


def finalise_audit(audit_record: Mapping[str, Any]) -> Dict[str, Any]:
    if not verify_audit_record(audit_record):
        return {"audit_complete": False, "reason": "AUDIT_VERIFICATION_FAILED"}

    payload = audit_record.get("payload", {})
    if payload.get("decision") == "ALLOW" and payload.get("execution_verified") is not True:
        return {"audit_complete": False, "reason": "ALLOW_REQUIRES_EXECUTION_VERIFIED"}

    return {"audit_complete": True, "audit_locked": True, "audit_verified": True}
