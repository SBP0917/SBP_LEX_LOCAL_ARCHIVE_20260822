from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

REQUIRED_EXECUTION_FIELDS = [
    "request_fingerprint",
    "state_hash",
    "decision",
    "pipeline_mode",
    "convergence_hash",
    "master_token",
    "execution_result",
    "execution_verified",
]


def build_execution_attestation(state: Mapping[str, Any]) -> Dict[str, Any]:
    missing = [field for field in REQUIRED_EXECUTION_FIELDS if state.get(field) is None]
    if missing:
        return {"valid": False, "reason": "EXECUTION_FIELD_MISSING", "missing": missing}

    payload = {field: state.get(field) for field in REQUIRED_EXECUTION_FIELDS}
    payload["timestamp"] = state.get("execution_timestamp")
    payload["timestamp_authority"] = "CANONICAL_RUNTIME"
    digest = generate_digest(payload)
    signature = sign_payload(payload)

    return {
        "valid": verify_signature(payload, signature),
        "attestation_hash": digest,
        "signature": signature,
        "payload": payload,
    }


def verify_execution_attestation(state: Mapping[str, Any], attestation: Mapping[str, Any]) -> bool:
    if not isinstance(attestation, Mapping):
        return False

    payload = attestation.get("payload")
    if not isinstance(payload, Mapping):
        return False

    if attestation.get("attestation_hash") != generate_digest(payload):
        return False

    if not verify_signature(payload, attestation.get("signature", {})):
        return False

    if payload.get("request_fingerprint") != state.get("request_fingerprint"):
        return False

    if payload.get("master_token") != state.get("master_token"):
        return False

    for field in ["decision", "pipeline_mode", "convergence_hash", "execution_result", "execution_verified"]:
        if payload.get(field) != state.get(field):
            return False

    return True
