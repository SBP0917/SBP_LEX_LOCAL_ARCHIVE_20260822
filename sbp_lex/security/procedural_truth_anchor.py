from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

REQUIRED_PROCEDURAL_FIELDS = ["corroboration_score", "freshness_state", "source_validation", "consistency_validation", "threshold_state"]
VALID_FRESHNESS = ["VALID", "STALE", "EXPIRED"]


def build_truth_anchor(truth: Mapping[str, Any]) -> Dict[str, Any]:
    missing = [field for field in REQUIRED_PROCEDURAL_FIELDS if truth.get(field) is None]
    if missing:
        return {"valid": False, "reason": "TRUTH_FIELDS_MISSING", "missing": missing}
    freshness = truth.get("freshness_state")
    if freshness not in VALID_FRESHNESS:
        return {"valid": False, "reason": "INVALID_FRESHNESS"}
    payload = {field: truth.get(field) for field in REQUIRED_PROCEDURAL_FIELDS}
    digest = generate_digest(payload)
    signature = sign_payload(payload)
    return {"valid": verify_signature(payload, signature), "truth_hash": digest, "signature": signature, "payload": payload}


def verify_truth_anchor(truth_anchor: Mapping[str, Any]) -> bool:
    return verify_signature(truth_anchor.get("payload", {}), truth_anchor.get("signature", {}))


def evaluate_truth_state(truth_anchor: Mapping[str, Any]) -> Dict[str, Any]:
    if not verify_truth_anchor(truth_anchor):
        return {"allowed": False, "reason": "TRUTH_INVALID"}
    payload = truth_anchor.get("payload", {})
    freshness = payload.get("freshness_state")
    if freshness != "VALID":
        return {"allowed": False, "reason": f"FRESHNESS_{freshness}"}
    if payload.get("threshold_state") != "SATISFIED":
        return {"allowed": False, "reason": "CORROBORATION_FAILURE"}
    return {"allowed": True, "truth_verified": True}
