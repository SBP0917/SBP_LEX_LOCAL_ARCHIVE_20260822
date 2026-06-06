from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

REQUIRED_ROOT_FIELDS = ["anchor_id", "authority_hash", "trust_state", "continuity_epoch"]
VALID_TRUST_STATES = ["VALID", "REVOKED", "EXPIRED"]


def build_root_anchor(root_state: Mapping[str, Any]) -> Dict[str, Any]:
    missing = [field for field in REQUIRED_ROOT_FIELDS if root_state.get(field) is None]
    if missing:
        return {"valid": False, "reason": "ROOT_FIELDS_MISSING", "missing": missing}
    trust = root_state.get("trust_state")
    if trust not in VALID_TRUST_STATES:
        return {"valid": False, "reason": "INVALID_TRUST_STATE"}
    payload = {field: root_state.get(field) for field in REQUIRED_ROOT_FIELDS}
    digest = generate_digest(payload)
    signature = sign_payload(payload)
    return {"valid": verify_signature(payload, signature), "root_hash": digest, "signature": signature, "payload": payload}


def verify_root_anchor(root_anchor: Mapping[str, Any]) -> bool:
    return verify_signature(root_anchor.get("payload", {}), root_anchor.get("signature", {}))


def evaluate_root_chain(root_anchor: Mapping[str, Any]) -> Dict[str, Any]:
    if not verify_root_anchor(root_anchor):
        return {"allowed": False, "reason": "ROOT_CHAIN_INVALID"}
    state = root_anchor.get("payload", {}).get("trust_state")
    if state != "VALID":
        return {"allowed": False, "reason": f"ROOT_STATE_{state}"}
    return {"allowed": True, "root_verified": True}
