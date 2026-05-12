from __future__ import annotations

from typing import Dict, Any
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

THRESHOLD_CATEGORIES = [
    "human_safety",
    "irreversibility",
    "cascading_impact",
    "financial_operational",
    "consequentiality_tier",
    "corroboration",
    "autonomy_boundary",
    "financial_tier",
    "escalation",
]

def _build_child_token(
    *,
    name: str,
    value: Any,
    state_hash: str,
    request_fingerprint: str,
    stage: str,
) -> Dict[str, Any]:

    payload = {
        "name": name,
        "value": value,
        "state_hash": state_hash,
        "request_fingerprint": request_fingerprint,
        "stage": stage,
    }

    digest = generate_digest(str(payload))
    signature = sign_payload(digest)

    return {
        **payload,
        "digest": digest,
        "signature": signature,
        "verified": True,
    }


def issue_threshold_bundle(state: dict, stage: str) -> dict:
    state_hash = state.get("state_hash")
    fingerprint = state.get("request_fingerprint")

    safety = state.get("safety_profile", {})

    child_tokens = {}

    # Individual threshold tokens
    for key in THRESHOLD_CATEGORIES:
        value = safety.get(key) or state.get(key)

        token = _build_child_token(
            name=f"{key}_token",
            value=value,
            state_hash=state_hash,
            request_fingerprint=fingerprint,
            stage=stage,
        )

        child_tokens[key] = token

    # Bundle hash (fast verification root)
    bundle_payload = {
        k: v["digest"] for k, v in child_tokens.items()
    }

    bundle_digest = generate_digest(str(bundle_payload))
    bundle_signature = sign_payload(bundle_digest)

    bundle_token = {
        "name": "threshold
