from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

CONVERGENCE_FIELDS = [
    "request_fingerprint",
    "state_hash",
    "classification_result",
    "licensing_result",
    "governance_result",
    "domain_result",
    "aurion15_result",
    "execution_result",
    "decision",
]


def build_convergence_digest(state: Mapping[str, Any]) -> Dict[str, Any]:
    tokens = state.get("tokens", {})
    payload = {field: state.get(field) for field in CONVERGENCE_FIELDS}
    payload.update(
        {
            "threshold_bundle_hash": tokens.get("threshold_bundle", {}).get("digest"),
            "token_bundle_hash": tokens.get("token_bundle", {}).get("digest"),
            "hash_chain_tail": state.get("hash_chain", [{}])[-1].get("hash") if state.get("hash_chain") else "GENESIS",
        }
    )
    convergence_hash = generate_digest(payload)
    signature = sign_payload(payload)
    return {
        "payload": payload,
        "convergence_hash": convergence_hash,
        "signature": signature,
        "verified": verify_signature(payload, signature),
    }


def verify_convergence_digest(state: Mapping[str, Any], digest_record: Mapping[str, Any]) -> bool:
    if not isinstance(digest_record, Mapping):
        return False

    payload = digest_record.get("payload")
    if not isinstance(payload, Mapping):
        return False

    if digest_record.get("convergence_hash") != generate_digest(payload):
        return False

    if not verify_signature(payload, digest_record.get("signature", {})):
        return False

    for field in CONVERGENCE_FIELDS:
        if payload.get(field) != state.get(field):
            return False

    tokens = state.get("tokens", {})
    if payload.get("threshold_bundle_hash") != tokens.get("threshold_bundle", {}).get("digest"):
        return False

    if payload.get("token_bundle_hash") != tokens.get("token_bundle", {}).get("digest"):
        return False

    current_tail = state.get("hash_chain", [{}])[-1].get("hash") if state.get("hash_chain") else "GENESIS"
    if payload.get("hash_chain_tail") != current_tail:
        return False

    return True
