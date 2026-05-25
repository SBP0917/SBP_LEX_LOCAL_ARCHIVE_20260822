from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import CONVERGENCE_VERSION
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


def build_pipeline_convergence_proof(
    *,
    pipeline_a: Mapping[str, Any],
    pipeline_b: Mapping[str, Any] | None = None,
    mode: str,
) -> Dict[str, Any]:
    a_summary = _state_summary(pipeline_a)
    b_summary = _state_summary(pipeline_b) if pipeline_b is not None else None
    matched = True
    mismatches: list[str] = []

    if pipeline_b is not None:
        for key in ["state_hash", "decision", "execution_result", "governance_result", "domain_result", "aurion15_result"]:
            if a_summary.get(key) != b_summary.get(key):
                matched = False
                mismatches.append(key)

    payload = {
        "version": CONVERGENCE_VERSION,
        "mode": mode,
        "pipeline_a": a_summary,
        "pipeline_b": b_summary,
        "matched": matched,
        "mismatches": mismatches,
    }
    convergence_hash = generate_digest(payload)
    signature = sign_payload(payload)
    return {
        **payload,
        "convergence_hash": convergence_hash,
        "signature": signature,
        "verified": verify_signature(payload, signature),
    }


def _state_summary(state: Mapping[str, Any] | None) -> Dict[str, Any] | None:
    if state is None:
        return None
    tokens = state.get("tokens", {})
    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash"),
        "pipeline_mode": state.get("pipeline_mode"),
        "governance_result": state.get("governance_result"),
        "domain_result": state.get("domain_result"),
        "aurion15_result": state.get("aurion15_result"),
        "execution_result": state.get("execution_result"),
        "decision": state.get("decision"),
        "threshold_bundle_hash": tokens.get("threshold_bundle", {}).get("digest"),
        "token_bundle_hash": tokens.get("token_bundle", {}).get("digest"),
        "audit_hash": state.get("audit_hash"),
    }


def verify_convergence_proof(proof: Mapping[str, Any]) -> bool:
    return {**payload, "signature": signature}
