from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.token_stack import issue_token, verify_token

REQUIRED_CORE_TOKENS = [
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain",
    "aurion",
    "execution_boundary",
]

REQUIRED_BUNDLE_TOKENS = [
    "threshold_bundle",
    "token_bundle",
]


def build_master_convergence_payload(state: Mapping[str, Any]) -> Dict[str, Any]:
    tokens = state.get("tokens", {})
    required = REQUIRED_CORE_TOKENS + REQUIRED_BUNDLE_TOKENS
    missing = [name for name in required if name not in tokens]
    token_digests = {name: tokens.get(name, {}).get("digest") for name in required if name in tokens}

    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash"),
        "pipeline_mode": state.get("pipeline_mode"),
        "convergence_hash": state.get("convergence_hash"),
        "threshold_bundle_digest": tokens.get("threshold_bundle", {}).get("digest"),
        "token_bundle_digest": tokens.get("token_bundle", {}).get("digest"),
        "required_token_digests": token_digests,
        "missing": missing,
        "valid": len(missing) == 0,
    }


def issue_master_convergence_token(
    state: Mapping[str, Any],
    *,
    issued_at_stage: str = "execution_gate",
) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    payload = build_master_convergence_payload(working_state)

    if not payload.get("valid"):
        working_state.setdefault("token_verification_failures", []).extend(
            f"missing_master_dependency:{item}" for item in payload.get("missing", [])
        )
        return working_state

    working_state = issue_token(
        working_state,
        name="master_convergence",
        issued_at_stage=issued_at_stage,
        payload=payload,
    )
    working_state["master_token"] = working_state.get("tokens", {}).get("master_convergence", {}).get("digest")
    return working_state


def verify_master_token(state: Mapping[str, Any]) -> bool:
    token = state.get("tokens", {}).get("master_convergence")
    if not isinstance(token, Mapping):
        return False

    if not verify_token(token, expected_request_fingerprint=state.get("request_fingerprint")):
        return False

    if state.get("master_token") != token.get("digest"):
        return False

    payload = token.get("payload")
    if not isinstance(payload, Mapping):
        return False

    if payload.get("request_fingerprint") != state.get("request_fingerprint"):
        return False

    if payload.get("pipeline_mode") != state.get("pipeline_mode"):
        return False

    if payload.get("convergence_hash") != state.get("convergence_hash"):
        return False

    tokens = state.get("tokens", {})
    if payload.get("threshold_bundle_digest") != tokens.get("threshold_bundle", {}).get("digest"):
        return False

    if payload.get("token_bundle_digest") != tokens.get("token_bundle", {}).get("digest"):
        return False

    required = REQUIRED_CORE_TOKENS + REQUIRED_BUNDLE_TOKENS
    if payload.get("missing"):
        return False

    required_token_digests = payload.get("required_token_digests", {})
    if set(required_token_digests.keys()) != set(required):
        return False

    for name in required:
        if required_token_digests.get(name) != tokens.get(name, {}).get("digest"):
            return False

    return True
