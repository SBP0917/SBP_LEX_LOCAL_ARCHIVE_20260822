from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import REQUIRED_CORE_TOKENS, SYSTEM_ISSUER, TOKEN_VERSION
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


def _token_signed_payload(token: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: token[key]
        for key in [
            "version",
            "name",
            "request_fingerprint",
            "state_hash",
            "tier",
            "corroboration_required",
            "issuer",
            "issued_at_stage",
            "issued_at",
            "issued_at_source",
            "payload",
        ]
        if key in token
    }


def _next_deterministic_issue_index(state: Mapping[str, Any]) -> int:
    return len(state.get("token_trace", [])) + 1


def issue_token(
    state: Mapping[str, Any],
    *,
    name: str,
    issued_at_stage: str,
    payload: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    issued_at = _next_deterministic_issue_index(working_state)
    token_payload = {
        "version": TOKEN_VERSION,
        "name": name,
        "request_fingerprint": working_state.get("request_fingerprint"),
        "state_hash": working_state.get("state_hash"),
        "tier": working_state.get("safety_profile", {}).get("computed_tier"),
        "corroboration_required": working_state.get("corroboration_required"),
        "issuer": SYSTEM_ISSUER,
        "issued_at_stage": issued_at_stage,
        "issued_at": issued_at,
        "issued_at_source": "TOKEN_TRACE_INDEX",
        "payload": deepcopy(dict(payload or {})),
    }
    digest = generate_digest(token_payload)
    signature = sign_payload(token_payload)
    token = {
        **token_payload,
        "digest": digest,
        "signature": signature,
        "verified": verify_signature(token_payload, signature),
    }
    working_state.setdefault("tokens", {})[name] = token
    working_state.setdefault("token_trace", []).append(
        {
            "event": "ISSUED",
            "name": name,
            "stage": issued_at_stage,
            "issued_at": issued_at,
            "digest": digest,
        }
    )
    return working_state


def verify_token(token: Mapping[str, Any], *, expected_request_fingerprint: str | None = None) -> bool:
    if not isinstance(token, Mapping):
        return False
    signed_payload = _token_signed_payload(token)
    if token.get("digest") != generate_digest(signed_payload):
        return False
    if expected_request_fingerprint is not None and token.get("request_fingerprint") != expected_request_fingerprint:
        return False
    return verify_signature(signed_payload, token.get("signature", {}))


def verify_required_tokens(state: Mapping[str, Any], *, required: list[str] | None = None) -> tuple[bool, list[str]]:
    required_names = required or REQUIRED_CORE_TOKENS
    tokens = state.get("tokens", {})
    failures: list[str] = []
    expected_fingerprint = state.get("request_fingerprint")
    for name in required_names:
        token = tokens.get(name)
        if token is None:
            failures.append(f"missing_token:{name}")
            continue
        if not verify_token(token, expected_request_fingerprint=expected_fingerprint):
            failures.append(f"invalid_token:{name}")
    return len(failures) == 0, failures


def issue_token_bundle(state: Mapping[str, Any], *, issued_at_stage: str = "token_bundle") -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    token_hashes = {
        name: token.get("digest")
        for name, token in sorted(working_state.get("tokens", {}).items())
    }
    return issue_token(
        working_state,
        name="token_bundle",
        issued_at_stage=issued_at_stage,
        payload={"token_hashes": token_hashes, "token_count": len(token_hashes)},
    )
