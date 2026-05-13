from __future__ import annotations

def verify_token(token: Mapping[str, Any], *, expected_state_hash: str | None = None) -> bool:
    token_dict = dict(token)
    signature = token_dict.get("signature")
    signed_payload = {
        key: token_dict[key]
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
            "payload",
        ]
        if key in token_dict
    }
    if expected_state_hash is not None and token_dict.get("state_hash") != expected_state_hash:
        return False
    if token_dict.get("digest") != generate_digest(signed_payload):
        return False
    return verify_signature(signed_payload, signature)


def verify_required_tokens(state: Mapping[str, Any], *, required: list[str] | None = None) -> tuple[bool, list[str]]:
    required_names = required or REQUIRED_CORE_TOKENS
    tokens = state.get("tokens", {})
    failures: list[str] = []
    expected_state_hash = state.get("state_hash")
    for name in required_names:
        token = tokens.get(name)
        if token is None:
            failures.append(f"missing_token:{name}")
            continue
        if not verify_token(token, expected_state_hash=expected_state_hash):
            failures.append(f"invalid_token:{name}")
    return len(failures) == 0, failures


def issue_token_bundle(state: Mapping[str, Any], *, issued_at_stage: str = "token_bundle") -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    token_hashes = {
        name: token.get("digest")
        for name, token in sorted(working_state.get("tokens", {}).items())
    }
    payload = {
        "token_hashes": token_hashes,
        "token_count": len(token_hashes),
    }
    return issue_token(working_state, name="token_bundle", issued_at_stage=issued_at_stage, payload=payload)
