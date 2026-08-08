from __future__ import annotations

from copy import deepcopy
from typing import Any, Collection, Dict, Mapping

from sbp_lex.config.security_config import REQUIRED_CORE_TOKENS, SYSTEM_ISSUER, TOKEN_VERSION
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

TOKEN_SIGNED_FIELDS = {
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
}
TOKEN_WRAPPER_FIELDS = TOKEN_SIGNED_FIELDS | {"digest", "signature", "verified"}
TOKEN_TRACE_FIELDS = {"event", "name", "stage", "issued_at", "digest"}
TOKEN_STAGE_ORDER = {
    stage: index
    for index, stage in enumerate(
        (
            "root_of_trust",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
            "domain_wrap",
            "aurion_runtime",
            "execution_gate",
        )
    )
}

_UNSET = object()


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
    if not isinstance(name, str) or not name:
        raise ValueError("token_name_invalid")
    if not isinstance(issued_at_stage, str) or not issued_at_stage:
        raise ValueError("token_stage_invalid")
    if payload is not None and not isinstance(payload, Mapping):
        raise ValueError("token_payload_invalid")
    if not isinstance(working_state.get("tokens", {}), Mapping):
        raise ValueError("token_store_invalid")
    if not isinstance(working_state.get("token_trace", []), list):
        raise ValueError("token_trace_invalid")
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


def verify_token(
    token: Mapping[str, Any],
    *,
    expected_request_fingerprint: str | None = None,
    expected_name: str | None = None,
    expected_stage: str | None = None,
    expected_state_hash: str | None = None,
    expected_eie_digest: Any = _UNSET,
    expected_traversal_id: Any = _UNSET,
    expected_tier: Any = _UNSET,
    expected_collective_attachment_hash: Any = _UNSET,
    expected_runtime_binding_digest: Any = _UNSET,
    expected_audit_readiness_digest: Any = _UNSET,
) -> bool:
    if not isinstance(token, Mapping):
        return False
    if set(token) != TOKEN_WRAPPER_FIELDS:
        return False
    if token.get("version") != TOKEN_VERSION:
        return False
    if token.get("issuer") != SYSTEM_ISSUER:
        return False
    if (
        not isinstance(token.get("name"), str)
        or not token.get("name")
        or not isinstance(token.get("request_fingerprint"), str)
        or not token.get("request_fingerprint")
        or not isinstance(token.get("state_hash"), str)
        or not token.get("state_hash")
        or not isinstance(token.get("issued_at_stage"), str)
        or not token.get("issued_at_stage")
        or not isinstance(token.get("issued_at"), int)
        or isinstance(token.get("issued_at"), bool)
        or token.get("issued_at", 0) <= 0
        or token.get("issued_at_source") != "TOKEN_TRACE_INDEX"
        or not isinstance(token.get("payload"), Mapping)
        or token.get("verified") is not True
    ):
        return False
    signed_payload = _token_signed_payload(token)
    if set(signed_payload) != TOKEN_SIGNED_FIELDS:
        return False
    if token.get("digest") != generate_digest(signed_payload):
        return False
    if expected_request_fingerprint is not None and token.get("request_fingerprint") != expected_request_fingerprint:
        return False
    if expected_name is not None and token.get("name") != expected_name:
        return False
    if expected_stage is not None and token.get("issued_at_stage") != expected_stage:
        return False
    if expected_state_hash is not None and token.get("state_hash") != expected_state_hash:
        return False
    if expected_tier is not _UNSET and token.get("tier") != expected_tier:
        return False
    payload = token.get("payload", {})
    payload_bindings = (
        ("eie_digest", expected_eie_digest),
        ("traversal_id", expected_traversal_id),
        ("collective_attachment_hash", expected_collective_attachment_hash),
        ("execution_runtime_binding_digest", expected_runtime_binding_digest),
        ("audit_readiness_digest", expected_audit_readiness_digest),
    )
    for field, expected in payload_bindings:
        if expected is not _UNSET and payload.get(field) != expected:
            return False
    return verify_signature(signed_payload, token.get("signature", {}))


def verify_required_tokens(state: Mapping[str, Any], *, required: list[str] | None = None) -> tuple[bool, list[str]]:
    required_names = required or REQUIRED_CORE_TOKENS
    tokens = state.get("tokens", {})
    failures: list[str] = []
    if not isinstance(tokens, Mapping):
        return False, ["token_store_invalid"]
    expected_fingerprint = state.get("request_fingerprint")
    for name in required_names:
        token = tokens.get(name)
        if token is None:
            failures.append(f"missing_token:{name}")
            continue
        if not verify_token(
            token,
            expected_request_fingerprint=expected_fingerprint,
            expected_name=name,
        ):
            failures.append(f"invalid_token:{name}")
    return len(failures) == 0, failures


def verify_exact_token_bundle(
    state: Mapping[str, Any],
    *,
    expected_names: Collection[str],
    bundle_name: str = "token_bundle",
    expected_stage: str | None = None,
) -> tuple[bool, list[str]]:
    """Verify the signed bundle snapshot against its exact live token subset.

    ``expected_names`` describes the tokens that existed immediately before the
    bundle was issued.  Later terminal tokens may exist in the live store, but
    they cannot be silently added to or removed from the signed snapshot.
    """

    failures: list[str] = []
    tokens = state.get("tokens", {})
    if not isinstance(tokens, Mapping):
        return False, ["token_bundle_store_invalid"]
    if (
        not isinstance(expected_names, Collection)
        or isinstance(expected_names, (str, bytes))
    ):
        return False, ["token_bundle_expected_names_invalid"]
    names = list(expected_names)
    if (
        any(not isinstance(name, str) or not name for name in names)
        or len(names) != len(set(names))
        or bundle_name in names
    ):
        return False, ["token_bundle_expected_names_invalid"]

    bundle = tokens.get(bundle_name)
    if not verify_token(
        bundle,
        expected_request_fingerprint=state.get("request_fingerprint"),
        expected_name=bundle_name,
        expected_stage=expected_stage,
    ):
        failures.append("token_bundle_invalid")
        return False, failures

    expected_hashes: dict[str, Any] = {}
    for name in names:
        token = tokens.get(name)
        if not isinstance(token, Mapping):
            failures.append(f"token_bundle_live_token_missing:{name}")
            continue
        if not verify_token(
            token,
            expected_request_fingerprint=state.get("request_fingerprint"),
            expected_name=name,
        ):
            failures.append(f"token_bundle_live_token_invalid:{name}")
        expected_hashes[name] = token.get("digest")

    payload = bundle.get("payload", {}) if isinstance(bundle, Mapping) else {}
    if not isinstance(payload, Mapping) or set(payload) != {
        "token_hashes",
        "token_count",
    }:
        failures.append("token_bundle_payload_invalid")
    else:
        token_hashes = payload.get("token_hashes")
        if not isinstance(token_hashes, Mapping):
            failures.append("token_bundle_hashes_invalid")
        elif dict(token_hashes) != {
            name: expected_hashes.get(name) for name in sorted(names)
        }:
            failures.append("token_bundle_hashes_mismatch")
        if payload.get("token_count") != len(names):
            failures.append("token_bundle_count_mismatch")
    return not failures, sorted(set(failures))


def verify_token_trace(
    state: Mapping[str, Any],
    *,
    expected_names: Collection[str],
    exact: bool = False,
) -> tuple[bool, list[str]]:
    """Verify one exact issuance event for each expected live token."""

    failures: list[str] = []
    tokens = state.get("tokens", {})
    trace = state.get("token_trace", [])
    if not isinstance(tokens, Mapping):
        return False, ["token_trace_store_invalid"]
    if not isinstance(trace, list):
        return False, ["token_trace_invalid"]
    if (
        not isinstance(expected_names, Collection)
        or isinstance(expected_names, (str, bytes))
    ):
        return False, ["token_trace_expected_names_invalid"]
    names = list(expected_names)
    if any(not isinstance(name, str) or not name for name in names) or len(
        names
    ) != len(set(names)):
        return False, ["token_trace_expected_names_invalid"]

    issued: list[Mapping[str, Any]] = []
    prior_stage_index = -1
    for index, entry in enumerate(trace):
        if not isinstance(entry, Mapping) or set(entry) != TOKEN_TRACE_FIELDS:
            failures.append(f"token_trace_entry_invalid:{index}")
            continue
        if (
            entry.get("event") != "ISSUED"
            or not isinstance(entry.get("name"), str)
            or not entry.get("name")
            or not isinstance(entry.get("stage"), str)
            or not entry.get("stage")
            or not isinstance(entry.get("issued_at"), int)
            or isinstance(entry.get("issued_at"), bool)
            or entry.get("issued_at", 0) <= 0
            or not isinstance(entry.get("digest"), str)
            or not entry.get("digest")
        ):
            failures.append(f"token_trace_entry_invalid:{index}")
            continue
        expected_issued_at = index + 1
        if entry.get("issued_at") != expected_issued_at:
            failures.append(f"token_trace_index_invalid:{index}")
        stage_index = TOKEN_STAGE_ORDER.get(str(entry.get("stage")))
        if stage_index is None:
            failures.append(f"token_trace_stage_invalid:{index}")
        elif stage_index < prior_stage_index:
            failures.append(f"token_trace_stage_order_invalid:{index}")
        else:
            prior_stage_index = stage_index
        issued.append(entry)

    issued_indices = [entry.get("issued_at") for entry in issued]
    if (
        len(issued_indices) != len(set(issued_indices))
        or issued_indices != list(range(1, len(trace) + 1))
    ):
        failures.append("token_trace_issue_sequence_invalid")

    issued_names = [str(entry.get("name")) for entry in issued]
    for name in names:
        token = tokens.get(name)
        matches = [
            entry
            for entry in issued
            if isinstance(token, Mapping)
            and entry.get("name") == name
            and entry.get("stage") == token.get("issued_at_stage")
            and entry.get("issued_at") == token.get("issued_at")
            and entry.get("digest") == token.get("digest")
        ]
        if len(matches) != 1:
            failures.append(f"token_trace_mismatch:{name}")
        if issued_names.count(name) != 1:
            failures.append(f"token_trace_duplicate:{name}")

    if exact:
        expected_set = set(names)
        if set(tokens) != expected_set:
            failures.append("token_store_name_set_mismatch")
        if len(issued) != len(names) or set(issued_names) != expected_set:
            failures.append("token_trace_name_set_mismatch")
    return not failures, sorted(set(failures))


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
