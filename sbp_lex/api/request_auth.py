from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlparse

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.api.credential_lifecycle import configured_registry

PROTOCOL_VERSION = "SBP_LEX_REQUEST_AUTH_V1"
AUTH_HEADER = "X-SBP-LEX-Request-Auth"
MAX_ENVELOPE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5
PRINCIPAL_TYPES = frozenset(
    {"viewer", "operator", "validator", "connector", "replay_examiner", "administrator", "maintenance"}
)
GET_PATHS = frozenset({
    "/health", "/dashboard", "/desktop", "/desktop/static/images/sbp_lex_background.png",
    "/desktop/latest", "/desktop/export/latest", "/desktop/export/replay-ledger",
    "/desktop/export/events", "/runtime/status", "/runtime/events", "/runtime/integrity",
    "/connector/checkpoints", "/apk/contract",
})
POST_SCOPES = {
    "/runtime/traverse": "runtime:traverse",
    "/runtime/replay": "runtime:replay",
    "/connector/envelope": "connector:submit",
    "/connector/build-envelope": "connector:build",
}
ENDPOINT_SCOPE_ALLOWLIST = {
    "viewer": frozenset({"observe"}),
    "operator": frozenset({"observe", "runtime:traverse", "runtime:replay"}),
    "validator": frozenset({"observe", "runtime:replay"}),
    "connector": frozenset({"observe", "connector:submit", "connector:build"}),
    "replay_examiner": frozenset({"observe", "runtime:replay"}),
    "administrator": frozenset({"observe", *POST_SCOPES.values()}),
    "maintenance": frozenset({"observe"}),
}
ENVELOPE_FIELDS = frozenset({
    "protocol_version", "request_id", "credential_id", "principal_id", "principal_type",
    "device_id", "method", "canonical_path", "canonical_query_digest",
    "canonical_body_digest", "content_type", "issued_at", "expires_at", "nonce",
    "security_mode", "credential_scope", "signature",
})


@dataclass(frozen=True)
class Principal:
    credential_id: str
    principal_id: str
    principal_type: str
    device_id: str
    scopes: frozenset[str]
    secret: str
    expires_at: datetime | None
    revoked: bool
    credential_version: int = 1
    status: str = "ACTIVE"


@dataclass(frozen=True)
class AuthenticationResult:
    allowed: bool
    status: int
    reason: str
    principal_id: str | None = None
    principal_type: str | None = None
    credential_scope: str | None = None


_REPLAY_LOCK = threading.Lock()
_USED_NONCES: set[tuple[str, str]] = set()
_USED_REQUEST_IDS: set[tuple[str, str]] = set()


def reset_replay_cache_for_tests() -> None:
    with _REPLAY_LOCK:
        _USED_NONCES.clear()
        _USED_REQUEST_IDS.clear()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def canonical_body_digest(body: bytes) -> str:
    parsed = loads_strict_json(body.decode("utf-8"))
    return hashlib.sha256(_canonical_json(parsed)).hexdigest()


def canonical_query_digest(path: str) -> str:
    parsed = urlparse(path)
    canonical = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_path(path: str) -> str:
    return urlparse(path).path


def _signature_payload(envelope: Mapping[str, Any]) -> bytes:
    return _canonical_json({key: envelope[key] for key in sorted(ENVELOPE_FIELDS - {"signature"})})


def sign_envelope(envelope: Mapping[str, Any], secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), _signature_payload(envelope), hashlib.sha256).hexdigest()


def configured_principals() -> dict[str, Principal]:
    return {
        item.credential_id: Principal(
            credential_id=item.credential_id, principal_id=item.principal_id,
            principal_type=item.principal_type, device_id=item.device_id,
            scopes=item.allowed_scopes, secret=item.secret, expires_at=item.expires_at,
            revoked=item.status == "REVOKED", credential_version=item.credential_version,
            status=item.status,
        )
        for item in configured_registry().snapshot().values()
        if item.principal_type in PRINCIPAL_TYPES
    }


def required_scope(method: str, path: str) -> str | None:
    parsed_path = canonical_path(path)
    if method == "GET" and parsed_path in GET_PATHS:
        return "observe"
    if method == "POST":
        return POST_SCOPES.get(parsed_path)
    return None


def principal_authorized(principal_type: str, scope: str, *, runtime_execution_active: bool = False) -> bool:
    if principal_type not in PRINCIPAL_TYPES or scope not in ENDPOINT_SCOPE_ALLOWLIST[principal_type]:
        return False
    if principal_type == "maintenance" and runtime_execution_active:
        return False
    return True


def _deny(reason: str, status: int = 401) -> AuthenticationResult:
    return AuthenticationResult(False, status, reason)


def authenticate_signed_request(
    *, method: str, path: str, content_type: str, body: bytes,
    envelope_text: str | None, security_mode: str, now: datetime | None = None,
    runtime_execution_active: bool = False,
) -> AuthenticationResult:
    if not envelope_text:
        return _deny("signed_request_authentication_required")
    try:
        envelope = loads_strict_json(envelope_text)
    except Exception:
        return _deny("malformed_request_authentication_envelope")
    if not isinstance(envelope, Mapping) or set(envelope) != ENVELOPE_FIELDS:
        return _deny("invalid_request_authentication_envelope_schema")
    if envelope.get("protocol_version") != PROTOCOL_VERSION:
        return _deny("unsupported_request_authentication_protocol")

    credential_id = envelope.get("credential_id")
    principal = configured_principals().get(credential_id) if isinstance(credential_id, str) else None
    if principal is None:
        return _deny("unknown_credential")
    current = now or datetime.now(timezone.utc)
    lifecycle_credential = configured_registry().get(principal.credential_id)
    if lifecycle_credential is None:
        return _deny("unknown_credential")
    if principal.credential_version < 1:
        return _deny("credential_version_unknown")
    if current < lifecycle_credential.not_before:
        return _deny("credential_not_yet_active")
    if principal.revoked or lifecycle_credential.status == "REVOKED":
        return _deny("credential_revoked")
    if current >= lifecycle_credential.expires_at:
        return _deny("credential_expired")
    if lifecycle_credential.status in {"PENDING", "SUSPENDED", "RETIRED", "EXPIRED"}:
        return _deny(f"credential_status_denied:{lifecycle_credential.status.lower()}")
    if not configured_registry().can_authenticate(lifecycle_credential, current):
        return _deny("credential_not_active")
    scope = required_scope(method, path)
    if scope is None:
        return _deny("endpoint_scope_denied", 403)
    if scope not in principal.scopes or not principal_authorized(
        principal.principal_type, scope, runtime_execution_active=runtime_execution_active
    ):
        return _deny("principal_scope_denied", 403)

    bindings = {
        "credential_id": principal.credential_id, "principal_id": principal.principal_id,
        "principal_type": principal.principal_type, "device_id": principal.device_id,
        "method": method, "canonical_path": canonical_path(path),
        "canonical_query_digest": canonical_query_digest(path),
        "content_type": content_type.lower().strip(), "security_mode": security_mode,
        "credential_scope": scope,
    }
    for key, expected in bindings.items():
        if envelope.get(key) != expected:
            return _deny(f"request_authentication_binding_mismatch:{key}")
    try:
        body_digest = canonical_body_digest(body)
    except Exception:
        return _deny("request_authentication_body_not_strict_json")
    if envelope.get("canonical_body_digest") != body_digest:
        return _deny("request_authentication_binding_mismatch:canonical_body_digest")

    issued = _parse_time(envelope.get("issued_at"))
    expires = _parse_time(envelope.get("expires_at"))
    if issued is None or expires is None or expires <= issued:
        return _deny("invalid_request_authentication_time_window")
    if (expires - issued).total_seconds() > MAX_ENVELOPE_SECONDS:
        return _deny("request_authentication_window_too_wide")
    if (issued - current).total_seconds() > MAX_FUTURE_SKEW_SECONDS:
        return _deny("request_authentication_issued_in_future")
    if current >= expires:
        return _deny("request_authentication_expired")

    request_id = envelope.get("request_id")
    nonce = envelope.get("nonce")
    if not isinstance(request_id, str) or not request_id or not isinstance(nonce, str) or not nonce:
        return _deny("invalid_request_authentication_replay_fields")
    signature = envelope.get("signature")
    if not isinstance(signature, str) or not hmac.compare_digest(signature, sign_envelope(envelope, principal.secret)):
        return _deny("invalid_request_authentication_signature")

    nonce_key = (principal.credential_id, nonce)
    request_key = (principal.credential_id, request_id)
    with _REPLAY_LOCK:
        if nonce_key in _USED_NONCES:
            return _deny("request_authentication_nonce_reused")
        if request_key in _USED_REQUEST_IDS:
            return _deny("request_authentication_request_id_reused")
        _USED_NONCES.add(nonce_key)
        _USED_REQUEST_IDS.add(request_key)
    configured_registry().mark_used(principal.credential_id, current)
    return AuthenticationResult(True, 200, "scoped_request_authenticated", principal.principal_id, principal.principal_type, scope)


def build_signed_envelope(
    *, principal: Principal, method: str, path: str, content_type: str, body: bytes,
    request_id: str, nonce: str, issued_at: datetime, expires_at: datetime,
    security_mode: str = "private",
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION, "request_id": request_id,
        "credential_id": principal.credential_id, "principal_id": principal.principal_id,
        "principal_type": principal.principal_type, "device_id": principal.device_id,
        "method": method, "canonical_path": canonical_path(path),
        "canonical_query_digest": canonical_query_digest(path),
        "canonical_body_digest": canonical_body_digest(body),
        "content_type": content_type.lower().strip(),
        "issued_at": issued_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": nonce, "security_mode": security_mode,
        "credential_scope": required_scope(method, path), "signature": "",
    }
    envelope["signature"] = sign_envelope(envelope, principal.secret)
    return envelope
