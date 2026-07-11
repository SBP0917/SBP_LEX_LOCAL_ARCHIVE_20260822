from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sbp_lex.api.access_control import decide_access
from sbp_lex.api.request_auth import (
    AUTH_HEADER,
    ENDPOINT_SCOPE_ALLOWLIST,
    GET_PATHS,
    POST_SCOPES,
    Principal,
    authenticate_signed_request,
    build_signed_envelope,
    principal_authorized,
    reset_replay_cache_for_tests,
    sign_envelope,
)

SECRET = "test-only-secret-material-32-bytes"
NOW = datetime(2026, 7, 11, 5, 0, tzinfo=timezone.utc)
BODY = b'{"request":{"action":"inspect"}}'
CONTENT_TYPE = "application/json"
PRINCIPALS = tuple(ENDPOINT_SCOPE_ALLOWLIST)
ENDPOINTS = tuple([("GET", path, "observe") for path in sorted(GET_PATHS)] + [
    ("POST", path, scope) for path, scope in sorted(POST_SCOPES.items())
])


def _record(principal_type: str, **overrides):
    record = {
        "credential_id": f"credential-{principal_type}",
        "principal_id": f"principal-{principal_type}",
        "principal_type": principal_type,
        "device_id": f"device-{principal_type}",
        "scopes": sorted(ENDPOINT_SCOPE_ALLOWLIST[principal_type]),
        "secret": SECRET,
        "revoked": False,
    }
    record.update(overrides)
    return record


def _principal(principal_type: str) -> Principal:
    record = _record(principal_type)
    return Principal(
        credential_id=record["credential_id"],
        principal_id=record["principal_id"],
        principal_type=principal_type,
        device_id=record["device_id"],
        scopes=frozenset(record["scopes"]),
        secret=SECRET,
        expires_at=None,
        revoked=False,
    )


def _install(monkeypatch, principal_type: str = "administrator", **overrides):
    monkeypatch.setenv("SBP_LEX_API_PRINCIPALS", json.dumps([_record(principal_type, **overrides)]))
    reset_replay_cache_for_tests()


def _envelope(
    principal_type: str = "administrator",
    *,
    method: str = "POST",
    path: str = "/runtime/traverse",
    body: bytes = BODY,
    request_id: str = "request-1",
    nonce: str = "nonce-1",
    issued: datetime = NOW,
    expires: datetime | None = None,
):
    return build_signed_envelope(
        principal=_principal(principal_type),
        method=method,
        path=path,
        content_type=CONTENT_TYPE,
        body=body,
        request_id=request_id,
        nonce=nonce,
        issued_at=issued,
        expires_at=expires or issued + timedelta(seconds=60),
    )


def _authenticate(monkeypatch, envelope, **overrides):
    principal_type = overrides.pop("principal_type", "administrator")
    _install(monkeypatch, principal_type)
    values = {
        "method": "POST",
        "path": "/runtime/traverse",
        "content_type": CONTENT_TYPE,
        "body": BODY,
        "envelope_text": json.dumps(envelope),
        "security_mode": "private",
        "now": NOW,
    }
    values.update(overrides)
    return authenticate_signed_request(**values)


@pytest.mark.parametrize("principal_type", PRINCIPALS)
@pytest.mark.parametrize("method,path,scope", ENDPOINTS)
def test_every_principal_against_every_endpoint(principal_type, method, path, scope):
    assert principal_authorized(principal_type, scope) is (
        scope in ENDPOINT_SCOPE_ALLOWLIST[principal_type]
    )


def test_viewer_is_observation_only():
    for scope in POST_SCOPES.values():
        assert not principal_authorized("viewer", scope)


def test_connector_cannot_replay_or_administer():
    assert not principal_authorized("connector", "runtime:replay")
    assert not principal_authorized("connector", "runtime:traverse")


def test_replay_examiner_cannot_traverse():
    assert principal_authorized("replay_examiner", "runtime:replay")
    assert not principal_authorized("replay_examiner", "runtime:traverse")


def test_administrator_access_does_not_encode_execution_authority():
    assert "execution:authorize" not in ENDPOINT_SCOPE_ALLOWLIST["administrator"]
    assert principal_authorized("administrator", "runtime:traverse")


def test_maintenance_valid_only_while_execution_inactive():
    assert principal_authorized("maintenance", "observe", runtime_execution_active=False)
    assert not principal_authorized("maintenance", "observe", runtime_execution_active=True)


def test_valid_signed_request_and_private_server_decision(monkeypatch):
    _install(monkeypatch)
    envelope = _envelope()
    result = authenticate_signed_request(
        method="POST", path="/runtime/traverse", content_type=CONTENT_TYPE, body=BODY,
        envelope_text=json.dumps(envelope), security_mode="private", now=NOW,
    )
    assert result.allowed
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "private")
    reset_replay_cache_for_tests()
    live_now = datetime.now(timezone.utc)
    envelope = _envelope(issued=live_now, expires=live_now + timedelta(seconds=60))
    decision = decide_access(
        method="POST", path="/runtime/traverse", client_host="203.0.113.8",
        headers={AUTH_HEADER: json.dumps(envelope), "Content-Type": CONTENT_TYPE}, body=BODY,
    )
    assert decision.allowed
    assert decision.principal_type == "administrator"


def test_private_bearer_only_post_fails_closed(monkeypatch):
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "private")
    monkeypatch.setenv("SBP_LEX_API_TOKEN", "legacy-private-token-value")
    decision = decide_access(
        method="POST", path="/runtime/traverse", client_host="203.0.113.8",
        headers={"Authorization": "Bearer legacy-private-token-value", "Content-Type": CONTENT_TYPE},
        body=BODY,
    )
    assert not decision.allowed
    assert decision.reason == "signed_request_authentication_required"


def test_legacy_private_bearer_is_bounded_to_viewer_get(monkeypatch):
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "private")
    monkeypatch.setenv("SBP_LEX_API_TOKEN", "legacy-private-token-value")
    decision = decide_access(
        method="GET", path="/runtime/status", client_host="203.0.113.8",
        headers={"Authorization": "Bearer legacy-private-token-value"},
    )
    assert decision.allowed
    assert decision.principal_type == "viewer"
    assert decision.credential_scope == "observe"


def test_local_mode_compatibility_preserved(monkeypatch):
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "local")
    decision = decide_access(
        method="POST", path="/runtime/traverse", client_host="127.0.0.1",
        headers={"Content-Type": CONTENT_TYPE}, body=BODY,
    )
    assert decision.allowed


@pytest.mark.parametrize(
    "principal_type,path",
    [("viewer", "/runtime/traverse"), ("connector", "/runtime/replay"), ("replay_examiner", "/runtime/traverse")],
)
def test_wrong_principal_scope_denied(monkeypatch, principal_type, path):
    _install(monkeypatch, principal_type)
    envelope = _envelope(principal_type, path=path)
    result = authenticate_signed_request(
        method="POST", path=path, content_type=CONTENT_TYPE, body=BODY,
        envelope_text=json.dumps(envelope), security_mode="private", now=NOW,
    )
    assert not result.allowed
    assert result.reason == "principal_scope_denied"


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ({"principal_id": "other"}, "request_authentication_binding_mismatch:principal_id"),
        ({"principal_type": "viewer"}, "request_authentication_binding_mismatch:principal_type"),
        ({"device_id": "other-device"}, "request_authentication_binding_mismatch:device_id"),
        ({"method": "PUT"}, "request_authentication_binding_mismatch:method"),
        ({"canonical_path": "/runtime/replay"}, "request_authentication_binding_mismatch:canonical_path"),
        ({"canonical_query_digest": "0" * 64}, "request_authentication_binding_mismatch:canonical_query_digest"),
        ({"content_type": "text/plain"}, "request_authentication_binding_mismatch:content_type"),
        ({"credential_scope": "runtime:replay"}, "request_authentication_binding_mismatch:credential_scope"),
        ({"canonical_body_digest": "0" * 64}, "request_authentication_binding_mismatch:canonical_body_digest"),
    ],
)
def test_resigned_binding_mutations_are_denied(monkeypatch, mutation, expected):
    envelope = _envelope()
    envelope.update(mutation)
    envelope["signature"] = sign_envelope(envelope, SECRET)
    result = _authenticate(monkeypatch, envelope)
    assert not result.allowed
    assert result.reason == expected


def test_altered_actual_body_path_method_query_and_content_type_denied(monkeypatch):
    cases = [
        {"body": b'{"request":{"action":"changed"}}'},
        {"path": "/runtime/replay"},
        {"method": "PUT"},
        {"path": "/runtime/traverse?changed=1"},
        {"content_type": "application/problem+json"},
    ]
    for index, changes in enumerate(cases):
        envelope = _envelope(request_id=f"req-{index}", nonce=f"nonce-{index}")
        result = _authenticate(monkeypatch, envelope, **changes)
        assert not result.allowed


def test_unknown_missing_expired_revoked_and_wrong_scope_credentials(monkeypatch):
    envelope = _envelope()
    _install(monkeypatch)
    missing = dict(envelope)
    missing["credential_id"] = ""
    assert not authenticate_signed_request(
        method="POST", path="/runtime/traverse", content_type=CONTENT_TYPE, body=BODY,
        envelope_text=json.dumps(missing), security_mode="private", now=NOW,
    ).allowed

    unknown = dict(envelope)
    unknown["credential_id"] = "unknown"
    unknown["signature"] = sign_envelope(unknown, SECRET)
    assert _authenticate(monkeypatch, unknown).reason == "unknown_credential"

    _install(monkeypatch, expires_at=(NOW - timedelta(seconds=1)).isoformat())
    assert authenticate_signed_request(
        method="POST", path="/runtime/traverse", content_type=CONTENT_TYPE, body=BODY,
        envelope_text=json.dumps(envelope), security_mode="private", now=NOW,
    ).reason == "credential_expired"

    _install(monkeypatch, revoked=True)
    assert authenticate_signed_request(
        method="POST", path="/runtime/traverse", content_type=CONTENT_TYPE, body=BODY,
        envelope_text=json.dumps(envelope), security_mode="private", now=NOW,
    ).reason == "credential_revoked"

    _install(monkeypatch, scopes=["observe"])
    assert authenticate_signed_request(
        method="POST", path="/runtime/traverse", content_type=CONTENT_TYPE, body=BODY,
        envelope_text=json.dumps(envelope), security_mode="private", now=NOW,
    ).reason == "principal_scope_denied"


def test_expired_future_and_wide_envelope_windows_denied(monkeypatch):
    expired = _envelope(issued=NOW - timedelta(minutes=2), expires=NOW - timedelta(seconds=1))
    assert _authenticate(monkeypatch, expired).reason == "request_authentication_expired"
    future = _envelope(issued=NOW + timedelta(seconds=6))
    assert _authenticate(monkeypatch, future).reason == "request_authentication_issued_in_future"
    wide = _envelope(expires=NOW + timedelta(seconds=121))
    assert _authenticate(monkeypatch, wide).reason == "request_authentication_window_too_wide"


def test_invalid_signature_duplicate_key_and_malformed_envelope_denied(monkeypatch):
    envelope = _envelope()
    envelope["signature"] = "0" * 64
    assert _authenticate(monkeypatch, envelope).reason == "invalid_request_authentication_signature"
    duplicate = json.dumps(_envelope())[:-1] + ',"nonce":"duplicate"}'
    _install(monkeypatch)
    result = authenticate_signed_request(
        method="POST", path="/runtime/traverse", content_type=CONTENT_TYPE, body=BODY,
        envelope_text=duplicate, security_mode="private", now=NOW,
    )
    assert result.reason == "malformed_request_authentication_envelope"


def test_duplicate_body_key_is_denied(monkeypatch):
    envelope = _envelope()
    result = _authenticate(monkeypatch, envelope, body=b'{"request":1,"request":2}')
    assert result.reason == "request_authentication_body_not_strict_json"


def test_nonce_and_request_id_are_single_use(monkeypatch):
    _install(monkeypatch)
    first = _envelope()
    kwargs = dict(
        method="POST", path="/runtime/traverse", content_type=CONTENT_TYPE, body=BODY,
        security_mode="private", now=NOW,
    )
    assert authenticate_signed_request(envelope_text=json.dumps(first), **kwargs).allowed
    assert authenticate_signed_request(envelope_text=json.dumps(first), **kwargs).reason == "request_authentication_nonce_reused"

    reset_replay_cache_for_tests()
    second = _envelope(nonce="nonce-2")
    assert authenticate_signed_request(envelope_text=json.dumps(first), **kwargs).allowed
    assert authenticate_signed_request(envelope_text=json.dumps(second), **kwargs).reason == "request_authentication_request_id_reused"


def test_request_cannot_be_replayed_for_another_endpoint_or_payload(monkeypatch):
    envelope = _envelope()
    assert not _authenticate(monkeypatch, envelope, path="/runtime/replay").allowed
    assert not _authenticate(monkeypatch, envelope, body=b'{"request":{"action":"other"}}').allowed


def test_secret_never_appears_in_results_or_access_payload(monkeypatch):
    envelope = _envelope()
    envelope["signature"] = "bad"
    result = _authenticate(monkeypatch, envelope)
    assert SECRET not in repr(result)
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "private")
    decision = decide_access(
        method="POST", path="/runtime/traverse", client_host="203.0.113.8",
        headers={AUTH_HEADER: json.dumps(envelope), "Content-Type": CONTENT_TYPE}, body=BODY,
    )
    assert SECRET not in json.dumps(decision.as_payload())
