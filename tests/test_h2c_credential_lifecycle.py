from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from sbp_lex.api.credential_lifecycle import (
    CredentialLifecycleError,
    configured_registry,
    credential_from_record,
    reset_registry_for_tests,
)
from sbp_lex.api.request_auth import (
    Principal,
    authenticate_signed_request,
    build_signed_envelope,
    reset_replay_cache_for_tests,
)

NOW = datetime(2026, 7, 11, 6, 0, tzinfo=timezone.utc)
SECRET = "credential-lifecycle-test-secret-32"
BODY = b'{"request":{"action":"inspect"}}'


def record(
    credential_id: str,
    principal_id: str,
    principal_type: str,
    *,
    status: str = "ACTIVE",
    version: int = 1,
    scopes=None,
    not_before=None,
    expires_at=None,
    rotation_group=None,
    secret=None,
):
    revoked = status == "REVOKED"
    return {
        "credential_id": credential_id,
        "principal_id": principal_id,
        "principal_type": principal_type,
        "credential_version": version,
        "credential_purpose": "desktop-v1-api",
        "allowed_scopes": list(scopes or ["observe"]),
        "issued_at": (NOW - timedelta(days=1)).isoformat(),
        "not_before": (not_before or NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (expires_at or NOW + timedelta(days=1)).isoformat(),
        "status": status,
        "rotation_group": rotation_group or f"group-{principal_id}",
        "replacement_credential_id": None,
        "revoked_at": (NOW - timedelta(seconds=1)).isoformat() if revoked else None,
        "revocation_reason": "compromise" if revoked else None,
        "last_used_at": None,
        "device_id": f"device-{principal_id}",
        "secret": secret or SECRET,
    }


def install(monkeypatch, *records):
    monkeypatch.setenv("SBP_LEX_API_PRINCIPALS", json.dumps(records))
    reset_registry_for_tests()
    reset_replay_cache_for_tests()
    return configured_registry()


def principal(item):
    return Principal(
        credential_id=item.credential_id,
        principal_id=item.principal_id,
        principal_type=item.principal_type,
        device_id=item.device_id,
        scopes=item.allowed_scopes,
        secret=item.secret,
        expires_at=item.expires_at,
        revoked=item.status == "REVOKED",
        credential_version=item.credential_version,
        status=item.status,
    )


def envelope(item, request_id="request-1", nonce="nonce-1", now=NOW):
    return build_signed_envelope(
        principal=principal(item), method="GET", path="/runtime/status",
        content_type="", body=b"{}", request_id=request_id, nonce=nonce,
        issued_at=now, expires_at=now + timedelta(seconds=60),
    )


def authenticate(item, auth_envelope, now=NOW):
    return authenticate_signed_request(
        method="GET", path="/runtime/status", content_type="", body=b"{}",
        envelope_text=json.dumps(auth_envelope), security_mode="private", now=now,
    )


def base_records(target_status="ACTIVE", **target_overrides):
    return (
        record("admin-credential", "admin-principal", "administrator", scopes=["observe"]),
        record(
            "operator-credential", "operator-principal", "operator",
            status=target_status, scopes=["observe", "runtime:traverse"], **target_overrides,
        ),
    )


def test_valid_active_credential_and_last_used(monkeypatch):
    registry = install(monkeypatch, *base_records())
    item = registry.get("operator-credential")
    assert authenticate(item, envelope(item)).allowed
    assert registry.get("operator-credential").last_used_at == NOW


def test_pending_before_not_before_then_activated(monkeypatch):
    registry = install(
        monkeypatch,
        record("admin-credential", "admin-principal", "administrator"),
        record(
            "operator-credential", "operator-principal", "operator", status="PENDING",
            not_before=NOW + timedelta(seconds=30),
        ),
    )
    item = registry.get("operator-credential")
    assert authenticate(item, envelope(item)).reason == "credential_not_yet_active"
    activated = registry.activate(
        "operator-credential", actor_id="admin-credential",
        request_id="activate-1", now=NOW + timedelta(seconds=31),
    )
    auth = envelope(activated, now=NOW + timedelta(seconds=31))
    assert authenticate(activated, auth, now=NOW + timedelta(seconds=31)).allowed


@pytest.mark.parametrize(
    "status,reason",
    [
        ("REVOKED", "credential_revoked"),
        ("SUSPENDED", "credential_status_denied:suspended"),
        ("RETIRED", "credential_status_denied:retired"),
        ("EXPIRED", "credential_expired"),
    ],
)
def test_non_active_states_denied(monkeypatch, status, reason):
    expiry = NOW - timedelta(seconds=1) if status == "EXPIRED" else NOW + timedelta(days=1)
    registry = install(monkeypatch, *base_records(status, expires_at=expiry))
    item = registry.get("operator-credential")
    assert authenticate(item, envelope(item)).reason == reason


def test_bounded_rotation_overlap_and_retirement(monkeypatch):
    registry = install(monkeypatch, *base_records())
    replacement = credential_from_record(
        record(
            "operator-v2", "operator-principal", "operator", version=2,
            scopes=["observe"], rotation_group="group-operator-principal",
        )
    )
    old, new = registry.rotate(
        "operator-credential", replacement, actor_id="admin-credential",
        request_id="rotation-1", now=NOW, overlap_seconds=30,
    )
    assert old.status == "ROTATING"
    assert registry.can_authenticate(old, NOW + timedelta(seconds=29))
    assert registry.can_authenticate(new, NOW + timedelta(seconds=29))
    assert not registry.can_authenticate(old, NOW + timedelta(seconds=30))
    assert registry.retire_expired_overlaps(NOW + timedelta(seconds=30)) == ["operator-credential"]
    assert registry.get("operator-credential").status == "RETIRED"


@pytest.mark.parametrize(
    "replacement,reason",
    [
        (
            record(
                "operator-v2", "operator-principal", "operator", version=2,
                scopes=["observe", "runtime:traverse", "runtime:replay"],
                rotation_group="group-operator-principal",
            ),
            "replacement_scope_broadening_denied",
        ),
        (
            record(
                "operator-v2", "operator-principal", "viewer", version=2,
                scopes=["observe"], rotation_group="group-operator-principal",
            ),
            "replacement_principal_mutation_denied",
        ),
        (
            record(
                "operator-v2", "operator-principal", "operator", version=1,
                scopes=["observe"], rotation_group="group-operator-principal",
            ),
            "credential_version_downgrade_denied",
        ),
    ],
)
def test_rotation_cannot_broaden_mutate_or_downgrade(monkeypatch, replacement, reason):
    registry = install(monkeypatch, *base_records())
    with pytest.raises(CredentialLifecycleError, match=reason):
        registry.rotate(
            "operator-credential", credential_from_record(replacement),
            actor_id="admin-credential", request_id="rotation-denied",
            now=NOW, overlap_seconds=30,
        )
    assert registry.get("operator-credential").status == "ACTIVE"


def test_rotation_replay_and_duplicate_replacement_denied(monkeypatch):
    registry = install(monkeypatch, *base_records())
    replacement = credential_from_record(
        record(
            "operator-v2", "operator-principal", "operator", version=2,
            scopes=["observe"], rotation_group="group-operator-principal",
        )
    )
    registry.rotate(
        "operator-credential", replacement, actor_id="admin-credential",
        request_id="rotation-replay", now=NOW, overlap_seconds=30,
    )
    with pytest.raises(CredentialLifecycleError, match="lifecycle_request_replayed"):
        registry.rotate(
            "operator-credential", replacement, actor_id="admin-credential",
            request_id="rotation-replay", now=NOW, overlap_seconds=30,
        )


def test_emergency_revocation_invalidates_outstanding_envelope(monkeypatch):
    registry = install(monkeypatch, *base_records())
    item = registry.get("operator-credential")
    outstanding = envelope(item)
    revoked = registry.revoke(
        "operator-credential", actor_id="admin-credential",
        request_id="revoke-1", now=NOW, reason="compromise",
    )
    assert revoked.status == "REVOKED"
    assert authenticate(item, outstanding).reason == "credential_revoked"


def test_revocation_replay_and_self_revocation_denied(monkeypatch):
    registry = install(monkeypatch, *base_records())
    registry.revoke(
        "operator-credential", actor_id="admin-credential",
        request_id="revoke-replay", now=NOW, reason="compromise",
    )
    with pytest.raises(CredentialLifecycleError, match="lifecycle_request_replayed"):
        registry.revoke(
            "operator-credential", actor_id="admin-credential",
            request_id="revoke-replay", now=NOW, reason="again",
        )

    registry = install(monkeypatch, record("self-admin", "same", "administrator"))
    with pytest.raises(CredentialLifecycleError, match="credential_self_transition_denied"):
        registry.revoke(
            "self-admin", actor_id="self-admin", request_id="self-revoke",
            now=NOW, reason="not allowed",
        )


def test_non_administrator_cannot_self_escalate(monkeypatch):
    registry = install(monkeypatch, *base_records())
    replacement = credential_from_record(
        record(
            "operator-v2", "operator-principal", "operator", version=2,
            scopes=["observe"], rotation_group="group-operator-principal",
        )
    )
    with pytest.raises(CredentialLifecycleError, match="transition_administrator_required"):
        registry.rotate(
            "operator-credential", replacement, actor_id="operator-credential",
            request_id="self-escalate", now=NOW, overlap_seconds=30,
        )


@pytest.mark.parametrize("version", [0, -1, "future", 1_000_001])
def test_unknown_credential_version_fails_closed(monkeypatch, version):
    bad = record("operator-credential", "operator-principal", "operator")
    bad["credential_version"] = version
    registry = install(monkeypatch, bad)
    assert registry.snapshot() == {}


@pytest.mark.parametrize("status", ["REVOKED", "EXPIRED", "SUSPENDED", "RETIRED"])
def test_non_pending_credentials_cannot_be_silently_reactivated(monkeypatch, status):
    expiry = NOW - timedelta(seconds=1) if status == "EXPIRED" else NOW + timedelta(days=1)
    registry = install(monkeypatch, *base_records(status, expires_at=expiry))
    with pytest.raises(CredentialLifecycleError, match="credential_activation_not_allowed"):
        registry.activate(
            "operator-credential", actor_id="admin-credential",
            request_id=f"reactivate-{status}", now=NOW,
        )


def test_credential_identifier_cannot_contain_secret_material():
    bad = record(SECRET + "-identifier", "operator", "operator")
    with pytest.raises(CredentialLifecycleError, match="credential_identifier_contains_secret_material"):
        credential_from_record(bad)


def test_lifecycle_events_immutable_and_secrets_not_exported(monkeypatch):
    registry = install(monkeypatch, *base_records())
    registry.revoke(
        "operator-credential", actor_id="admin-credential",
        request_id="revoke-audit", now=NOW, reason="compromise",
    )
    event = registry.events()[0]
    with pytest.raises(FrozenInstanceError):
        event.new_status = "ACTIVE"
    exported = json.dumps(registry.public_snapshot()) + repr(registry.events())
    assert SECRET not in exported


def test_administrator_viewer_and_maintenance_boundaries_preserved(monkeypatch):
    registry = install(
        monkeypatch,
        record("admin", "admin", "administrator", scopes=["observe", "runtime:traverse"]),
        record("viewer", "viewer", "viewer", scopes=["observe"]),
        record("maintenance", "maintenance", "maintenance", scopes=["observe"]),
    )
    assert "execution:authorize" not in registry.get("admin").allowed_scopes
    assert "runtime:traverse" not in registry.get("viewer").allowed_scopes
    from sbp_lex.api.request_auth import principal_authorized
    assert principal_authorized("maintenance", "observe", runtime_execution_active=False)
    assert not principal_authorized("maintenance", "observe", runtime_execution_active=True)
