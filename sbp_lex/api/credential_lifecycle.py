from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sbp_lex.api.schema_validation import loads_strict_json

CREDENTIAL_STATES = frozenset({"PENDING", "ACTIVE", "ROTATING", "EXPIRED", "REVOKED", "SUSPENDED", "RETIRED"})
PRINCIPAL_TYPES = frozenset(
    {"viewer", "operator", "validator", "connector", "replay_examiner", "administrator", "maintenance"}
)
MAX_ROTATION_OVERLAP_SECONDS = 300
MAX_CREDENTIAL_VERSION = 1_000_000
REQUIRED_FIELDS = frozenset({
    "credential_id", "principal_id", "principal_type", "credential_version",
    "credential_purpose", "allowed_scopes", "issued_at", "not_before", "expires_at",
    "status", "rotation_group", "replacement_credential_id", "revoked_at",
    "revocation_reason", "last_used_at", "device_id", "secret",
})


def parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


@dataclass(frozen=True)
class Credential:
    credential_id: str
    principal_id: str
    principal_type: str
    credential_version: int
    credential_purpose: str
    allowed_scopes: frozenset[str]
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    status: str
    rotation_group: str
    replacement_credential_id: str | None
    revoked_at: datetime | None
    revocation_reason: str | None
    last_used_at: datetime | None
    device_id: str
    secret: str
    overlap_expires_at: datetime | None = None


@dataclass(frozen=True)
class LifecycleEvent:
    sequence: int
    request_id: str
    action: str
    credential_id: str
    actor_principal_id: str
    occurred_at: str
    previous_status: str | None
    new_status: str
    event_digest: str


class CredentialLifecycleError(ValueError):
    pass


class CredentialRegistry:
    def __init__(self, credentials: Mapping[str, Credential]):
        self._lock = threading.RLock()
        self._credentials = dict(credentials)
        self._events: tuple[LifecycleEvent, ...] = ()
        self._transition_requests: set[str] = set()

    def get(self, credential_id: str) -> Credential | None:
        with self._lock:
            return self._credentials.get(credential_id)

    def snapshot(self) -> dict[str, Credential]:
        with self._lock:
            return dict(self._credentials)

    def events(self) -> tuple[LifecycleEvent, ...]:
        with self._lock:
            return self._events

    def public_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "credential_id": item.credential_id,
                    "principal_id": item.principal_id,
                    "principal_type": item.principal_type,
                    "credential_version": item.credential_version,
                    "credential_purpose": item.credential_purpose,
                    "allowed_scopes": sorted(item.allowed_scopes),
                    "issued_at": item.issued_at.isoformat(),
                    "not_before": item.not_before.isoformat(),
                    "expires_at": item.expires_at.isoformat(),
                    "status": item.status,
                    "rotation_group": item.rotation_group,
                    "replacement_credential_id": item.replacement_credential_id,
                    "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None,
                    "revocation_reason": item.revocation_reason,
                    "last_used_at": item.last_used_at.isoformat() if item.last_used_at else None,
                    "device_id": item.device_id,
                }
                for item in sorted(self._credentials.values(), key=lambda value: value.credential_id)
            ]

    def _authorize_transition(self, actor: Credential, target: Credential, action: str, now: datetime) -> None:
        if not self.can_authenticate(actor, now):
            raise CredentialLifecycleError("transition_actor_not_active")
        if actor.principal_type != "administrator":
            raise CredentialLifecycleError("transition_administrator_required")
        if actor.principal_id == target.principal_id and action in {"ROTATE", "REVOKE", "SUSPEND"}:
            raise CredentialLifecycleError("credential_self_transition_denied")

    def _record(
        self, *, request_id: str, action: str, previous: Credential | None,
        current: Credential, actor: Credential, now: datetime,
        persisted_new_state: Any = None,
    ) -> None:
        if not request_id or request_id in self._transition_requests:
            raise CredentialLifecycleError("lifecycle_request_replayed")
        payload = {
            "sequence": len(self._events) + 1, "request_id": request_id, "action": action,
            "credential_id": current.credential_id, "actor_principal_id": actor.principal_id,
            "occurred_at": now.isoformat(), "previous_status": previous.status if previous else None,
            "new_status": current.status,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        from sbp_lex.api.security_state_store import active_security_state_store
        store = active_security_state_store()
        if store is not None:
            store.append_lifecycle(
                action=action, credential_id=current.credential_id,
                principal_id=current.principal_id,
                credential_version=current.credential_version,
                request_id=request_id,
                prior_state=_safe_credential_state(previous) if previous else None,
                new_state=(
                    persisted_new_state
                    if persisted_new_state is not None
                    else _safe_credential_state(current)
                ),
                reason=action.lower(), now=now,
            )
        self._transition_requests.add(request_id)
        self._events = (*self._events, LifecycleEvent(**payload, event_digest=digest))

    def _assert_new_request(self, request_id: str) -> None:
        if not request_id or request_id in self._transition_requests:
            raise CredentialLifecycleError("lifecycle_request_replayed")

    def can_authenticate(self, credential: Credential, now: datetime) -> bool:
        if now < credential.not_before or now >= credential.expires_at:
            return False
        if credential.status == "ACTIVE":
            return True
        if credential.status != "ROTATING" or credential.overlap_expires_at is None or now >= credential.overlap_expires_at:
            return False
        replacement = self._credentials.get(credential.replacement_credential_id or "")
        return bool(
            replacement
            and replacement.status == "ACTIVE"
            and replacement.principal_type == credential.principal_type
            and replacement.allowed_scopes <= credential.allowed_scopes
            and replacement.credential_version > credential.credential_version
        )

    def mark_used(self, credential_id: str, now: datetime) -> None:
        with self._lock:
            credential = self._credentials.get(credential_id)
            if credential is not None and self.can_authenticate(credential, now):
                current = replace(credential, last_used_at=now)
                from sbp_lex.api.security_state_store import active_security_state_store
                store = active_security_state_store()
                if store is not None:
                    store.append_lifecycle(
                        action="USED", credential_id=current.credential_id,
                        principal_id=current.principal_id,
                        credential_version=current.credential_version,
                        request_id=f"use-{uuid.uuid4()}",
                        prior_state=_safe_credential_state(credential),
                        new_state=_safe_credential_state(current),
                        reason="authenticated_use", now=now,
                    )
                self._credentials[credential_id] = current

    def activate(self, credential_id: str, *, actor_id: str, request_id: str, now: datetime) -> Credential:
        with self._lock:
            self._assert_new_request(request_id)
            target = self._require(credential_id)
            actor = self._require(actor_id)
            self._authorize_transition(actor, target, "ACTIVATE", now)
            if target.status != "PENDING" or now < target.not_before:
                raise CredentialLifecycleError("credential_activation_not_allowed")
            current = replace(target, status="ACTIVE")
            self._record(request_id=request_id, action="ACTIVATE", previous=target, current=current, actor=actor, now=now)
            self._credentials[credential_id] = current
            return current

    def rotate(
        self, credential_id: str, replacement: Credential, *, actor_id: str,
        request_id: str, now: datetime, overlap_seconds: int,
    ) -> tuple[Credential, Credential]:
        with self._lock:
            self._assert_new_request(request_id)
            target = self._require(credential_id)
            actor = self._require(actor_id)
            self._authorize_transition(actor, target, "ROTATE", now)
            if target.status != "ACTIVE":
                raise CredentialLifecycleError("rotation_source_not_active")
            if replacement.credential_id in self._credentials:
                raise CredentialLifecycleError("replacement_credential_exists")
            if replacement.status != "ACTIVE" or replacement.not_before > now or replacement.expires_at <= now:
                raise CredentialLifecycleError("replacement_not_active")
            if replacement.principal_id != target.principal_id or replacement.principal_type != target.principal_type:
                raise CredentialLifecycleError("replacement_principal_mutation_denied")
            if replacement.rotation_group != target.rotation_group:
                raise CredentialLifecycleError("replacement_rotation_group_mismatch")
            if replacement.allowed_scopes > target.allowed_scopes:
                raise CredentialLifecycleError("replacement_scope_broadening_denied")
            if replacement.credential_version <= target.credential_version:
                raise CredentialLifecycleError("credential_version_downgrade_denied")
            if not 1 <= overlap_seconds <= MAX_ROTATION_OVERLAP_SECONDS:
                raise CredentialLifecycleError("rotation_overlap_out_of_bounds")
            rotating = replace(
                target, status="ROTATING", replacement_credential_id=replacement.credential_id,
                overlap_expires_at=now + timedelta(seconds=overlap_seconds),
            )
            self._record(
                request_id=request_id, action="ROTATE", previous=target,
                current=rotating, actor=actor, now=now,
                persisted_new_state={
                    "source": _safe_credential_state(rotating),
                    "replacement": _safe_credential_state(replacement),
                },
            )
            self._credentials[replacement.credential_id] = replacement
            self._credentials[credential_id] = rotating
            return rotating, replacement

    def retire_expired_overlaps(self, now: datetime) -> list[str]:
        retired: list[str] = []
        with self._lock:
            for credential_id, credential in list(self._credentials.items()):
                if credential.status == "ROTATING" and credential.overlap_expires_at and now >= credential.overlap_expires_at:
                    current = replace(credential, status="RETIRED")
                    from sbp_lex.api.security_state_store import active_security_state_store
                    store = active_security_state_store()
                    if store is not None:
                        store.append_lifecycle(
                            action="RETIRED", credential_id=current.credential_id,
                            principal_id=current.principal_id,
                            credential_version=current.credential_version,
                            request_id=f"retire-{credential_id}-{int(now.timestamp())}",
                            prior_state=_safe_credential_state(credential),
                            new_state=_safe_credential_state(current),
                            reason="rotation_overlap_expired", now=now,
                        )
                    self._credentials[credential_id] = current
                    retired.append(credential_id)
        return sorted(retired)

    def revoke(
        self, credential_id: str, *, actor_id: str, request_id: str,
        now: datetime, reason: str,
    ) -> Credential:
        with self._lock:
            self._assert_new_request(request_id)
            target = self._require(credential_id)
            actor = self._require(actor_id)
            self._authorize_transition(actor, target, "REVOKE", now)
            if target.status in {"REVOKED", "RETIRED"}:
                raise CredentialLifecycleError("credential_cannot_be_revoked")
            current = replace(
                target, status="REVOKED", revoked_at=now,
                revocation_reason=reason or "unspecified", overlap_expires_at=None,
            )
            self._record(request_id=request_id, action="REVOKE", previous=target, current=current, actor=actor, now=now)
            self._credentials[credential_id] = current
            return current

    def _require(self, credential_id: str) -> Credential:
        credential = self._credentials.get(credential_id)
        if credential is None:
            raise CredentialLifecycleError("unknown_credential")
        return credential


def credential_from_record(record: Mapping[str, Any]) -> Credential:
    if set(record) != REQUIRED_FIELDS:
        raise CredentialLifecycleError("credential_schema_invalid")
    times = {key: parse_time(record.get(key)) for key in ("issued_at", "not_before", "expires_at")}
    optional_times = {key: parse_time(record.get(key)) for key in ("revoked_at", "last_used_at")}
    if any(value is None for value in times.values()):
        raise CredentialLifecycleError("credential_time_invalid")
    version = record.get("credential_version")
    scopes = record.get("allowed_scopes")
    if (
        not isinstance(version, int) or isinstance(version, bool)
        or not 1 <= version <= MAX_CREDENTIAL_VERSION
    ):
        raise CredentialLifecycleError("credential_version_unknown")
    if (
        record.get("status") not in CREDENTIAL_STATES
        or record.get("principal_type") not in PRINCIPAL_TYPES
        or not isinstance(scopes, list) or not scopes or not all(isinstance(scope, str) for scope in scopes)
        or len(scopes) != len(set(scopes))
        or not all(isinstance(record.get(key), str) and record.get(key) for key in (
            "credential_id", "principal_id", "principal_type", "credential_purpose",
            "rotation_group", "device_id", "secret",
        ))
    ):
        raise CredentialLifecycleError("credential_schema_invalid")
    if (
        (record["replacement_credential_id"] is not None and (
            not isinstance(record["replacement_credential_id"], str) or not record["replacement_credential_id"]
        ))
        or (record["revocation_reason"] is not None and not isinstance(record["revocation_reason"], str))
        or any(record[key] is not None and optional_times[key] is None for key in optional_times)
    ):
        raise CredentialLifecycleError("credential_schema_invalid")
    if record["secret"] in record["credential_id"]:
        raise CredentialLifecycleError("credential_identifier_contains_secret_material")
    if times["issued_at"] > times["not_before"] or times["not_before"] >= times["expires_at"]:
        raise CredentialLifecycleError("credential_time_order_invalid")
    if record["status"] == "REVOKED" and optional_times["revoked_at"] is None:
        raise CredentialLifecycleError("revocation_metadata_required")
    return Credential(
        credential_id=record["credential_id"], principal_id=record["principal_id"],
        principal_type=record["principal_type"], credential_version=version,
        credential_purpose=record["credential_purpose"], allowed_scopes=frozenset(scopes),
        issued_at=times["issued_at"], not_before=times["not_before"], expires_at=times["expires_at"],
        status=record["status"], rotation_group=record["rotation_group"],
        replacement_credential_id=record["replacement_credential_id"],
        revoked_at=optional_times["revoked_at"], revocation_reason=record["revocation_reason"],
        last_used_at=optional_times["last_used_at"], device_id=record["device_id"], secret=record["secret"],
    )


def _safe_credential_state(credential: Credential) -> dict[str, Any]:
    return {
        "credential_id": credential.credential_id,
        "principal_id": credential.principal_id,
        "principal_type": credential.principal_type,
        "credential_version": credential.credential_version,
        "allowed_scopes": sorted(credential.allowed_scopes),
        "status": credential.status,
        "rotation_group": credential.rotation_group,
        "replacement_credential_id": credential.replacement_credential_id,
        "revoked_at": credential.revoked_at.isoformat() if credential.revoked_at else None,
        "revocation_reason": credential.revocation_reason,
        "last_used_at": credential.last_used_at.isoformat() if credential.last_used_at else None,
        "overlap_expires_at": credential.overlap_expires_at.isoformat() if credential.overlap_expires_at else None,
    }


_REGISTRY_LOCK = threading.Lock()
_REGISTRY_SOURCE = ""
_REGISTRY = CredentialRegistry({})


def reset_registry_for_tests() -> None:
    global _REGISTRY_SOURCE, _REGISTRY
    with _REGISTRY_LOCK:
        _REGISTRY_SOURCE = "\0"
        _REGISTRY = CredentialRegistry({})


def configured_registry() -> CredentialRegistry:
    global _REGISTRY_SOURCE, _REGISTRY
    raw = os.environ.get("SBP_LEX_API_PRINCIPALS", "")
    with _REGISTRY_LOCK:
        if raw == _REGISTRY_SOURCE:
            return _REGISTRY
        credentials: dict[str, Credential] = {}
        try:
            records = loads_strict_json(raw) if raw else []
            if not isinstance(records, list):
                raise CredentialLifecycleError("credential_registry_not_list")
            for record in records:
                if not isinstance(record, Mapping):
                    raise CredentialLifecycleError("credential_schema_invalid")
                credential = credential_from_record(record)
                if credential.credential_id in credentials:
                    raise CredentialLifecycleError("duplicate_credential_id")
                credentials[credential.credential_id] = credential
            from sbp_lex.api.security_state_store import active_security_state_store
            store = active_security_state_store()
            if store is not None:
                persisted = store.state().get("credential_states", {})
                for credential_id, state in persisted.items():
                    if credential_id not in credentials or not isinstance(state, Mapping):
                        continue
                    current = credentials[credential_id]
                    credentials[credential_id] = replace(
                        current,
                        status=str(state.get("status", current.status)),
                        replacement_credential_id=state.get(
                            "replacement_credential_id", current.replacement_credential_id
                        ),
                        revoked_at=parse_time(state.get("revoked_at")) or current.revoked_at,
                        revocation_reason=state.get("revocation_reason", current.revocation_reason),
                        last_used_at=parse_time(state.get("last_used_at")) or current.last_used_at,
                        overlap_expires_at=parse_time(state.get("overlap_expires_at")),
                    )
        except Exception:
            credentials = {}
        _REGISTRY_SOURCE = raw
        _REGISTRY = CredentialRegistry(credentials)
        return _REGISTRY
