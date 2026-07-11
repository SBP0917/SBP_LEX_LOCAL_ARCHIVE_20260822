from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sbp_lex.api.security_state_store as store_module
from sbp_lex.api.security_state_store import (
    MAX_RECORD_BYTES,
    SecurityStatePersistenceError,
    SecurityStateStore,
    resolve_security_state_path,
)
from sbp_lex.api.credential_lifecycle import CredentialRegistry, credential_from_record

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def make_store(tmp_path: Path) -> SecurityStateStore:
    root = tmp_path / "runtime_artifacts" / "api_security_state"
    return SecurityStateStore(root / "security_state.jsonl", allowed_root=root)


def initialized(tmp_path: Path) -> SecurityStateStore:
    store = make_store(tmp_path)
    assert store.validate_and_recover() == "NEW_STORE_INITIALIZED"
    return store


def restart(store: SecurityStateStore) -> SecurityStateStore:
    other = SecurityStateStore(store.path, allowed_root=store.path.parent)
    assert other.validate_and_recover() in {"VALID", "RECOVERED_INTERRUPTED_FINAL_WRITE"}
    return other


def credential_state(credential_id: str, status: str, **extra):
    return {
        "credential_id": credential_id,
        "principal_id": "principal-1",
        "principal_type": "operator",
        "credential_version": extra.pop("credential_version", 1),
        "allowed_scopes": ["observe"],
        "status": status,
        "rotation_group": "group-1",
        "replacement_credential_id": extra.pop("replacement_credential_id", None),
        "revoked_at": extra.pop("revoked_at", None),
        "revocation_reason": extra.pop("revocation_reason", None),
        "last_used_at": None,
        "overlap_expires_at": extra.pop("overlap_expires_at", None),
        **extra,
    }


def lifecycle_record(credential_id, principal_id, principal_type, *, version=1, scopes=None):
    return {
        "credential_id": credential_id, "principal_id": principal_id,
        "principal_type": principal_type, "credential_version": version,
        "credential_purpose": "desktop-v1-api", "allowed_scopes": list(scopes or ["observe"]),
        "issued_at": (NOW - timedelta(days=1)).isoformat(),
        "not_before": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=1)).isoformat(), "status": "ACTIVE",
        "rotation_group": f"group-{principal_id}", "replacement_credential_id": None,
        "revoked_at": None, "revocation_reason": None, "last_used_at": None,
        "device_id": f"device-{principal_id}", "secret": "test-secret-material-32-bytes",
    }


@pytest.mark.parametrize("status", ["REVOKED", "SUSPENDED", "RETIRED", "EXPIRED"])
def test_credential_security_states_survive_restart(tmp_path, status):
    store = initialized(tmp_path)
    state = credential_state("credential-1", status)
    store.append_lifecycle(
        action=status, credential_id="credential-1", principal_id="principal-1",
        credential_version=1, request_id=f"state-{status}", prior_state={"status": "ACTIVE"},
        new_state=state, reason="test", now=NOW,
    )
    recovered = restart(store)
    assert recovered.state()["credential_states"]["credential-1"]["status"] == status


def test_completed_rotation_and_old_retirement_survive_restart(tmp_path):
    store = initialized(tmp_path)
    source = credential_state(
        "credential-v1", "ROTATING", replacement_credential_id="credential-v2",
        overlap_expires_at=(NOW + timedelta(seconds=30)).isoformat(),
    )
    replacement = credential_state("credential-v2", "ACTIVE", credential_version=2)
    store.append_lifecycle(
        action="ROTATE", credential_id="credential-v1", principal_id="principal-1",
        credential_version=1, request_id="rotate-1", prior_state={"status": "ACTIVE"},
        new_state={"source": source, "replacement": replacement}, reason="rotation", now=NOW,
    )
    store.append_lifecycle(
        action="RETIRED", credential_id="credential-v1", principal_id="principal-1",
        credential_version=1, request_id="retire-1", prior_state=source,
        new_state=credential_state("credential-v1", "RETIRED", replacement_credential_id="credential-v2"),
        reason="overlap_expired", now=NOW + timedelta(seconds=30),
    )
    state = restart(store).state()["credential_states"]
    assert state["credential-v1"]["status"] == "RETIRED"
    assert state["credential-v2"]["status"] == "ACTIVE"


def test_nonce_and_request_id_replay_survive_restart(tmp_path):
    store = initialized(tmp_path)
    store.register_replay(
        credential_id="credential-1", request_id="request-1", nonce="nonce-1",
        expires_at=NOW + timedelta(seconds=60), now=NOW,
    )
    recovered = restart(store)
    with pytest.raises(SecurityStatePersistenceError, match="persistent_nonce_replay"):
        recovered.register_replay(
            credential_id="credential-1", request_id="request-2", nonce="nonce-1",
            expires_at=NOW + timedelta(seconds=60), now=NOW,
        )
    with pytest.raises(SecurityStatePersistenceError, match="persistent_request_id_replay"):
        recovered.register_replay(
            credential_id="credential-1", request_id="request-1", nonce="nonce-2",
            expires_at=NOW + timedelta(seconds=60), now=NOW,
        )


def test_replay_retention_cleanup_never_removes_live_state(tmp_path):
    store = initialized(tmp_path)
    store.register_replay(
        credential_id="credential-1", request_id="request-1", nonce="nonce-1",
        expires_at=NOW + timedelta(seconds=120), now=NOW,
    )
    assert restart(store).state()["request_ids"]["request-1"]
    expired = SecurityStateStore(store.path, allowed_root=store.path.parent)
    records = expired._read_records()
    state = store_module.reconstruct_security_state(records, NOW + timedelta(seconds=121))
    assert "request-1" not in state["request_ids"]


def test_recoverable_partial_final_write_is_classified_and_removed(tmp_path):
    store = initialized(tmp_path)
    store.append_event(event_type="CREDENTIAL_TEST", credential_id="c", new_state={"status": "ACTIVE"})
    with store.path.open("ab") as handle:
        handle.write(b'{"partial":')
        handle.flush()
    recovered = SecurityStateStore(store.path, allowed_root=store.path.parent)
    assert recovered.validate_and_recover() == "RECOVERED_INTERRUPTED_FINAL_WRITE"
    assert recovered.path.read_bytes().endswith(b"\n")


def test_truncated_checkpointed_final_record_fails_closed(tmp_path):
    store = initialized(tmp_path)
    store.append_event(event_type="CREDENTIAL_TEST", credential_id="c", new_state={"status": "ACTIVE"})
    data = store.path.read_bytes()
    store.path.write_bytes(data[:-10])
    with pytest.raises(SecurityStatePersistenceError):
        make_store(tmp_path).validate_and_recover()


def _mutate_record(store: SecurityStateStore, index: int, mutation):
    records = [json.loads(line) for line in store.path.read_text().splitlines()]
    mutation(records[index])
    store.path.write_text("\n".join(json.dumps(item, sort_keys=True, separators=(",", ":")) for item in records) + "\n")


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (lambda r: r.__setitem__("record_hash", "0" * 64), "security_state_record_hash_invalid"),
        (lambda r: r.__setitem__("previous_record_hash", "bad"), "security_state_previous_hash_invalid"),
        (lambda r: r.__setitem__("sequence", 99), "security_state_sequence_invalid"),
        (lambda r: r.__setitem__("integrity_signature", {}), "security_state_signature_invalid"),
    ],
)
def test_record_hash_link_sequence_and_signature_tamper(tmp_path, mutation, reason):
    store = initialized(tmp_path)
    store.append_event(event_type="CREDENTIAL_ONE", credential_id="c1")
    store.append_event(event_type="CREDENTIAL_TWO", credential_id="c2")
    _mutate_record(store, 1, mutation)
    with pytest.raises(SecurityStatePersistenceError, match=reason):
        make_store(tmp_path).validate_and_recover()


def test_corrupted_middle_missing_reordered_and_duplicate_records(tmp_path):
    store = initialized(tmp_path)
    for number in range(3):
        store.append_event(event_type="CREDENTIAL_TEST", credential_id=f"c{number}")
    original = store.path.read_bytes()
    lines = original.splitlines(keepends=True)
    variants = [
        lines[0] + b"{bad json}\n" + lines[2],
        lines[0] + lines[2],
        lines[1] + lines[0] + lines[2],
        lines[0] + lines[0] + lines[2],
    ]
    for data in variants:
        store.path.write_bytes(data)
        with pytest.raises(SecurityStatePersistenceError):
            make_store(tmp_path).validate_and_recover()
        store.path.write_bytes(original)


def test_missing_corrupt_stale_and_rollback_checkpoint(tmp_path):
    store = initialized(tmp_path)
    old_checkpoint = store.checkpoint_path.read_bytes()
    old_anchor = store.anchor_path.read_bytes()
    store.append_event(event_type="CREDENTIAL_TEST", credential_id="c")
    current_checkpoint = store.checkpoint_path.read_bytes()
    store.checkpoint_path.unlink()
    with pytest.raises(SecurityStatePersistenceError, match="ambiguous_missing_component"):
        make_store(tmp_path).validate_and_recover()
    store.checkpoint_path.write_bytes(b"{bad}")
    with pytest.raises(SecurityStatePersistenceError, match="checkpoint_corrupted"):
        make_store(tmp_path).validate_and_recover()
    store.checkpoint_path.write_bytes(old_checkpoint)
    with pytest.raises(SecurityStatePersistenceError, match="checkpoint_stale_or_rollback"):
        make_store(tmp_path).validate_and_recover()
    store.checkpoint_path.write_bytes(current_checkpoint)
    store.anchor_path.write_bytes(old_anchor)
    with pytest.raises(SecurityStatePersistenceError, match="rollback_detected"):
        make_store(tmp_path).validate_and_recover()


def test_ledger_rollback_detected_by_current_checkpoint(tmp_path):
    store = initialized(tmp_path)
    empty_ledger = store.path.read_bytes()
    store.append_event(event_type="CREDENTIAL_TEST", credential_id="c")
    store.path.write_bytes(empty_ledger)
    with pytest.raises(SecurityStatePersistenceError, match="checkpoint_stale_or_rollback"):
        make_store(tmp_path).validate_and_recover()


def test_concurrent_nonce_and_request_registration_allows_one(tmp_path):
    store = initialized(tmp_path)
    results = []
    barrier = threading.Barrier(4)

    def worker():
        barrier.wait()
        try:
            store.register_replay(
                credential_id="c", request_id="request", nonce="nonce",
                expires_at=NOW + timedelta(seconds=60), now=NOW,
            )
            results.append("accepted")
        except SecurityStatePersistenceError as exc:
            results.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("accepted") == 1
    assert len(results) == 4


def test_second_authoritative_writer_denied(tmp_path):
    first = initialized(tmp_path)
    first.acquire_authoritative_writer()
    second = make_store(tmp_path)
    with pytest.raises(SecurityStatePersistenceError, match="second_writer_denied"):
        second.acquire_authoritative_writer()
    first.close()


def test_rotation_revocation_race_is_serialized_and_persisted(tmp_path, monkeypatch):
    store = initialized(tmp_path)
    monkeypatch.setattr(store_module, "_ACTIVE_STORE", store)
    admin = credential_from_record(lifecycle_record("admin", "admin", "administrator"))
    target = credential_from_record(
        lifecycle_record(
            "target-v1", "target", "operator",
            scopes=["observe", "runtime:traverse"],
        )
    )
    replacement = credential_from_record(
        lifecycle_record("target-v2", "target", "operator", version=2)
    )
    registry = CredentialRegistry({"admin": admin, "target-v1": target})
    results = []
    barrier = threading.Barrier(2)

    def rotate():
        barrier.wait()
        try:
            registry.rotate(
                "target-v1", replacement, actor_id="admin",
                request_id="race-rotate", now=NOW, overlap_seconds=30,
            )
            results.append("rotated")
        except Exception as exc:
            results.append(str(exc))

    def revoke():
        barrier.wait()
        try:
            registry.revoke(
                "target-v1", actor_id="admin", request_id="race-revoke",
                now=NOW, reason="emergency",
            )
            results.append("revoked")
        except Exception as exc:
            results.append(str(exc))

    threads = [threading.Thread(target=rotate), threading.Thread(target=revoke)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len([item for item in results if item in {"rotated", "revoked"}]) == 1
    recovered = restart(store).state()["credential_states"]["target-v1"]
    assert recovered["status"] in {"ROTATING", "REVOKED"}


def test_path_boundaries_and_extension(tmp_path):
    root = tmp_path / "approved"
    root.mkdir()
    with pytest.raises(SecurityStatePersistenceError, match="outside_approved_root"):
        resolve_security_state_path(tmp_path / "outside.jsonl", allowed_root=root)
    with pytest.raises(SecurityStatePersistenceError, match="extension_denied"):
        resolve_security_state_path(root / "state.txt", allowed_root=root)
    with pytest.raises(SecurityStatePersistenceError, match="outside_approved_root"):
        resolve_security_state_path(root / ".." / "escape.jsonl", allowed_root=root)


def test_oversized_record_and_store_hard_limit(tmp_path, monkeypatch):
    store = initialized(tmp_path)
    with pytest.raises(SecurityStatePersistenceError, match="record_oversized"):
        store.append_event(event_type="CREDENTIAL_TEST", reason="x" * MAX_RECORD_BYTES)
    monkeypatch.setattr(store_module, "MAX_STORE_BYTES", 100)
    with pytest.raises(SecurityStatePersistenceError, match="store_hard_limit"):
        store.append_event(event_type="CREDENTIAL_TEST", reason="bounded")


def test_disk_full_failure_does_not_advance_memory_state(tmp_path, monkeypatch):
    store = initialized(tmp_path)
    before = store.state()

    def fail_write(path, data):
        raise SecurityStatePersistenceError("security_state_atomic_write_failed")

    monkeypatch.setattr(store, "_atomic_write", fail_write)
    with pytest.raises(SecurityStatePersistenceError, match="atomic_write_failed"):
        store.append_event(event_type="CREDENTIAL_TEST", credential_id="c")
    assert store.state() == before


def test_process_crash_after_event_append_rolls_forward_with_intent(tmp_path, monkeypatch):
    store = initialized(tmp_path)

    def crash():
        raise SecurityStatePersistenceError("simulated_crash_after_event_append")

    monkeypatch.setattr(store, "_write_checkpoint_and_anchor", crash)
    with pytest.raises(SecurityStatePersistenceError, match="simulated_crash"):
        store.append_event(event_type="CREDENTIAL_TEST", credential_id="c", new_state={"status": "REVOKED"})
    recovered = make_store(tmp_path)
    assert recovered.validate_and_recover() == "RECOVERED_EVENT_APPEND_BEFORE_CHECKPOINT"
    assert recovered.state()["credential_states"]["c"]["status"] == "REVOKED"


def test_process_crash_before_anchor_replacement_rolls_forward(tmp_path, monkeypatch):
    store = initialized(tmp_path)
    original = store._atomic_write

    def crash_on_anchor(path, data):
        if path == store.anchor_path:
            raise SecurityStatePersistenceError("simulated_crash_before_anchor")
        return original(path, data)

    monkeypatch.setattr(store, "_atomic_write", crash_on_anchor)
    with pytest.raises(SecurityStatePersistenceError, match="simulated_crash"):
        store.append_event(event_type="CREDENTIAL_TEST", credential_id="c", new_state={"status": "SUSPENDED"})
    recovered = make_store(tmp_path)
    assert recovered.validate_and_recover() == "RECOVERED_CHECKPOINT_BEFORE_ANCHOR"
    assert recovered.state()["credential_states"]["c"]["status"] == "SUSPENDED"


def test_persisted_records_and_exports_contain_no_secrets(tmp_path):
    store = initialized(tmp_path)
    secret = "raw-super-secret-credential-material"
    store.append_lifecycle(
        action="REVOKED", credential_id="credential-safe", principal_id="principal-safe",
        credential_version=1, request_id="revoke-safe", prior_state={"status": "ACTIVE"},
        new_state={"status": "REVOKED"}, reason="compromise", now=NOW,
    )
    combined = store.path.read_text() + store.checkpoint_path.read_text() + store.anchor_path.read_text()
    assert secret not in combined
    assert "nonce-raw" not in combined


def test_startup_validation_blocks_listener_on_invalid_store(tmp_path, monkeypatch):
    store = initialized(tmp_path)
    store.append_event(event_type="CREDENTIAL_TEST", credential_id="c")
    store.checkpoint_path.write_text("{corrupt}")
    bound = False
    try:
        make_store(tmp_path).validate_and_recover()
        bound = True
    except SecurityStatePersistenceError:
        pass
    assert bound is False
