from __future__ import annotations

import json
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator, Mapping

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
APPROVED_ROOT = (REPOSITORY_ROOT / "runtime_artifacts" / "api_security_state").resolve()
DEFAULT_PATH = APPROVED_ROOT / "security_state.jsonl"
RECORD_VERSION = "H4A_SECURITY_STATE_RECORD_V1"
DOMAIN = "SBP_LEX_DESKTOP_V1_API_SECURITY_STATE"
MAX_RECORD_BYTES = 65_536
MAX_STORE_BYTES = 8_388_608
STORE_WARNING_BYTES = 6_291_456
MAX_REPLAY_RETENTION_SECONDS = 300
ALLOWED_SUFFIX = ".jsonl"
RECORD_FIELDS = frozenset({
    "record_version", "sequence", "event_id", "event_type", "credential_id",
    "principal_id", "request_id", "nonce_digest", "credential_version",
    "prior_state", "new_state", "reason", "issued_at", "effective_at",
    "previous_record_hash", "record_hash", "integrity_signature",
    "runtime_instance_id", "retention_expires_at", "integrity_domain",
})


class SecurityStatePersistenceError(RuntimeError):
    pass


def _now_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def resolve_security_state_path(path: Path, *, allowed_root: Path = APPROVED_ROOT) -> Path:
    root = allowed_root.resolve()
    if root.exists() and root.is_symlink():
        raise SecurityStatePersistenceError("security_state_root_reparse_point_denied")
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    candidate = candidate.resolve(strict=False)
    if not candidate.is_relative_to(root):
        raise SecurityStatePersistenceError("security_state_path_outside_approved_root")
    if candidate.suffix.lower() != ALLOWED_SUFFIX:
        raise SecurityStatePersistenceError("security_state_extension_denied")
    parent = candidate.parent
    while parent != root.parent:
        if parent.exists() and parent.is_symlink():
            raise SecurityStatePersistenceError("security_state_reparse_point_denied")
        if parent == root:
            break
        parent = parent.parent
    return candidate


def _safe_record_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in sorted(RECORD_FIELDS - {"record_hash", "integrity_signature"})}


def _checkpoint_payload(records: list[Mapping[str, Any]], state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "checkpoint_version": "H4A_SECURITY_STATE_CHECKPOINT_V1",
        "integrity_domain": DOMAIN,
        "record_count": len(records),
        "head_sequence": records[-1]["sequence"] if records else 0,
        "head_hash": records[-1]["record_hash"] if records else "GENESIS",
        "state_digest": generate_digest(dict(state)),
        "state": dict(state),
    }


def _bound(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "payload": dict(payload),
        "integrity_hash": generate_digest(dict(payload)),
        "integrity_signature": sign_payload({"integrity_domain": DOMAIN, "payload": dict(payload)}),
    }


def _verify_bound(value: Mapping[str, Any]) -> bool:
    payload = value.get("payload")
    return bool(
        isinstance(payload, Mapping)
        and value.get("integrity_hash") == generate_digest(dict(payload))
        and verify_signature(
            {"integrity_domain": DOMAIN, "payload": dict(payload)},
            value.get("integrity_signature", {}),
        )
    )


def reconstruct_security_state(records: list[Mapping[str, Any]], now: datetime | None = None) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    credentials: dict[str, Any] = {}
    nonces: dict[str, str] = {}
    request_ids: dict[str, str] = {}
    lifecycle_requests: dict[str, str] = {}
    for record in records:
        event_type = record["event_type"]
        expiry = _parse_time(record.get("retention_expires_at"))
        if event_type == "NONCE_REGISTERED" and expiry and expiry > current:
            nonces[str(record["nonce_digest"])] = _now_text(expiry)
        elif event_type == "REQUEST_ID_REGISTERED" and expiry and expiry > current:
            request_ids[str(record["request_id"])] = _now_text(expiry)
        elif event_type.startswith("CREDENTIAL_"):
            new_state = record.get("new_state")
            if event_type == "CREDENTIAL_ROTATE" and isinstance(new_state, Mapping):
                source = new_state.get("source")
                replacement = new_state.get("replacement")
                if isinstance(source, Mapping):
                    credentials[str(record["credential_id"])] = dict(source)
                if isinstance(replacement, Mapping) and replacement.get("credential_id"):
                    credentials[str(replacement["credential_id"])] = dict(replacement)
            else:
                credentials[str(record["credential_id"])] = new_state
            if record.get("request_id"):
                lifecycle_requests[str(record["request_id"])] = event_type
        elif event_type == "AUTH_REQUEST_REGISTERED" and expiry and expiry > current:
            if record.get("nonce_digest"):
                nonces[str(record["nonce_digest"])] = _now_text(expiry)
            if record.get("request_id"):
                request_ids[str(record["request_id"])] = _now_text(expiry)
    return {
        "credential_states": dict(sorted(credentials.items())),
        "nonce_digests": dict(sorted(nonces.items())),
        "request_ids": dict(sorted(request_ids.items())),
        "lifecycle_requests": dict(sorted(lifecycle_requests.items())),
    }


class SecurityStateStore:
    def __init__(
        self, path: Path = DEFAULT_PATH, *, allowed_root: Path = APPROVED_ROOT,
        runtime_instance_id: str | None = None,
    ):
        self.path = resolve_security_state_path(path, allowed_root=allowed_root)
        self.checkpoint_path = self.path.with_suffix(".checkpoint.json")
        self.anchor_path = self.path.with_suffix(".anchor.json")
        self.intent_path = self.path.with_suffix(".intent.json")
        self.lock_path = self.path.with_suffix(".lock")
        self.runtime_instance_id = runtime_instance_id or f"desktop-v1-{os.getpid()}"
        self._thread_lock = threading.RLock()
        self._writer_handle = None
        self._transient_handle = None
        self._records: list[dict[str, Any]] = []
        self._state: dict[str, Any] = reconstruct_security_state([])
        self.recovery_classification = "UNINITIALIZED"

    @contextmanager
    def _writer(self) -> Iterator[None]:
        with self._thread_lock:
            if self._writer_handle is not None or self._transient_handle is not None:
                yield
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.lock_path.open("a+b")
            try:
                handle.seek(0)
                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
                import msvcrt
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise SecurityStatePersistenceError("security_state_second_writer_denied") from exc
                self._transient_handle = handle
                yield
            finally:
                self._transient_handle = None
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
                handle.close()

    def acquire_authoritative_writer(self) -> None:
        with self._thread_lock:
            if self._writer_handle is not None:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                handle = self.lock_path.open("a+b")
                handle.seek(0)
                if handle.read(1) == b"":
                    handle.write(b"\0")
                    handle.flush()
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except (OSError, PermissionError) as exc:
                if "handle" in locals():
                    handle.close()
                raise SecurityStatePersistenceError("security_state_second_writer_denied") from exc
            self._writer_handle = handle

    def close(self) -> None:
        with self._thread_lock:
            if self._writer_handle is None:
                return
            import msvcrt
            self._writer_handle.seek(0)
            try:
                msvcrt.locking(self._writer_handle.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                self._writer_handle.close()
                self._writer_handle = None

    def _read_records(self, raw: bytes | None = None) -> list[dict[str, Any]]:
        if raw is None and not self.path.exists():
            return []
        raw = self.path.read_bytes() if raw is None else raw
        if len(raw) > MAX_STORE_BYTES:
            raise SecurityStatePersistenceError("security_state_store_hard_limit")
        records: list[dict[str, Any]] = []
        lines = raw.splitlines(keepends=True)
        for index, line in enumerate(lines):
            if len(line) > MAX_RECORD_BYTES:
                raise SecurityStatePersistenceError("security_state_record_oversized")
            if not line.endswith(b"\n"):
                if index == len(lines) - 1:
                    raise SecurityStatePersistenceError("security_state_recoverable_interrupted_final_write")
                raise SecurityStatePersistenceError("security_state_truncated_record")
            try:
                record = loads_strict_json(line.decode("utf-8"))
            except Exception as exc:
                label = "final" if index == len(lines) - 1 else "middle"
                raise SecurityStatePersistenceError(f"security_state_corrupted_{label}_record") from exc
            if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
                raise SecurityStatePersistenceError("security_state_record_schema_invalid")
            records.append(record)
        return records

    def _verify_records(self, records: list[Mapping[str, Any]]) -> None:
        previous = "GENESIS"
        for index, record in enumerate(records):
            if record["record_version"] != RECORD_VERSION or record["integrity_domain"] != DOMAIN:
                raise SecurityStatePersistenceError("security_state_record_version_invalid")
            if record["sequence"] != index + 1:
                raise SecurityStatePersistenceError("security_state_sequence_invalid")
            if record["previous_record_hash"] != previous:
                raise SecurityStatePersistenceError("security_state_previous_hash_invalid")
            payload = _safe_record_payload(record)
            if record["record_hash"] != generate_digest(payload):
                raise SecurityStatePersistenceError("security_state_record_hash_invalid")
            if not verify_signature(
                {"integrity_domain": DOMAIN, "payload": payload},
                record["integrity_signature"],
            ):
                raise SecurityStatePersistenceError("security_state_signature_invalid")
            previous = record["record_hash"]

    def validate_and_recover(self) -> str:
        with self._writer():
            ledger_exists = self.path.exists()
            checkpoint_exists = self.checkpoint_path.exists()
            anchor_exists = self.anchor_path.exists()
            if not ledger_exists and not checkpoint_exists and not anchor_exists:
                self._records = []
                self._state = reconstruct_security_state([])
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._atomic_write(self.path, b"")
                self._write_checkpoint_and_anchor()
                self.recovery_classification = "NEW_STORE_INITIALIZED"
                return self.recovery_classification
            if not ledger_exists or not checkpoint_exists or not anchor_exists:
                raise SecurityStatePersistenceError("security_state_ambiguous_missing_component")
            raw_ledger = self.path.read_bytes()
            interrupted_tail = b""
            if raw_ledger and not raw_ledger.endswith(b"\n"):
                last_newline = raw_ledger.rfind(b"\n")
                if last_newline < 0:
                    raise SecurityStatePersistenceError("security_state_ambiguous_persistence_state")
                interrupted_tail = raw_ledger[last_newline + 1:]
                raw_ledger = raw_ledger[:last_newline + 1]
            records = self._read_records(raw_ledger)
            self._verify_records(records)
            try:
                checkpoint = loads_strict_json(self.checkpoint_path.read_text("utf-8"))
                anchor = loads_strict_json(self.anchor_path.read_text("utf-8"))
            except Exception as exc:
                raise SecurityStatePersistenceError("security_state_checkpoint_corrupted") from exc
            if not isinstance(checkpoint, Mapping) or not _verify_bound(checkpoint):
                raise SecurityStatePersistenceError("security_state_checkpoint_integrity_invalid")
            if not isinstance(anchor, Mapping) or not _verify_bound(anchor):
                raise SecurityStatePersistenceError("security_state_anchor_integrity_invalid")
            state = reconstruct_security_state(records)
            expected = _checkpoint_payload(records, state)
            intent = None
            if self.intent_path.exists():
                try:
                    loaded_intent = loads_strict_json(self.intent_path.read_text("utf-8"))
                except Exception as exc:
                    raise SecurityStatePersistenceError("security_state_intent_corrupted") from exc
                if not isinstance(loaded_intent, Mapping) or not _verify_bound(loaded_intent):
                    raise SecurityStatePersistenceError("security_state_intent_integrity_invalid")
                intent = loaded_intent["payload"]
            if dict(checkpoint["payload"]) != expected:
                prefix_records = records[:-1]
                prefix_state = reconstruct_security_state(prefix_records)
                prefix_expected = _checkpoint_payload(prefix_records, prefix_state)
                anchor_payload = anchor["payload"]
                if (
                    records
                    and intent is not None
                    and intent.get("sequence") == records[-1]["sequence"]
                    and intent.get("record_hash") == records[-1]["record_hash"]
                    and dict(checkpoint["payload"]) == prefix_expected
                    and anchor_payload.get("head_sequence") == prefix_expected["head_sequence"]
                    and anchor_payload.get("head_hash") == prefix_expected["head_hash"]
                    and anchor_payload.get("checkpoint_hash") == checkpoint["integrity_hash"]
                ):
                    self._records = [dict(item) for item in records]
                    self._state = state
                    self._write_checkpoint_and_anchor()
                    self.intent_path.unlink(missing_ok=True)
                    self.recovery_classification = "RECOVERED_EVENT_APPEND_BEFORE_CHECKPOINT"
                    return self.recovery_classification
                raise SecurityStatePersistenceError("security_state_checkpoint_stale_or_rollback")
            anchor_payload = anchor["payload"]
            if (
                anchor_payload.get("integrity_domain") != DOMAIN
                or anchor_payload.get("head_sequence") != expected["head_sequence"]
                or anchor_payload.get("head_hash") != expected["head_hash"]
                or anchor_payload.get("checkpoint_hash") != checkpoint["integrity_hash"]
            ):
                if (
                    intent is not None
                    and intent.get("sequence") == expected["head_sequence"]
                    and intent.get("record_hash") == expected["head_hash"]
                    and expected["head_sequence"] > 0
                    and anchor_payload.get("head_sequence") == expected["head_sequence"] - 1
                    and anchor_payload.get("head_hash")
                    == (records[-2]["record_hash"] if len(records) > 1 else "GENESIS")
                ):
                    self._records = [dict(item) for item in records]
                    self._state = state
                    self._write_checkpoint_and_anchor()
                    self.intent_path.unlink(missing_ok=True)
                    self.recovery_classification = "RECOVERED_CHECKPOINT_BEFORE_ANCHOR"
                    return self.recovery_classification
                raise SecurityStatePersistenceError("security_state_rollback_detected")
            self._records = [dict(item) for item in records]
            self._state = state
            if interrupted_tail:
                self._atomic_write(self.path, raw_ledger)
                self.recovery_classification = "RECOVERED_INTERRUPTED_FINAL_WRITE"
            else:
                self.recovery_classification = "VALID"
            return self.recovery_classification

    def _atomic_write(self, path: Path, data: bytes) -> None:
        temp = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
        try:
            with temp.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        except OSError as exc:
            if temp.exists():
                temp.unlink(missing_ok=True)
            raise SecurityStatePersistenceError("security_state_atomic_write_failed") from exc

    def _write_checkpoint_and_anchor(self) -> None:
        checkpoint = _bound(_checkpoint_payload(self._records, self._state))
        checkpoint_bytes = (json.dumps(checkpoint, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self._atomic_write(self.checkpoint_path, checkpoint_bytes)
        anchor = _bound({
            "anchor_version": "H4A_SECURITY_STATE_ANCHOR_V1",
            "integrity_domain": DOMAIN,
            "head_sequence": len(self._records),
            "head_hash": self._records[-1]["record_hash"] if self._records else "GENESIS",
            "checkpoint_hash": checkpoint["integrity_hash"],
        })
        self._atomic_write(
            self.anchor_path,
            (json.dumps(anchor, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )

    def append_event(
        self, *, event_type: str, credential_id: str | None = None,
        principal_id: str | None = None, request_id: str | None = None,
        nonce_digest: str | None = None, credential_version: int | None = None,
        prior_state: Any = None, new_state: Any = None, reason: str = "",
        issued_at: datetime | None = None, effective_at: datetime | None = None,
        retention_expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        with self._writer():
            self.validate_and_recover()
            sequence = len(self._records) + 1
            now = issued_at or datetime.now(timezone.utc)
            payload = {
                "record_version": RECORD_VERSION, "sequence": sequence,
                "event_id": str(uuid.uuid4()), "event_type": event_type,
                "credential_id": credential_id, "principal_id": principal_id,
                "request_id": request_id, "nonce_digest": nonce_digest,
                "credential_version": credential_version, "prior_state": prior_state,
                "new_state": new_state, "reason": reason, "issued_at": _now_text(now),
                "effective_at": _now_text(effective_at or now),
                "previous_record_hash": self._records[-1]["record_hash"] if self._records else "GENESIS",
                "runtime_instance_id": self.runtime_instance_id,
                "retention_expires_at": _now_text(retention_expires_at) if retention_expires_at else None,
                "integrity_domain": DOMAIN,
            }
            record_hash = generate_digest(payload)
            record = {
                **payload, "record_hash": record_hash,
                "integrity_signature": sign_payload({"integrity_domain": DOMAIN, "payload": payload}),
            }
            encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if len(encoded) > MAX_RECORD_BYTES:
                raise SecurityStatePersistenceError("security_state_record_oversized")
            existing = self.path.read_bytes() if self.path.exists() else b""
            if len(existing) + len(encoded) > MAX_STORE_BYTES:
                raise SecurityStatePersistenceError("security_state_store_hard_limit")
            intent = _bound({
                "intent_version": "H4A_SECURITY_STATE_WRITE_INTENT_V1",
                "integrity_domain": DOMAIN,
                "sequence": sequence,
                "record_hash": record_hash,
            })
            self._atomic_write(
                self.intent_path,
                (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            )
            self._atomic_write(self.path, existing + encoded)
            self._records.append(record)
            self._state = reconstruct_security_state(self._records)
            self._write_checkpoint_and_anchor()
            self.intent_path.unlink(missing_ok=True)
            return record

    def register_replay(
        self, *, credential_id: str, request_id: str, nonce: str,
        expires_at: datetime, now: datetime,
    ) -> None:
        nonce_digest = sha256(nonce.encode()).hexdigest()
        with self._writer():
            self.validate_and_recover()
            if nonce_digest in self._state["nonce_digests"]:
                raise SecurityStatePersistenceError("persistent_nonce_replay")
            if request_id in self._state["request_ids"]:
                raise SecurityStatePersistenceError("persistent_request_id_replay")
            retention = min(expires_at, now + timedelta(seconds=MAX_REPLAY_RETENTION_SECONDS))
            self.append_event(
                event_type="AUTH_REQUEST_REGISTERED", credential_id=credential_id,
                request_id=request_id, nonce_digest=nonce_digest,
                reason="authenticated_request_replay_protection",
                issued_at=now, retention_expires_at=retention,
            )

    def append_lifecycle(
        self, *, action: str, credential_id: str, principal_id: str,
        credential_version: int, request_id: str, prior_state: Any,
        new_state: Any, reason: str, now: datetime,
    ) -> None:
        self.append_event(
            event_type=f"CREDENTIAL_{action}", credential_id=credential_id,
            principal_id=principal_id, credential_version=credential_version,
            request_id=request_id, prior_state=prior_state, new_state=new_state,
            reason=reason, issued_at=now, effective_at=now,
        )

    def state(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._state))

    def storage_warning(self) -> bool:
        return self.path.exists() and self.path.stat().st_size >= STORE_WARNING_BYTES


_ACTIVE_STORE: SecurityStateStore | None = None


def active_security_state_store() -> SecurityStateStore | None:
    return _ACTIVE_STORE


def initialize_security_state_store(path: Path | None = None, *, hold_writer: bool = False) -> SecurityStateStore:
    global _ACTIVE_STORE
    configured = path or Path(os.environ.get("SBP_LEX_SECURITY_STATE_STORE", str(DEFAULT_PATH)))
    store = SecurityStateStore(configured)
    store.validate_and_recover()
    if hold_writer:
        store.acquire_authoritative_writer()
    _ACTIVE_STORE = store
    return store


def reset_active_store_for_tests() -> None:
    global _ACTIVE_STORE
    if _ACTIVE_STORE is not None:
        _ACTIVE_STORE.close()
    _ACTIVE_STORE = None
