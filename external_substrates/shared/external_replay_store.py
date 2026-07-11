from __future__ import annotations

import json
import os
import threading
import uuid
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.signing import sign_payload, verify_signature

DOMAIN = "SBP_LEX_DESKTOP_V1_EXTERNAL_REPLAY_STATE"
RECORD_VERSION = "H6I_EXTERNAL_REPLAY_RECORD_V1"
CHECKPOINT_VERSION = "H6I_EXTERNAL_REPLAY_CHECKPOINT_V1"
ANCHOR_VERSION = "H6I_EXTERNAL_REPLAY_ANCHOR_V1"
DEFAULT_ROOT = (Path(__file__).resolve().parents[2] / "runtime_artifacts" / "external_boundary").resolve()
DEFAULT_PATH = DEFAULT_ROOT / "external_replay_ledger.jsonl"
MINIMUM_RETENTION_SECONDS = 600
MAX_RECORDS = 100_000
RECORD_FIELDS = frozenset({
    "record_version", "sequence", "external_package_id", "canonical_package_digest",
    "source_id", "key_id", "substrate_type", "issued_timestamp", "accepted_timestamp",
    "freshness_window", "protection_until", "previous_record_hash", "record_hash",
    "integrity_binding",
})


class ExternalReplayStoreError(RuntimeError):
    pass


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo else None


def _text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve(path: Path, root: Path) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    candidate = candidate.resolve(strict=False)
    if not candidate.is_relative_to(root) or candidate.suffix != ".jsonl":
        raise ExternalReplayStoreError("external_replay_path_denied")
    return candidate


def _bound(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = {"integrity_domain": DOMAIN, "payload": dict(payload)}
    return {"payload": dict(payload), "digest": digest_mapping(value), "signature": sign_payload(value)}


def _verify_bound(value: Any) -> bool:
    if not isinstance(value, Mapping) or not isinstance(value.get("payload"), Mapping):
        return False
    payload = dict(value["payload"])
    bound = {"integrity_domain": DOMAIN, "payload": payload}
    return value.get("digest") == digest_mapping(bound) and verify_signature(bound, str(value.get("signature", "")))


class ExternalReplayStore:
    def __init__(self, path: Path = DEFAULT_PATH, *, allowed_root: Path = DEFAULT_ROOT) -> None:
        self.path = _resolve(path, allowed_root)
        self.checkpoint_path = self.path.with_suffix(".checkpoint.json")
        self.anchor_path = self.path.with_suffix(".anchor.json")
        self.intent_path = self.path.with_suffix(".intent.json")
        self.lock_path = self.path.with_suffix(".lock")
        self._thread_lock = threading.RLock()

    @contextmanager
    def _writer(self) -> Iterator[None]:
        with self._thread_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.lock_path.open("a+b")
            try:
                if handle.read(1) == b"":
                    handle.write(b"\0")
                    handle.flush()
                import msvcrt
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise ExternalReplayStoreError("external_replay_second_writer_denied") from exc
                yield
            finally:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
                handle.close()

    def _atomic_bytes(self, path: Path, data: bytes) -> None:
        temporary = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise ExternalReplayStoreError("external_replay_atomic_write_failed") from exc

    def _atomic_json(self, path: Path, value: Mapping[str, Any]) -> None:
        self._atomic_bytes(path, (canonical_dumps(dict(value)) + "\n").encode("utf-8"))

    def _checkpoint(self, records: Sequence[Mapping[str, Any]], generation: int) -> dict[str, Any]:
        return _bound({
            "checkpoint_version": CHECKPOINT_VERSION,
            "generation": generation,
            "record_count": len(records),
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
        })

    def _write_metadata(self, records: Sequence[Mapping[str, Any]], generation: int) -> None:
        checkpoint = self._checkpoint(records, generation)
        anchor = _bound({
            "anchor_version": ANCHOR_VERSION,
            "generation": generation,
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
            "checkpoint_digest": checkpoint["digest"],
        })
        self._atomic_json(self.checkpoint_path, checkpoint)
        self._atomic_json(self.anchor_path, anchor)

    def initialize(self) -> None:
        with self._writer():
            if any(path.exists() for path in (self.path, self.checkpoint_path, self.anchor_path)):
                raise ExternalReplayStoreError("external_replay_store_already_exists")
            self._atomic_bytes(self.path, b"")
            self._write_metadata([], 1)

    def _read_records(self) -> list[dict[str, Any]]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError as exc:
            raise ExternalReplayStoreError("external_replay_store_missing") from exc
        if raw and not raw.endswith(b"\n"):
            raise ExternalReplayStoreError("external_replay_ledger_truncated")
        records: list[dict[str, Any]] = []
        for line in raw.splitlines():
            try:
                value = json.loads(line.decode("utf-8"))
            except Exception as exc:
                raise ExternalReplayStoreError("external_replay_ledger_corrupted") from exc
            if not isinstance(value, dict):
                raise ExternalReplayStoreError("external_replay_record_invalid")
            records.append(value)
        return records

    def _verify_records(self, records: Sequence[Mapping[str, Any]]) -> None:
        previous = "GENESIS"
        for index, record in enumerate(records):
            if set(record) != RECORD_FIELDS or record.get("record_version") != RECORD_VERSION:
                raise ExternalReplayStoreError("external_replay_record_schema_invalid")
            if record.get("sequence") != index + 1 or record.get("previous_record_hash") != previous:
                raise ExternalReplayStoreError("external_replay_ledger_lineage_invalid")
            body = {key: deepcopy(value) for key, value in record.items() if key not in {"record_hash", "integrity_binding"}}
            if record.get("record_hash") != digest_mapping(body):
                raise ExternalReplayStoreError("external_replay_record_hash_invalid")
            binding = {"integrity_domain": DOMAIN, "record_hash": record["record_hash"]}
            if not verify_signature(binding, str(record.get("integrity_binding", ""))):
                raise ExternalReplayStoreError("external_replay_record_integrity_invalid")
            if _parse(record.get("issued_timestamp")) is None or _parse(record.get("accepted_timestamp")) is None:
                raise ExternalReplayStoreError("external_replay_timestamp_invalid")
            if not isinstance(record.get("freshness_window"), int) or record["freshness_window"] < 1:
                raise ExternalReplayStoreError("external_replay_freshness_window_invalid")
            previous = str(record["record_hash"])

    def _load(self) -> tuple[list[dict[str, Any]], int]:
        if self.intent_path.exists():
            raise ExternalReplayStoreError("external_replay_incomplete_write_intent")
        if not self.checkpoint_path.exists() or not self.anchor_path.exists():
            raise ExternalReplayStoreError("external_replay_checkpoint_missing")
        records = self._read_records()
        self._verify_records(records)
        try:
            checkpoint = json.loads(self.checkpoint_path.read_text("utf-8"))
            anchor = json.loads(self.anchor_path.read_text("utf-8"))
        except Exception as exc:
            raise ExternalReplayStoreError("external_replay_checkpoint_corrupted") from exc
        if not _verify_bound(checkpoint) or not _verify_bound(anchor):
            raise ExternalReplayStoreError("external_replay_checkpoint_integrity_invalid")
        generation = checkpoint["payload"].get("generation")
        if not isinstance(generation, int) or checkpoint != self._checkpoint(records, generation):
            raise ExternalReplayStoreError("external_replay_checkpoint_stale_or_rollback")
        expected_anchor = {
            "anchor_version": ANCHOR_VERSION,
            "generation": generation,
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
            "checkpoint_digest": checkpoint["digest"],
        }
        if dict(anchor["payload"]) != expected_anchor:
            raise ExternalReplayStoreError("external_replay_anchor_rollback")
        return records, generation

    def accept(
        self, *, external_package_id: str, canonical_package_digest: str,
        source_id: str, key_id: str, substrate_type: str, issued_timestamp: str,
        accepted_timestamp: str, freshness_window: int,
    ) -> dict[str, Any]:
        with self._writer():
            records, generation = self._load()
            for record in records:
                same_id = record["external_package_id"] == external_package_id
                same_digest = record["canonical_package_digest"] == canonical_package_digest
                if same_id and record["source_id"] != source_id:
                    raise ExternalReplayStoreError("external_replay_cross_source_substitution")
                if same_id and not same_digest:
                    raise ExternalReplayStoreError("external_replay_id_content_changed")
                if same_id:
                    raise ExternalReplayStoreError("external_package_replay")
                if same_digest and record["source_id"] != source_id:
                    raise ExternalReplayStoreError("external_replay_cross_source_substitution")
                if same_digest:
                    raise ExternalReplayStoreError("external_replay_digest_reused")
            accepted = _parse(accepted_timestamp)
            issued = _parse(issued_timestamp)
            if accepted is None or issued is None or freshness_window < 1:
                raise ExternalReplayStoreError("external_replay_input_invalid")
            retention = max(freshness_window, MINIMUM_RETENTION_SECONDS)
            body = {
                "record_version": RECORD_VERSION,
                "sequence": len(records) + 1,
                "external_package_id": external_package_id,
                "canonical_package_digest": canonical_package_digest,
                "source_id": source_id,
                "key_id": key_id,
                "substrate_type": substrate_type,
                "issued_timestamp": issued_timestamp,
                "accepted_timestamp": accepted_timestamp,
                "freshness_window": freshness_window,
                "protection_until": _text(max(issued + timedelta(seconds=freshness_window), accepted + timedelta(seconds=retention))),
                "previous_record_hash": records[-1]["record_hash"] if records else "GENESIS",
            }
            record_hash = digest_mapping(body)
            record = {
                **body,
                "record_hash": record_hash,
                "integrity_binding": sign_payload({"integrity_domain": DOMAIN, "record_hash": record_hash}),
            }
            intent = _bound({"sequence": record["sequence"], "record_hash": record_hash})
            self._atomic_json(self.intent_path, intent)
            encoded = (canonical_dumps(record) + "\n").encode("utf-8")
            existing = self.path.read_bytes()
            self._atomic_bytes(self.path, existing + encoded)
            records.append(record)
            self._write_metadata(records, generation + 1)
            self.intent_path.unlink(missing_ok=True)
            return deepcopy(record)

    def compact(self, *, now: str, maximum_records: int = MAX_RECORDS) -> int:
        with self._writer():
            records, generation = self._load()
            if len(records) <= maximum_records:
                return 0
            current = _parse(now)
            if current is None:
                raise ExternalReplayStoreError("external_replay_compaction_time_invalid")
            retained = [record for record in records if _parse(record["protection_until"]) >= current]
            expired = [record for record in records if _parse(record["protection_until"]) < current]
            remove_count = min(len(expired), max(0, len(records) - maximum_records))
            remove_hashes = {record["record_hash"] for record in expired[:remove_count]}
            retained = [record for record in records if record["record_hash"] not in remove_hashes]
            rebuilt: list[dict[str, Any]] = []
            for record in retained:
                body = {
                    **{key: deepcopy(value) for key, value in record.items() if key not in {"sequence", "previous_record_hash", "record_hash", "integrity_binding"}},
                    "sequence": len(rebuilt) + 1,
                    "previous_record_hash": rebuilt[-1]["record_hash"] if rebuilt else "GENESIS",
                }
                record_hash = digest_mapping(body)
                rebuilt.append({
                    **body, "record_hash": record_hash,
                    "integrity_binding": sign_payload({"integrity_domain": DOMAIN, "record_hash": record_hash}),
                })
            self._atomic_bytes(self.path, b"".join((canonical_dumps(item) + "\n").encode() for item in rebuilt))
            self._write_metadata(rebuilt, generation + 1)
            return remove_count

    def validate(self) -> None:
        self._load()

    def records(self) -> list[dict[str, Any]]:
        records, _ = self._load()
        return deepcopy(records)
