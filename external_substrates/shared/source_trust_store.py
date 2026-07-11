from __future__ import annotations

import base64
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
from external_substrates.shared.source_crypto import ALGORITHM, PURPOSE

TRUST_RECORD_VERSION = "H6H_EXTERNAL_SOURCE_TRUST_RECORD_V1"
STORE_VERSION = "H6H_EXTERNAL_SOURCE_TRUST_STORE_V1"
CHECKPOINT_VERSION = "H6H_EXTERNAL_SOURCE_TRUST_CHECKPOINT_V1"
ANCHOR_VERSION = "H6H_EXTERNAL_SOURCE_TRUST_ANCHOR_V1"
INTEGRITY_DOMAIN = "SBP_LEX_DESKTOP_V1_EXTERNAL_SOURCE_TRUST_ADMIN"
STATUSES = frozenset({"PENDING", "ACTIVE", "ROTATING", "SUSPENDED", "REVOKED", "EXPIRED", "RETIRED"})
SUBSTRATE_PACKAGE_TYPES = {
    "SKG": frozenset({"external_skg_signal_package"}),
    "DTN": frozenset({"external_dtn_signal_package"}),
}
MAX_ROTATION_OVERLAP = timedelta(minutes=10)
DEFAULT_ROOT = (Path(__file__).resolve().parents[2] / "runtime_artifacts" / "external_boundary").resolve()
DEFAULT_PATH = DEFAULT_ROOT / "source_trust_store.json"
RECORD_FIELDS = frozenset({
    "trust_record_version", "source_id", "substrate_type", "key_id", "key_version",
    "algorithm", "public_verification_material", "allowed_package_types",
    "allowed_schema_versions", "not_before", "expires_at", "status", "revoked_at",
    "revocation_reason", "replacement_key_id", "previous_record_hash", "record_hash",
    "integrity_binding",
})


class ExternalTrustStoreError(RuntimeError):
    pass


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _resolve(path: Path, root: Path) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    candidate = candidate.resolve(strict=False)
    if not candidate.is_relative_to(root) or candidate.suffix != ".json":
        raise ExternalTrustStoreError("trust_store_path_denied")
    return candidate


def _bound(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = {"integrity_domain": INTEGRITY_DOMAIN, "payload": dict(payload)}
    return {"payload": dict(payload), "digest": digest_mapping(value), "signature": sign_payload(value)}


def _verify_bound(value: Any) -> bool:
    if not isinstance(value, Mapping) or not isinstance(value.get("payload"), Mapping):
        return False
    payload = dict(value["payload"])
    bound = {"integrity_domain": INTEGRITY_DOMAIN, "payload": payload}
    return value.get("digest") == digest_mapping(bound) and verify_signature(bound, str(value.get("signature", "")))


def authorize_trust_change(
    *, action: str, source_id: str, key_id: str, approval_reference: str,
    actor_id: str = "DESKTOP_V1_LOCAL_TRUST_ADMIN",
) -> dict[str, Any]:
    if not approval_reference:
        raise ExternalTrustStoreError("explicit_admin_approval_required")
    return _bound({
        "authorization_version": "H6H_LOCAL_TRUST_ADMIN_AUTHORIZATION_V1",
        "actor_id": actor_id,
        "action": action,
        "source_id": source_id,
        "key_id": key_id,
        "approval_reference": approval_reference,
    })


def trust_record_values(
    *, source_id: str, substrate_type: str, key_id: str, key_version: int,
    public_verification_material: str, allowed_package_types: Sequence[str],
    allowed_schema_versions: Sequence[str], not_before: str, expires_at: str,
    status: str = "PENDING", algorithm: str = ALGORITHM,
    revoked_at: str | None = None, revocation_reason: str | None = None,
    replacement_key_id: str | None = None,
) -> dict[str, Any]:
    return {
        "trust_record_version": TRUST_RECORD_VERSION,
        "source_id": source_id,
        "substrate_type": substrate_type,
        "key_id": key_id,
        "key_version": key_version,
        "algorithm": algorithm,
        "public_verification_material": public_verification_material,
        "allowed_package_types": sorted(set(allowed_package_types)),
        "allowed_schema_versions": sorted(set(allowed_schema_versions)),
        "not_before": not_before,
        "expires_at": expires_at,
        "status": status,
        "revoked_at": revoked_at,
        "revocation_reason": revocation_reason,
        "replacement_key_id": replacement_key_id,
    }


class ExternalSourceTrustStore:
    def __init__(self, path: Path = DEFAULT_PATH, *, allowed_root: Path = DEFAULT_ROOT) -> None:
        self.path = _resolve(path, allowed_root)
        self.checkpoint_path = self.path.with_suffix(".checkpoint.json")
        self.anchor_path = self.path.with_suffix(".anchor.json")
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
                    raise ExternalTrustStoreError("trust_store_second_writer_denied") from exc
                yield
            finally:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
                handle.close()

    def _atomic(self, path: Path, value: Mapping[str, Any]) -> None:
        temporary = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
        data = (canonical_dumps(dict(value)) + "\n").encode("utf-8")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise ExternalTrustStoreError("trust_store_atomic_write_failed") from exc

    def _payload(self, records: Sequence[Mapping[str, Any]], generation: int) -> dict[str, Any]:
        return {"store_version": STORE_VERSION, "generation": generation, "records": [dict(item) for item in records]}

    def _checkpoint(self, records: Sequence[Mapping[str, Any]], generation: int) -> dict[str, Any]:
        return _bound({
            "checkpoint_version": CHECKPOINT_VERSION,
            "generation": generation,
            "record_count": len(records),
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
        })

    def _write_all(self, records: Sequence[Mapping[str, Any]], generation: int) -> None:
        payload = self._payload(records, generation)
        store = {"payload": payload, "payload_digest": digest_mapping(payload), "integrity_binding": _bound(payload)}
        checkpoint = self._checkpoint(records, generation)
        anchor = _bound({
            "anchor_version": ANCHOR_VERSION,
            "generation": generation,
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
            "checkpoint_digest": checkpoint["digest"],
        })
        self._atomic(self.path, store)
        self._atomic(self.checkpoint_path, checkpoint)
        self._atomic(self.anchor_path, anchor)

    def initialize(self, authorization: Mapping[str, Any]) -> None:
        with self._writer():
            if any(path.exists() for path in (self.path, self.checkpoint_path, self.anchor_path)):
                raise ExternalTrustStoreError("trust_store_already_exists")
            if not _verify_bound(authorization) or authorization["payload"].get("action") != "INITIALIZE":
                raise ExternalTrustStoreError("unauthorised_trust_store_mutation")
            self._write_all([], 1)

    def _load(self) -> tuple[list[dict[str, Any]], int]:
        if not all(path.exists() for path in (self.path, self.checkpoint_path, self.anchor_path)):
            raise ExternalTrustStoreError("trust_store_missing_or_ambiguous")
        try:
            store = json.loads(self.path.read_text("utf-8"))
            checkpoint = json.loads(self.checkpoint_path.read_text("utf-8"))
            anchor = json.loads(self.anchor_path.read_text("utf-8"))
        except Exception as exc:
            raise ExternalTrustStoreError("trust_store_corrupted") from exc
        if not isinstance(store, Mapping) or set(store) != {"payload", "payload_digest", "integrity_binding"}:
            raise ExternalTrustStoreError("trust_store_schema_invalid")
        payload = store.get("payload")
        if not isinstance(payload, Mapping) or payload.get("store_version") != STORE_VERSION:
            raise ExternalTrustStoreError("trust_store_version_invalid")
        if (
            store.get("payload_digest") != digest_mapping(dict(payload))
            or not _verify_bound(store.get("integrity_binding"))
            or dict(store["integrity_binding"]["payload"]) != dict(payload)
        ):
            raise ExternalTrustStoreError("trust_store_integrity_invalid")
        records = payload.get("records")
        generation = payload.get("generation")
        if not isinstance(records, list) or not isinstance(generation, int) or generation < 1:
            raise ExternalTrustStoreError("trust_store_payload_invalid")
        self._verify_records(records)
        expected_checkpoint = self._checkpoint(records, generation)
        if not _verify_bound(checkpoint) or checkpoint != expected_checkpoint:
            raise ExternalTrustStoreError("trust_store_checkpoint_stale_or_rollback")
        if not _verify_bound(anchor):
            raise ExternalTrustStoreError("trust_store_anchor_invalid")
        expected_anchor = {
            "anchor_version": ANCHOR_VERSION,
            "generation": generation,
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
            "checkpoint_digest": checkpoint["digest"],
        }
        if dict(anchor["payload"]) != expected_anchor:
            raise ExternalTrustStoreError("trust_store_rollback_detected")
        return [dict(item) for item in records], generation

    def _verify_records(self, records: Sequence[Mapping[str, Any]]) -> None:
        previous = "GENESIS"
        for record in records:
            if not isinstance(record, Mapping) or set(record) != RECORD_FIELDS:
                raise ExternalTrustStoreError("trust_record_schema_invalid")
            if record.get("trust_record_version") != TRUST_RECORD_VERSION or record.get("previous_record_hash") != previous:
                raise ExternalTrustStoreError("trust_record_lineage_invalid")
            body = {key: deepcopy(value) for key, value in record.items() if key not in {"record_hash", "integrity_binding"}}
            if record.get("record_hash") != digest_mapping(body):
                raise ExternalTrustStoreError("trust_record_hash_invalid")
            binding = {"record_hash": record["record_hash"], "integrity_domain": INTEGRITY_DOMAIN}
            if not verify_signature(binding, str(record.get("integrity_binding", ""))):
                raise ExternalTrustStoreError("trust_record_integrity_invalid")
            self._validate_record(record)
            previous = str(record["record_hash"])

    def _validate_record(self, record: Mapping[str, Any]) -> None:
        substrate = record.get("substrate_type")
        if substrate not in SUBSTRATE_PACKAGE_TYPES or record.get("status") not in STATUSES:
            raise ExternalTrustStoreError("trust_record_enum_invalid")
        if record.get("algorithm") != ALGORITHM:
            raise ExternalTrustStoreError("trust_record_algorithm_invalid")
        if not all(isinstance(record.get(key), str) and record.get(key) for key in ("source_id", "key_id")):
            raise ExternalTrustStoreError("trust_record_identity_invalid")
        if not isinstance(record.get("key_version"), int) or record["key_version"] < 1:
            raise ExternalTrustStoreError("trust_record_key_version_invalid")
        if not set(record.get("allowed_package_types", [])) <= SUBSTRATE_PACKAGE_TYPES[str(substrate)]:
            raise ExternalTrustStoreError("trust_record_package_scope_invalid")
        if not record.get("allowed_package_types") or not record.get("allowed_schema_versions"):
            raise ExternalTrustStoreError("trust_record_scope_missing")
        start, end = _parse_time(record.get("not_before")), _parse_time(record.get("expires_at"))
        if start is None or end is None or start >= end:
            raise ExternalTrustStoreError("trust_record_validity_invalid")
        try:
            raw = base64.b64decode(record.get("public_verification_material", ""), validate=True)
            from cryptography.hazmat.primitives.asymmetric import mldsa
            mldsa.MLDSA65PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise ExternalTrustStoreError("trust_record_public_key_invalid") from exc
        if record.get("status") == "REVOKED" and (not record.get("revoked_at") or not record.get("revocation_reason")):
            raise ExternalTrustStoreError("trust_record_revocation_incomplete")

    def append(self, values: Mapping[str, Any], authorization: Mapping[str, Any]) -> dict[str, Any]:
        with self._writer():
            records, generation = self._load()
            auth = authorization.get("payload", {}) if isinstance(authorization, Mapping) else {}
            if (
                not _verify_bound(authorization)
                or auth.get("action") != "APPEND_TRUST_RECORD"
                or auth.get("source_id") != values.get("source_id")
                or auth.get("key_id") != values.get("key_id")
            ):
                raise ExternalTrustStoreError("unauthorised_trust_store_mutation")
            required_values = RECORD_FIELDS - {"previous_record_hash", "record_hash", "integrity_binding"}
            if set(values) != required_values:
                raise ExternalTrustStoreError("trust_record_input_schema_invalid")
            prior = self._latest(records).get(str(values["key_id"]))
            if prior and int(values["key_version"]) <= int(prior["key_version"]):
                raise ExternalTrustStoreError("trust_record_version_rollback")
            self._validate_replacement_scope(values, records)
            body = {**deepcopy(dict(values)), "previous_record_hash": records[-1]["record_hash"] if records else "GENESIS"}
            record_hash = digest_mapping(body)
            record = {
                **body,
                "record_hash": record_hash,
                "integrity_binding": sign_payload({"record_hash": record_hash, "integrity_domain": INTEGRITY_DOMAIN}),
            }
            self._validate_record(record)
            records.append(record)
            self._write_all(records, generation + 1)
            return deepcopy(record)

    def _latest(self, records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for record in records:
            latest[str(record["key_id"])] = dict(record)
        return latest

    def _validate_replacement_scope(self, values: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> None:
        key_id = str(values.get("key_id"))
        candidates = [
            item for item in self._latest(records).values()
            if item.get("replacement_key_id") == key_id
        ]
        for prior in candidates:
            if prior.get("source_id") != values.get("source_id") or prior.get("substrate_type") != values.get("substrate_type"):
                raise ExternalTrustStoreError("replacement_identity_or_substrate_mismatch")
            if not set(values.get("allowed_package_types", [])) <= set(prior.get("allowed_package_types", [])):
                raise ExternalTrustStoreError("replacement_scope_broadening")
            if not set(values.get("allowed_schema_versions", [])) <= set(prior.get("allowed_schema_versions", [])):
                raise ExternalTrustStoreError("replacement_scope_broadening")
            prior_expiry = _parse_time(prior.get("expires_at"))
            new_start = _parse_time(values.get("not_before"))
            if prior_expiry and new_start and prior_expiry - new_start > MAX_ROTATION_OVERLAP:
                raise ExternalTrustStoreError("rotation_overlap_exceeded")

    def active_record(
        self, *, source_id: str, key_id: str, substrate_type: str,
        package_type: str, schema_version: str, now: str,
    ) -> dict[str, Any]:
        records, _ = self._load()
        record = self._latest(records).get(key_id)
        if record is None:
            raise ExternalTrustStoreError("unknown_source_key")
        if record.get("source_id") != source_id:
            raise ExternalTrustStoreError("source_identity_mismatch")
        if record.get("substrate_type") != substrate_type:
            raise ExternalTrustStoreError("source_substrate_mismatch")
        if record.get("status") != "ACTIVE":
            raise ExternalTrustStoreError(f"source_key_not_active:{str(record.get('status')).lower()}")
        current = _parse_time(now)
        if current is None or not (_parse_time(record["not_before"]) <= current < _parse_time(record["expires_at"])):
            raise ExternalTrustStoreError("source_key_expired_or_not_yet_valid")
        if package_type not in record["allowed_package_types"]:
            raise ExternalTrustStoreError("source_key_package_class_denied")
        if schema_version not in record["allowed_schema_versions"]:
            raise ExternalTrustStoreError("source_key_schema_denied")
        if record.get("algorithm") != ALGORITHM:
            raise ExternalTrustStoreError("source_key_algorithm_denied")
        return deepcopy(record)

    def validate(self) -> None:
        self._load()

    def export_public_records(self) -> list[dict[str, Any]]:
        records, _ = self._load()
        rendered = canonical_dumps(records).lower()
        if "private" in rendered or "seed" in rendered:
            raise ExternalTrustStoreError("private_key_material_detected")
        return deepcopy(records)
