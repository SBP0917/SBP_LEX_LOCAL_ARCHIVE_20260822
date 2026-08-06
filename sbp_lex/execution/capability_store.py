from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

DOMAIN = "SBP_LEX_DESKTOP_V1_EXECUTION_CAPABILITY_STATE"
ATTESTATION_DOMAIN = "SBP_LEX_DESKTOP_V1_POST_EXECUTION_ATTESTATION"
COMPLETION_EVIDENCE_DOMAIN = (
    "SBP_LEX_DESKTOP_V1_ADAPTER_COMPLETION_EVIDENCE"
)
CAPABILITY_DOMAIN = "SBP_LEX_DESKTOP_V1_SINGLE_USE_EXECUTION_CAPABILITY"
CAPABILITY_VERSION = "H7_EXECUTION_CAPABILITY_V2"
ATTESTATION_VERSION = "H7_POST_EXECUTION_ATTESTATION_V2"
COMPLETION_EVIDENCE_VERSION = "H7_ADAPTER_COMPLETION_EVIDENCE_V2"
RECORD_VERSION = "H7_EXECUTION_CAPABILITY_RECORD_V1"
CHECKPOINT_VERSION = "H7_EXECUTION_CAPABILITY_CHECKPOINT_V1"
ANCHOR_VERSION = "H7_EXECUTION_CAPABILITY_ANCHOR_V1"
DEFAULT_ROOT = (Path(__file__).resolve().parents[2] / "runtime_artifacts" / "execution_integrity").resolve()
DEFAULT_PATH = DEFAULT_ROOT / "capability_lifecycle.jsonl"
MAX_RECORD_BYTES = 262_144
MAX_STORE_BYTES = 33_554_432
CAPABILITY_FIELDS = frozenset({
    "capability_version", "capability_id", "request_id", "request_fingerprint",
    "traversal_authority_digest", "issuance_authority_key",
    "eie_identifier", "eie_digest", "canonical_state_hash", "pipeline_mode",
    "pipeline_a_result_digest", "pipeline_b_result_digest", "convergence_result",
    "procedural_truth_token", "classification_token", "licensing_token",
    "governance_token", "grc_token", "domain_token", "aurion_result",
    "target_identity", "target_type", "operation_identity", "canonical_parameter_digest",
    "execution_specification_id", "execution_specification_digest",
    "constraint_digest", "constraint_snapshot", "issued_at", "not_before", "expires_at",
    "reservation_timeout_seconds", "execution_start_deadline", "maximum_execution_seconds",
    "completion_report_deadline", "maximum_attempts", "consumption_state",
    "cancellation_state", "safe_cancellation_supported", "issuer_identity",
    "runtime_identity", "approved_baseline_identifier", "measurement_digest",
    "startup_attestation_digest", "startup_sequence",
    "execution_adapter_identity", "execution_consumer_identity", "audit_lineage_identifier",
    "capability_digest", "integrity_binding",
})
RECORD_FIELDS = frozenset({
    "record_version", "sequence", "event_id", "event_type", "capability_id",
    "prior_state", "new_state", "occurred_at", "capability_digest", "details",
    "previous_record_hash", "record_hash", "integrity_binding",
})
STORE_TRANSITIONS = {
    None: frozenset({"PENDING"}),
    "PENDING": frozenset({"ACTIVE", "CANCELLED"}),
    "ACTIVE": frozenset({"RESERVED", "CANCELLED", "EXPIRED", "REVOKED"}),
    "RESERVED": frozenset({"EXECUTING", "CANCELLED", "EXPIRED", "REVOKED"}),
    "EXECUTING": frozenset({"EXECUTING", "COMPLETED", "FAILED", "AMBIGUOUS", "CANCELLED"}),
    "COMPLETED": frozenset({"RETIRED"}),
    "CANCELLED": frozenset({"RETIRED"}),
    "EXPIRED": frozenset({"RETIRED"}),
    "REVOKED": frozenset({"RETIRED"}),
    "FAILED": frozenset({"RETIRED"}),
    "AMBIGUOUS": frozenset({"RETIRED"}),
    "RETIRED": frozenset(),
}
EVENT_TRANSITIONS = {
    "CAPABILITY_ISSUED": (None, "PENDING"),
    "CAPABILITY_ACTIVATED": ("PENDING", "ACTIVE"),
    "CAPABILITY_RESERVED": ("ACTIVE", "RESERVED"),
    "EXECUTION_STARTED": ("RESERVED", "EXECUTING"),
    "EXECUTION_REVALIDATED": ("EXECUTING", "EXECUTING"),
    "CAPABILITY_CANCELLED": ({"PENDING", "ACTIVE", "RESERVED"}, "CANCELLED"),
    "CAPABILITY_REVOKED": ({"ACTIVE", "RESERVED"}, "REVOKED"),
    "CAPABILITY_EXPIRED": ({"ACTIVE", "RESERVED"}, "EXPIRED"),
    "EXECUTION_DURATION_EXCEEDED": ("EXECUTING", "FAILED"),
    "EXECUTION_COMPLETED": ("EXECUTING", "COMPLETED"),
    "EXECUTION_FAILED": ("EXECUTING", "FAILED"),
    "EXECUTION_CANCELLED": ("EXECUTING", "CANCELLED"),
    "EXECUTION_AMBIGUOUS": ("EXECUTING", "AMBIGUOUS"),
    "EXECUTION_REVOKED_FAILED": ("EXECUTING", "FAILED"),
    "RESTART_DURING_EXECUTION_AMBIGUOUS": ("EXECUTING", "AMBIGUOUS"),
    "CAPABILITY_RETIRED": ({"COMPLETED", "CANCELLED", "EXPIRED", "REVOKED", "FAILED", "AMBIGUOUS"}, "RETIRED"),
}
ATTESTATION_PAYLOAD_FIELDS = frozenset({
    "attestation_version", "attestation_id", "capability_id", "request_id",
    "request_fingerprint", "traversal_authority_digest", "capability_digest",
    "eie_digest", "canonical_state_hash", "target_identity", "operation_identity",
    "parameter_digest", "constraint_digest", "pipeline_mode", "convergence_digest",
    "execution_start", "execution_finish", "completion_classification", "result_digest",
    "adapter_identity", "runtime_identity", "approved_baseline_identifier",
    "measurement_digest", "startup_attestation_digest", "startup_sequence",
    "audit_lineage_identifier", "completion_evidence", "completion_evidence_digest",
    "completion_evidence_valid",
    "previous_attestation_hash",
})
COMPLETION_EVIDENCE_FIELDS = frozenset({
    "evidence_version", "capability_id", "request_fingerprint",
    "traversal_authority_digest", "capability_digest", "eie_digest",
    "canonical_state_hash", "target_identity", "operation_identity",
    "parameter_digest", "result_digest", "adapter_identity", "observed_at",
    "runtime_identity", "approved_baseline_identifier", "measurement_digest",
    "startup_attestation_digest", "startup_sequence", "audit_lineage_identifier",
    "completion_status",
})
ATTESTATION_CAPABILITY_FIELDS = {
    "capability_id": "capability_id", "request_id": "request_id",
    "request_fingerprint": "request_fingerprint",
    "traversal_authority_digest": "traversal_authority_digest",
    "capability_digest": "capability_digest",
    "eie_digest": "eie_digest", "canonical_state_hash": "canonical_state_hash",
    "target_identity": "target_identity", "operation_identity": "operation_identity",
    "parameter_digest": "canonical_parameter_digest", "pipeline_mode": "pipeline_mode",
    "convergence_digest": "convergence_result", "adapter_identity": "execution_adapter_identity",
    "runtime_identity": "runtime_identity",
    "approved_baseline_identifier": "approved_baseline_identifier",
    "measurement_digest": "measurement_digest",
    "startup_attestation_digest": "startup_attestation_digest",
    "startup_sequence": "startup_sequence",
    "audit_lineage_identifier": "audit_lineage_identifier",
}
PIPELINE_MODES = frozenset({
    "MODE_1_FULL_MIRRORED",
    "MODE_2_SPLIT_VALIDATOR",
    "MODE_3_SINGLE_CONSTRAINED",
})
ISSUER = "SBP_LEX_DESKTOP_V1_EXECUTION_INTEGRITY"
LOCAL_EXECUTION_CONSUMER_ID = (
    "SBP_LEX_DESKTOP_V1_LOCAL_EXECUTION_SERVICE"
)
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CONTEXT_FIELDS = (
    "request_id", "request_fingerprint", "eie_identifier", "eie_digest",
    "canonical_state_hash", "pipeline_mode", "pipeline_a_result_digest",
    "pipeline_b_result_digest", "convergence_result", "procedural_truth_token",
    "classification_token", "licensing_token", "governance_token", "grc_token",
    "domain_token", "aurion_result", "target_identity", "target_type",
    "operation_identity", "canonical_parameter_digest", "constraint_digest",
    "constraint_snapshot", "runtime_identity", "approved_baseline_identifier",
    "measurement_digest", "startup_attestation_digest", "startup_sequence",
    "execution_adapter_identity", "audit_lineage_identifier",
)


class CapabilityStoreError(RuntimeError):
    pass


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _valid_request_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= 256
    )


def _valid_baseline_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= 128
    )


def _resolve(path: Path, root: Path) -> Path:
    raw_root = root.absolute()
    if raw_root.exists() and raw_root.is_symlink():
        raise CapabilityStoreError("capability_store_root_reparse_point_denied")
    resolved_root = raw_root.resolve()
    raw_candidate = path.absolute() if path.is_absolute() else raw_root / path
    if raw_candidate.exists() and raw_candidate.is_symlink():
        raise CapabilityStoreError("capability_store_reparse_point_denied")
    parent = raw_candidate.parent
    while parent != raw_root.parent:
        if parent.exists() and parent.is_symlink():
            raise CapabilityStoreError("capability_store_reparse_point_denied")
        if parent == raw_root:
            break
        parent = parent.parent
    candidate = raw_candidate.resolve(strict=False)
    if not candidate.is_relative_to(resolved_root) or candidate.suffix != ".jsonl":
        raise CapabilityStoreError("capability_store_path_denied")
    return candidate


def _bound(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = {"integrity_domain": DOMAIN, "payload": dict(payload)}
    return {
        "payload": dict(payload),
        "integrity_hash": generate_digest(value),
        "integrity_binding": sign_payload(value),
    }


def _verify_bound(value: Any) -> bool:
    if not isinstance(value, Mapping) or not isinstance(value.get("payload"), Mapping):
        return False
    payload = dict(value["payload"])
    bound = {"integrity_domain": DOMAIN, "payload": payload}
    return (
        value.get("integrity_hash") == generate_digest(bound)
        and verify_signature(bound, value.get("integrity_binding", {}))
    )


def _verify_embedded_capability(
    capability: Any, *, capability_id: str, capability_digest: str,
) -> bool:
    if not isinstance(capability, Mapping):
        return False
    if set(capability) != CAPABILITY_FIELDS:
        return False
    if (
        capability.get("capability_version") != CAPABILITY_VERSION
        or capability.get("capability_id") != capability_id
        or capability.get("capability_digest") != capability_digest
        or capability.get("issuer_identity") != ISSUER
        or capability.get("execution_consumer_identity")
        != LOCAL_EXECUTION_CONSUMER_ID
        or capability.get("maximum_attempts") != 1
        or capability.get("consumption_state") != "UNCONSUMED"
        or capability.get("cancellation_state") != "NOT_CANCELLED"
        or not isinstance(capability.get("safe_cancellation_supported"), bool)
        or not _valid_request_id(capability.get("request_id"))
        or not isinstance(capability.get("eie_identifier"), str)
        or not capability.get("eie_identifier")
        or capability.get("eie_identifier")
        != capability.get("eie_identifier").strip()
        or capability.get("pipeline_mode") not in PIPELINE_MODES
        or not _valid_baseline_identifier(
            capability.get("approved_baseline_identifier")
        )
        or not isinstance(capability.get("startup_sequence"), int)
        or isinstance(capability.get("startup_sequence"), bool)
        or capability.get("startup_sequence", 0) <= 0
    ):
        return False
    identity_fields = (
        "target_identity", "target_type", "operation_identity",
        "execution_specification_id", "execution_adapter_identity",
        "execution_consumer_identity", "issuer_identity",
    )
    if any(
        not isinstance(capability.get(field), str)
        or _IDENTITY.fullmatch(str(capability[field])) is None
        for field in identity_fields
    ):
        return False
    digest_fields = (
        "capability_id", "request_fingerprint", "traversal_authority_digest",
        "issuance_authority_key", "eie_digest", "canonical_state_hash",
        "pipeline_a_result_digest", "convergence_result",
        "procedural_truth_token", "classification_token", "licensing_token",
        "governance_token", "grc_token", "domain_token", "aurion_result",
        "canonical_parameter_digest", "execution_specification_digest",
        "constraint_digest", "runtime_identity", "measurement_digest",
        "startup_attestation_digest", "audit_lineage_identifier",
        "capability_digest",
    )
    if any(not _is_digest(capability.get(field)) for field in digest_fields):
        return False
    pipeline_b = capability.get("pipeline_b_result_digest")
    if (
        capability.get("pipeline_mode") == "MODE_3_SINGLE_CONSTRAINED"
        and pipeline_b is not None
    ) or (
        capability.get("pipeline_mode") != "MODE_3_SINGLE_CONSTRAINED"
        and not _is_digest(pipeline_b)
    ):
        return False
    constraints = capability.get("constraint_snapshot")
    if (
        not isinstance(constraints, Mapping)
        or not constraints
        or capability.get("constraint_digest")
        != generate_digest(dict(constraints))
    ):
        return False
    temporal_integer_fields = (
        "reservation_timeout_seconds", "maximum_execution_seconds",
    )
    if any(
        not isinstance(capability.get(field), int)
        or isinstance(capability.get(field), bool)
        or capability.get(field, 0) <= 0
        for field in temporal_integer_fields
    ):
        return False
    issued = _parse_time(capability.get("issued_at"))
    not_before = _parse_time(capability.get("not_before"))
    expires = _parse_time(capability.get("expires_at"))
    start_deadline = _parse_time(capability.get("execution_start_deadline"))
    completion_deadline = _parse_time(
        capability.get("completion_report_deadline")
    )
    if (
        issued is None
        or not_before is None
        or expires is None
        or start_deadline is None
        or completion_deadline is None
        or not_before != issued
        or start_deadline <= issued
        or completion_deadline > expires
        or completion_deadline
        < start_deadline
        + timedelta(seconds=int(capability["maximum_execution_seconds"]))
        or int(capability["reservation_timeout_seconds"])
        > int((start_deadline - issued).total_seconds())
    ):
        return False
    expected_authority_key = generate_digest({
        "domain": "H7_SINGLE_CAPABILITY_PER_CANONICAL_TRAVERSAL",
        "traversal_authority_digest": capability[
            "traversal_authority_digest"
        ],
    })
    if capability.get("issuance_authority_key") != expected_authority_key:
        return False
    seed = {
        **{
            key: deepcopy(capability[key])
            for key in _CONTEXT_FIELDS
        },
        "traversal_authority_digest": capability[
            "traversal_authority_digest"
        ],
        "issuance_authority_key": capability["issuance_authority_key"],
        "execution_specification_id": capability[
            "execution_specification_id"
        ],
        "execution_specification_digest": capability[
            "execution_specification_digest"
        ],
        "issued_at": capability["issued_at"],
        "audit_lineage_identifier": capability[
            "audit_lineage_identifier"
        ],
    }
    if capability.get("capability_id") != generate_digest({
        "domain": CAPABILITY_DOMAIN,
        "seed": seed,
    }):
        return False
    body = {
        key: deepcopy(value)
        for key, value in capability.items()
        if key not in {"capability_digest", "integrity_binding"}
    }
    bound = {"integrity_domain": CAPABILITY_DOMAIN, "payload": body}
    return (
        capability_digest == generate_digest(bound)
        and verify_signature(bound, capability.get("integrity_binding", {}))
    )


def _verify_attestation_payload(
    payload: Mapping[str, Any], *, capability: Mapping[str, Any],
    capability_id: str, classification: str, previous_hash: str,
) -> bool:
    started = _parse_time(payload.get("execution_start"))
    finished = _parse_time(payload.get("execution_finish"))
    evidence = payload.get("completion_evidence")
    evidence_valid = payload.get("completion_evidence_valid")
    if not isinstance(evidence, Mapping) or not isinstance(
        evidence_valid, bool
    ):
        return False
    evidence_copy = dict(evidence)
    if (
        payload.get("completion_evidence_digest")
        != generate_digest(evidence_copy)
        or (
            classification == "COMPLETED"
            and evidence_valid is not True
        )
        or (evidence_valid is False and bool(evidence_copy))
        or payload.get("attestation_id") != generate_digest({
            "capability_id": payload.get("capability_id"),
            "finish": payload.get("execution_finish"),
            "classification": payload.get("completion_classification"),
            "completion_evidence_digest": payload.get(
                "completion_evidence_digest"
            ),
        })
    ):
        return False
    if evidence_valid:
        evidence_payload = evidence_copy.get("payload")
        if (
            set(evidence_copy) != {"payload", "integrity_binding"}
            or not isinstance(evidence_payload, Mapping)
            or set(evidence_payload) != COMPLETION_EVIDENCE_FIELDS
            or evidence_payload.get("evidence_version")
            != COMPLETION_EVIDENCE_VERSION
            or evidence_payload.get("completion_status") != "POSITIVE"
            or evidence_payload.get("result_digest")
            != payload.get("result_digest")
            or _parse_time(evidence_payload.get("observed_at")) is None
            or finished is None
            or _parse_time(evidence_payload.get("observed_at")) > finished
        ):
            return False
        evidence_pairs = {
            "capability_id": "capability_id",
            "request_fingerprint": "request_fingerprint",
            "traversal_authority_digest": "traversal_authority_digest",
            "capability_digest": "capability_digest",
            "eie_digest": "eie_digest",
            "canonical_state_hash": "canonical_state_hash",
            "target_identity": "target_identity",
            "operation_identity": "operation_identity",
            "parameter_digest": "canonical_parameter_digest",
            "adapter_identity": "execution_adapter_identity",
            "runtime_identity": "runtime_identity",
            "approved_baseline_identifier": (
                "approved_baseline_identifier"
            ),
            "measurement_digest": "measurement_digest",
            "startup_attestation_digest": "startup_attestation_digest",
            "startup_sequence": "startup_sequence",
            "audit_lineage_identifier": "audit_lineage_identifier",
        }
        evidence_bound = {
            "integrity_domain": COMPLETION_EVIDENCE_DOMAIN,
            "payload": dict(evidence_payload),
        }
        if (
            any(
                evidence_payload.get(left) != capability.get(right)
                for left, right in evidence_pairs.items()
            )
            or not verify_signature(
                evidence_bound,
                evidence_copy.get("integrity_binding", {}),
            )
        ):
            return False
    return (
        set(payload) == ATTESTATION_PAYLOAD_FIELDS
        and payload.get("attestation_version") == ATTESTATION_VERSION
        and payload.get("capability_id") == capability_id
        and payload.get("completion_classification") == classification
        and payload.get("previous_attestation_hash") == previous_hash
        and started is not None
        and finished is not None
        and finished >= started
        and isinstance(payload.get("startup_sequence"), int)
        and not isinstance(payload.get("startup_sequence"), bool)
        and payload.get("startup_sequence", 0) > 0
        and _valid_baseline_identifier(
            payload.get("approved_baseline_identifier")
        )
        and all(
            _is_digest(payload.get(field))
            for field in (
                "attestation_id", "capability_id", "request_fingerprint",
                "traversal_authority_digest", "capability_digest",
                "eie_digest", "canonical_state_hash", "parameter_digest",
                "constraint_digest", "convergence_digest", "result_digest",
                "runtime_identity", "measurement_digest",
                "startup_attestation_digest", "audit_lineage_identifier",
                "completion_evidence_digest",
            )
        )
        and all(
            payload.get(attestation_field) == capability.get(capability_field)
            for attestation_field, capability_field in ATTESTATION_CAPABILITY_FIELDS.items()
        )
    )


class CapabilityLifecycleStore:
    def __init__(self, path: Path = DEFAULT_PATH, *, allowed_root: Path = DEFAULT_ROOT) -> None:
        self.allowed_root = allowed_root.resolve()
        self.path = _resolve(path, allowed_root)
        self.checkpoint_path = self.path.with_suffix(".checkpoint.json")
        self.anchor_path = self.path.with_suffix(".anchor.json")
        self.intent_path = self.path.with_suffix(".intent.json")
        self.lock_path = self.path.with_suffix(".lock")
        self._thread_lock = threading.RLock()
        self._lease_handle: Any = None

    def _assert_paths(self) -> None:
        for path in (
            self.path, self.checkpoint_path, self.anchor_path,
            self.intent_path, self.lock_path,
        ):
            if not path.resolve(strict=False).is_relative_to(self.allowed_root):
                raise CapabilityStoreError("capability_store_path_denied")
            if path.exists() and path.is_symlink():
                raise CapabilityStoreError("capability_store_reparse_point_denied")

    @contextmanager
    def _writer(self) -> Iterator[None]:
        with self._thread_lock:
            self._assert_paths()
            if self._lease_handle is not None:
                yield
                return
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
                    raise CapabilityStoreError("capability_store_second_writer_denied") from exc
                yield
            finally:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
                handle.close()

    def acquire_writer_lease(self) -> None:
        with self._thread_lock:
            if self._lease_handle is not None:
                return
            self._assert_paths()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.lock_path.open("a+b")
            try:
                if handle.read(1) == b"":
                    handle.write(b"\0")
                    handle.flush()
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                handle.close()
                raise CapabilityStoreError("capability_store_second_writer_denied") from exc
            self._lease_handle = handle

    def release_writer_lease(self) -> None:
        with self._thread_lock:
            handle = self._lease_handle
            self._lease_handle = None
            if handle is None:
                return
            try:
                import msvcrt
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
            for attempt in range(5):
                try:
                    os.replace(temporary, path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.01 * (2 ** attempt))
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise CapabilityStoreError("capability_store_atomic_write_failed") from exc

    def _atomic_json(self, path: Path, value: Mapping[str, Any]) -> None:
        encoded = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self._atomic_bytes(path, encoded)

    def _checkpoint_payload(self, records: Sequence[Mapping[str, Any]], generation: int) -> dict[str, Any]:
        latest = self._latest(records)
        return {
            "checkpoint_version": CHECKPOINT_VERSION,
            "generation": generation,
            "record_count": len(records),
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
            "latest_state_digest": generate_digest(latest),
            "latest_states": latest,
            "last_observed_at": records[-1]["occurred_at"] if records else None,
            "attestation_head": self._attestation_head(records),
        }

    def _attestation_head(self, records: Sequence[Mapping[str, Any]]) -> str:
        head = "GENESIS"
        for record in records:
            attestation = record.get("details", {}).get("execution_attestation", {})
            if isinstance(attestation, Mapping) and attestation.get("attestation_hash"):
                head = str(attestation["attestation_hash"])
        return head

    def _anchor_payload(
        self, records: Sequence[Mapping[str, Any]], generation: int,
        checkpoint_hash: str,
    ) -> dict[str, Any]:
        return {
            "anchor_version": ANCHOR_VERSION,
            "generation": generation,
            "head_hash": records[-1]["record_hash"] if records else "GENESIS",
            "checkpoint_hash": checkpoint_hash,
        }

    def _write_metadata(self, records: Sequence[Mapping[str, Any]], generation: int) -> None:
        checkpoint = _bound(self._checkpoint_payload(records, generation))
        anchor = _bound(self._anchor_payload(records, generation, checkpoint["integrity_hash"]))
        self._atomic_json(self.checkpoint_path, checkpoint)
        self._atomic_json(self.anchor_path, anchor)

    def initialize(self) -> None:
        with self._writer():
            if any(path.exists() for path in (self.path, self.checkpoint_path, self.anchor_path, self.intent_path)):
                raise CapabilityStoreError("capability_store_already_exists")
            self._atomic_bytes(self.path, b"")
            self._write_metadata([], 1)

    def _read_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            raise CapabilityStoreError("capability_store_missing")
        raw = self.path.read_bytes()
        if len(raw) > MAX_STORE_BYTES:
            raise CapabilityStoreError("capability_store_hard_limit")
        if raw and not raw.endswith(b"\n"):
            raise CapabilityStoreError("capability_store_truncated")
        records: list[dict[str, Any]] = []
        for index, line in enumerate(raw.splitlines()):
            if len(line) > MAX_RECORD_BYTES:
                raise CapabilityStoreError("capability_record_oversized")
            try:
                record = loads_strict_json(line.decode("utf-8"))
            except Exception as exc:
                raise CapabilityStoreError(f"capability_store_corrupt_record:{index}") from exc
            if not isinstance(record, dict):
                raise CapabilityStoreError("capability_record_not_mapping")
            records.append(record)
        return records

    def _verify_records(self, records: Sequence[Mapping[str, Any]]) -> None:
        previous = "GENESIS"
        last_time: datetime | None = None
        latest: dict[str, tuple[str, str]] = {}
        attestation_head = "GENESIS"
        capabilities: dict[str, Mapping[str, Any]] = {}
        issuance_keys: set[str] = set()
        for index, record in enumerate(records):
            if set(record) != RECORD_FIELDS or record.get("record_version") != RECORD_VERSION:
                raise CapabilityStoreError("capability_record_schema_invalid")
            if record.get("sequence") != index + 1 or record.get("previous_record_hash") != previous:
                raise CapabilityStoreError("capability_record_lineage_invalid")
            occurred = _parse_time(record.get("occurred_at"))
            if occurred is None or (last_time is not None and occurred < last_time):
                raise CapabilityStoreError("capability_store_clock_rollback")
            body = {key: deepcopy(value) for key, value in record.items() if key not in {"record_hash", "integrity_binding"}}
            if record.get("record_hash") != generate_digest(body):
                raise CapabilityStoreError("capability_record_hash_invalid")
            binding = {"integrity_domain": DOMAIN, "record_hash": record["record_hash"]}
            if not verify_signature(binding, record.get("integrity_binding", {})):
                raise CapabilityStoreError("capability_record_integrity_invalid")
            capability_id = str(record["capability_id"])
            details = record.get("details")
            if not isinstance(details, Mapping):
                raise CapabilityStoreError("capability_record_details_invalid")
            if record.get("event_type") == "CAPABILITY_ISSUED":
                capability = details.get("capability")
                if not _verify_embedded_capability(
                    capability, capability_id=capability_id,
                    capability_digest=str(record.get("capability_digest")),
                ):
                    raise CapabilityStoreError("capability_issuance_evidence_invalid")
                issuance_key = str(capability["issuance_authority_key"])
                if issuance_key in issuance_keys:
                    raise CapabilityStoreError("execution_authority_already_consumed")
                issuance_keys.add(issuance_key)
                capabilities[capability_id] = capability
            elif capability_id not in capabilities:
                raise CapabilityStoreError("capability_issuance_evidence_missing")
            prior = latest.get(capability_id)
            expected_prior = prior[0] if prior else None
            if record.get("prior_state") != expected_prior:
                raise CapabilityStoreError("capability_record_prior_state_invalid")
            if prior and record.get("capability_digest") != prior[1]:
                raise CapabilityStoreError("capability_identity_regeneration_denied")
            event_rule = EVENT_TRANSITIONS.get(str(record.get("event_type")))
            if event_rule is None:
                raise CapabilityStoreError("capability_event_unknown")
            allowed_prior, expected_new = event_rule
            allowed = expected_prior in allowed_prior if isinstance(allowed_prior, set) else expected_prior == allowed_prior
            if not allowed or record.get("new_state") != expected_new:
                raise CapabilityStoreError("capability_event_transition_invalid")
            if record.get("new_state") not in STORE_TRANSITIONS.get(expected_prior, frozenset()):
                raise CapabilityStoreError("capability_state_transition_invalid")
            attestation = details.get("execution_attestation", {})
            if expected_prior == "EXECUTING" and record.get("new_state") in {"COMPLETED", "FAILED", "AMBIGUOUS", "CANCELLED"} and not attestation:
                raise CapabilityStoreError("execution_terminal_attestation_missing")
            if attestation:
                if not isinstance(attestation, Mapping) or not isinstance(attestation.get("payload"), Mapping):
                    raise CapabilityStoreError("execution_attestation_schema_invalid")
                payload = dict(attestation["payload"])
                bound = {"integrity_domain": ATTESTATION_DOMAIN, "payload": payload}
                if (
                    not _verify_attestation_payload(
                        payload, capability=capabilities[capability_id],
                        capability_id=capability_id,
                        classification=str(record.get("new_state")),
                        previous_hash=attestation_head,
                    )
                    or attestation.get("attestation_hash") != generate_digest(bound)
                    or not verify_signature(bound, attestation.get("integrity_binding", {}))
                ):
                    raise CapabilityStoreError("execution_attestation_integrity_invalid")
                attestation_head = str(attestation["attestation_hash"])
            latest[capability_id] = (str(record["new_state"]), str(record["capability_digest"]))
            previous = str(record["record_hash"])
            last_time = occurred

    def _load(self) -> tuple[list[dict[str, Any]], int]:
        self._assert_paths()
        if self.intent_path.exists():
            raise CapabilityStoreError("capability_store_incomplete_write_intent")
        if not self.checkpoint_path.exists() or not self.anchor_path.exists():
            raise CapabilityStoreError("capability_store_ambiguous_missing_component")
        records = self._read_records()
        self._verify_records(records)
        try:
            checkpoint = loads_strict_json(self.checkpoint_path.read_text("utf-8"))
            anchor = loads_strict_json(self.anchor_path.read_text("utf-8"))
        except Exception as exc:
            raise CapabilityStoreError("capability_store_metadata_corrupted") from exc
        if not _verify_bound(checkpoint) or not _verify_bound(anchor):
            raise CapabilityStoreError("capability_store_metadata_integrity_invalid")
        generation = checkpoint["payload"].get("generation")
        expected_checkpoint = self._checkpoint_payload(records, generation) if isinstance(generation, int) else None
        if expected_checkpoint is None or dict(checkpoint["payload"]) != expected_checkpoint:
            raise CapabilityStoreError("capability_store_checkpoint_rollback")
        if generation < 1:
            raise CapabilityStoreError("capability_store_checkpoint_generation_invalid")
        expected_anchor = self._anchor_payload(records, generation, checkpoint["integrity_hash"])
        if dict(anchor["payload"]) != expected_anchor:
            raise CapabilityStoreError("capability_store_rollback_detected")
        return records, generation

    def _latest(self, records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for record in records:
            latest[str(record["capability_id"])] = {
                "state": record["new_state"],
                "capability_digest": record["capability_digest"],
                "sequence": record["sequence"],
                "record_hash": record["record_hash"],
                "occurred_at": record["occurred_at"],
                "event_type": record["event_type"],
            }
        return dict(sorted(latest.items()))

    def append_transition(
        self, *, capability_id: str, capability_digest: str,
        event_type: str, expected_state: str | None, new_state: str,
        occurred_at: str, details: Mapping[str, Any] | None = None,
        attestation_payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._writer():
            records, generation = self._load()
            if details is not None and not isinstance(details, Mapping):
                raise CapabilityStoreError("capability_record_details_invalid")
            record_details = deepcopy(dict(details or {}))
            if "execution_attestation" in record_details:
                raise CapabilityStoreError("execution_attestation_must_be_store_bound")
            issued_capability: Mapping[str, Any] | None = None
            if event_type == "CAPABILITY_ISSUED":
                issued_capability = record_details.get("capability")
                if not _verify_embedded_capability(
                    issued_capability, capability_id=capability_id,
                    capability_digest=capability_digest,
                ):
                    raise CapabilityStoreError("capability_issuance_evidence_invalid")
                existing_keys = {
                    item["details"]["capability"]["issuance_authority_key"]
                    for item in records if item["event_type"] == "CAPABILITY_ISSUED"
                }
                if issued_capability["issuance_authority_key"] in existing_keys:
                    raise CapabilityStoreError("execution_authority_already_consumed")
            latest = self._latest(records).get(capability_id)
            actual_state = latest["state"] if latest else None
            if actual_state != expected_state:
                if latest and latest["capability_digest"] != capability_digest:
                    raise CapabilityStoreError("capability_identity_regeneration_denied")
                raise CapabilityStoreError(f"capability_state_conflict:{actual_state}")
            if latest and latest["capability_digest"] != capability_digest:
                raise CapabilityStoreError("capability_digest_changed")
            event_rule = EVENT_TRANSITIONS.get(event_type)
            if event_rule is None:
                raise CapabilityStoreError("capability_event_unknown")
            allowed_prior, required_new = event_rule
            allowed = actual_state in allowed_prior if isinstance(allowed_prior, set) else actual_state == allowed_prior
            if not allowed or new_state != required_new or new_state not in STORE_TRANSITIONS.get(actual_state, frozenset()):
                raise CapabilityStoreError("capability_event_transition_invalid")
            if event_type == "CAPABILITY_ISSUED":
                capability = issued_capability
            else:
                issuance = next(
                    (item for item in records if item["capability_id"] == capability_id and item["event_type"] == "CAPABILITY_ISSUED"),
                    None,
                )
                if issuance is None:
                    raise CapabilityStoreError("capability_issuance_evidence_missing")
                capability = issuance["details"]["capability"]
            terminal_execution = actual_state == "EXECUTING" and new_state in {
                "COMPLETED", "FAILED", "AMBIGUOUS", "CANCELLED",
            }
            if terminal_execution and attestation_payload is None:
                raise CapabilityStoreError("execution_terminal_attestation_missing")
            if attestation_payload is not None:
                if not terminal_execution or not isinstance(attestation_payload, Mapping):
                    raise CapabilityStoreError("execution_attestation_transition_invalid")
                payload = deepcopy(dict(attestation_payload))
                if "previous_attestation_hash" in payload:
                    raise CapabilityStoreError("execution_attestation_chain_store_owned")
                payload["previous_attestation_hash"] = self._attestation_head(records)
                bound = {"integrity_domain": ATTESTATION_DOMAIN, "payload": payload}
                if not _verify_attestation_payload(
                    payload, capability=capability, capability_id=capability_id,
                    classification=new_state, previous_hash=self._attestation_head(records),
                ):
                    raise CapabilityStoreError("execution_attestation_integrity_invalid")
                record_details["execution_attestation"] = {
                    "payload": payload,
                    "attestation_hash": generate_digest(bound),
                    "integrity_binding": sign_payload(bound),
                }
            current = _parse_time(occurred_at)
            previous_time = _parse_time(records[-1]["occurred_at"]) if records else None
            if current is None or (previous_time is not None and current < previous_time):
                raise CapabilityStoreError("capability_store_clock_rollback")
            body = {
                "record_version": RECORD_VERSION,
                "sequence": len(records) + 1,
                "event_id": generate_digest({
                    "domain": DOMAIN, "capability_id": capability_id,
                    "sequence": len(records) + 1, "event_type": event_type,
                }),
                "event_type": event_type,
                "capability_id": capability_id,
                "prior_state": actual_state,
                "new_state": new_state,
                "occurred_at": occurred_at,
                "capability_digest": capability_digest,
                "details": record_details,
                "previous_record_hash": records[-1]["record_hash"] if records else "GENESIS",
            }
            record_hash = generate_digest(body)
            record = {
                **body,
                "record_hash": record_hash,
                "integrity_binding": sign_payload({"integrity_domain": DOMAIN, "record_hash": record_hash}),
            }
            encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            if len(encoded) > MAX_RECORD_BYTES:
                raise CapabilityStoreError("capability_record_oversized")
            existing = self.path.read_bytes()
            if len(existing) + len(encoded) > MAX_STORE_BYTES:
                raise CapabilityStoreError("capability_store_hard_limit")
            intent = _bound({
                "intent_version": "H7_EXECUTION_CAPABILITY_INTENT_V1",
                "sequence": record["sequence"],
                "record_hash": record_hash,
                "previous_record_hash": record["previous_record_hash"],
                "prior_generation": generation,
            })
            self._atomic_json(self.intent_path, intent)
            self._atomic_bytes(self.path, existing + encoded)
            records.append(record)
            self._write_metadata(records, generation + 1)
            self.intent_path.unlink(missing_ok=True)
            return deepcopy(record)

    def state(self, capability_id: str) -> str | None:
        records, _ = self._load()
        latest = self._latest(records).get(capability_id)
        return str(latest["state"]) if latest else None

    def history(self, capability_id: str) -> list[dict[str, Any]]:
        records, _ = self._load()
        return [deepcopy(item) for item in records if item["capability_id"] == capability_id]

    def previous_attestation_hash(self) -> str:
        records, _ = self._load()
        return self._attestation_head(records)

    def latest_states(self) -> dict[str, dict[str, Any]]:
        records, _ = self._load()
        return deepcopy(self._latest(records))

    def validate(self) -> None:
        self._load()

    def validate_and_recover(self) -> str:
        with self._writer():
            if not self.intent_path.exists():
                self._load()
                return "VALID"
            try:
                intent = loads_strict_json(self.intent_path.read_text("utf-8"))
            except Exception as exc:
                raise CapabilityStoreError("capability_store_intent_corrupted") from exc
            if not _verify_bound(intent):
                raise CapabilityStoreError("capability_store_intent_integrity_invalid")
            payload = intent["payload"]
            if set(payload) != {
                "intent_version", "sequence", "record_hash",
                "previous_record_hash", "prior_generation",
            } or payload.get("intent_version") != "H7_EXECUTION_CAPABILITY_INTENT_V1":
                raise CapabilityStoreError("capability_store_intent_schema_invalid")
            records = self._read_records()
            self._verify_records(records)
            try:
                checkpoint = loads_strict_json(self.checkpoint_path.read_text("utf-8"))
                anchor = loads_strict_json(self.anchor_path.read_text("utf-8"))
            except Exception as exc:
                raise CapabilityStoreError("capability_store_metadata_corrupted") from exc
            if not _verify_bound(checkpoint) or not _verify_bound(anchor):
                raise CapabilityStoreError("capability_store_metadata_integrity_invalid")
            sequence = payload.get("sequence")
            record_hash = payload.get("record_hash")
            ledger_has_new = bool(records and records[-1]["sequence"] == sequence and records[-1]["record_hash"] == record_hash)
            prefix_head = records[-1]["record_hash"] if records else "GENESIS"
            ledger_is_prefix = (
                len(records) + 1 == sequence
                and payload.get("previous_record_hash") == prefix_head
            )
            generation = checkpoint["payload"].get("generation")
            if not isinstance(generation, int):
                raise CapabilityStoreError("capability_store_checkpoint_generation_invalid")
            if generation < 1:
                raise CapabilityStoreError("capability_store_checkpoint_generation_invalid")
            checkpoint_current = dict(checkpoint["payload"]) == self._checkpoint_payload(records, generation)
            anchor_current = dict(anchor["payload"]) == self._anchor_payload(records, generation, checkpoint["integrity_hash"])
            if (
                ledger_is_prefix and checkpoint_current and anchor_current
                and payload.get("prior_generation") == generation
            ):
                self.intent_path.unlink(missing_ok=True)
                return "RECOVERED_INTENT_BEFORE_LEDGER"
            if ledger_has_new:
                prefix = records[:-1]
                if (
                    records[-1].get("previous_record_hash") != payload.get("previous_record_hash")
                    or payload.get("prior_generation") not in {generation, generation - 1}
                ):
                    raise CapabilityStoreError("capability_store_intent_lineage_invalid")
                checkpoint_prefix = dict(checkpoint["payload"]) == self._checkpoint_payload(prefix, generation)
                anchor_prefix = dict(anchor["payload"]) == self._anchor_payload(prefix, generation, checkpoint["integrity_hash"])
                if checkpoint_current and anchor_current:
                    self.intent_path.unlink(missing_ok=True)
                    return "RECOVERED_METADATA_BEFORE_INTENT_CLEANUP"
                if checkpoint_prefix and anchor_prefix:
                    self._write_metadata(records, generation + 1)
                    self.intent_path.unlink(missing_ok=True)
                    return "RECOVERED_LEDGER_BEFORE_METADATA"
                if checkpoint_current:
                    prefix_checkpoint = _bound(self._checkpoint_payload(prefix, generation - 1)) if generation > 1 else None
                    if prefix_checkpoint and dict(anchor["payload"]) == self._anchor_payload(prefix, generation - 1, prefix_checkpoint["integrity_hash"]):
                        self._write_metadata(records, generation)
                        self.intent_path.unlink(missing_ok=True)
                        return "RECOVERED_CHECKPOINT_BEFORE_ANCHOR"
            raise CapabilityStoreError("capability_store_ambiguous_crash_state")
