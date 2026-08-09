from __future__ import annotations

import json
import os
import uuid
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping

from sbp_lex.recovery.common import atomic_json, sha256_bytes
from sbp_lex.runtime.resource_budgets import ResourceBudgetPolicy
from sbp_lex.security.pqc import generate_digest


LIFECYCLE_VERSION = "PASS8_DESKTOP_V1_OPERATIONAL_LIFECYCLE_V1"
OWNERSHIP_VERSION = "PASS8_DESKTOP_V1_RUNTIME_OWNERSHIP_V1"
RECOVERY_RECORD_VERSION = "PASS8_DESKTOP_V1_RECOVERY_RECORD_V1"

NOT_STARTED = "NOT_STARTED"
STARTING = "STARTING"
STARTUP_VALIDATION = "STARTUP_VALIDATION"
READY = "READY"
PROCESSING = "PROCESSING"
DRAINING = "DRAINING"
STOPPING = "STOPPING"
STOPPED = "STOPPED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
RECOVERY_VALIDATION = "RECOVERY_VALIDATION"
QUARANTINED = "QUARANTINED"
FAILED_CLOSED = "FAILED_CLOSED"

LIFECYCLE_STATES = frozenset({
    NOT_STARTED, STARTING, STARTUP_VALIDATION, READY, PROCESSING,
    DRAINING, STOPPING, STOPPED, RECOVERY_REQUIRED,
    RECOVERY_VALIDATION, QUARANTINED, FAILED_CLOSED,
})

_ALLOWED_TRANSITIONS = {
    NOT_STARTED: {STARTING, FAILED_CLOSED},
    STARTING: {STARTUP_VALIDATION, FAILED_CLOSED},
    STARTUP_VALIDATION: {READY, FAILED_CLOSED, QUARANTINED},
    READY: {PROCESSING, DRAINING, STOPPING, FAILED_CLOSED, RECOVERY_REQUIRED},
    PROCESSING: {READY, DRAINING, FAILED_CLOSED, RECOVERY_REQUIRED},
    DRAINING: {STOPPING, FAILED_CLOSED},
    STOPPING: {STOPPED, FAILED_CLOSED},
    STOPPED: {STARTING, RECOVERY_REQUIRED},
    RECOVERY_REQUIRED: {RECOVERY_VALIDATION, QUARANTINED, FAILED_CLOSED},
    RECOVERY_VALIDATION: {READY, QUARANTINED, FAILED_CLOSED},
    QUARANTINED: set(),
    FAILED_CLOSED: {RECOVERY_REQUIRED, QUARANTINED},
}


class OperationalResilienceError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _measurement_valid(measurement: Mapping[str, Any]) -> bool:
    return (
        measurement.get("status") == "MEASURED_STARTUP_APPROVED"
        and isinstance(measurement.get("runtime_identity"), str)
        and len(str(measurement.get("runtime_identity"))) == 64
        and isinstance(measurement.get("approved_baseline_identifier"), str)
        and bool(measurement.get("approved_baseline_identifier"))
        and isinstance(measurement.get("measurement_digest"), str)
        and len(str(measurement.get("measurement_digest"))) == 64
        and isinstance(measurement.get("startup_attestation_digest"), str)
        and len(str(measurement.get("startup_attestation_digest"))) == 64
        and isinstance(measurement.get("startup_sequence"), int)
        and not isinstance(measurement.get("startup_sequence"), bool)
        and int(measurement.get("startup_sequence", 0)) > 0
    )


class RuntimeLifecycleController:
    """Operational evidence state; never a Governance or execution authority."""

    def __init__(
        self,
        runtime_id: str,
        *,
        event_sink: Callable[[str, Mapping[str, Any]], Any] | None = None,
        budgets: ResourceBudgetPolicy | None = None,
    ) -> None:
        if not isinstance(runtime_id, str) or not runtime_id:
            raise ValueError("runtime_id_invalid")
        self.runtime_id = runtime_id
        self.budgets = budgets or ResourceBudgetPolicy()
        self._event_sink = event_sink
        self._lock = RLock()
        self._state = NOT_STARTED
        self._sequence = 0
        self._accepting_work = False
        self._shutdown_requested = False
        self._active: dict[str, str] = {}
        self._pending_capabilities: set[str] = set()
        self._records: list[dict[str, Any]] = []
        self._crash_count = 0
        self._restart_count = 0
        self._recovery_count = 0
        self._measurement: dict[str, Any] | None = None

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def _record(
        self,
        event_type: str,
        *,
        reason: str,
        request_identifier: str | None = None,
        stage: str | None = None,
    ) -> dict[str, Any]:
        self._sequence += 1
        payload = {
            "lifecycle_version": LIFECYCLE_VERSION,
            "sequence": self._sequence,
            "runtime_id": self.runtime_id,
            "lifecycle_state": self._state,
            "event_type": event_type,
            "reason": reason,
            "request_identifier": request_identifier,
            "stage": stage,
            "active_traversal_count": len(self._active),
            "pending_capability_count": len(self._pending_capabilities),
            "accepting_work": self._accepting_work,
            "authority_granted": False,
            "resume_authority": False,
        }
        record = {**payload, "record_digest": generate_digest(payload)}
        self._records.append(record)
        if len(self._records) > self.budgets.maximum_failure_records:
            self._records = self._records[-self.budgets.maximum_failure_records:]
        if self._event_sink is not None:
            self._event_sink(event_type, payload)
        return deepcopy(record)

    def _transition(self, target: str, *, event_type: str, reason: str) -> dict[str, Any]:
        if target not in LIFECYCLE_STATES:
            raise OperationalResilienceError("lifecycle_target_unknown")
        if target != self._state and target not in _ALLOWED_TRANSITIONS[self._state]:
            raise OperationalResilienceError(
                f"lifecycle_transition_invalid:{self._state}:{target}"
            )
        self._state = target
        return self._record(event_type, reason=reason)

    def start(self, measurement: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._state not in {NOT_STARTED, STOPPED}:
                raise OperationalResilienceError("runtime_already_started")
            if self._state == STOPPED:
                self._restart_count += 1
                if self._restart_count > self.budgets.maximum_restart_attempts:
                    self._transition(
                        QUARANTINED,
                        event_type="restart_limit_reached",
                        reason="restart_attempt_limit_reached",
                    )
                    raise OperationalResilienceError("restart_attempt_limit_reached")
            self._transition(STARTING, event_type="startup_requested", reason="startup_requested")
            self._transition(
                STARTUP_VALIDATION,
                event_type="startup_validation_started",
                reason="measured_startup_required",
            )
            if not isinstance(measurement, Mapping) or not _measurement_valid(measurement):
                self._accepting_work = False
                self._measurement = None
                self._transition(
                    FAILED_CLOSED,
                    event_type="startup_rejected",
                    reason="measured_startup_invalid",
                )
                raise OperationalResilienceError("measured_startup_invalid")
            self._measurement = deepcopy(dict(measurement))
            self._accepting_work = True
            self._shutdown_requested = False
            self._transition(
                READY,
                event_type="startup_validated",
                reason="measured_startup_approved",
            )
            return self.status()

    def begin_traversal(self, request_identifier: str, *, stage: str = "ingress") -> dict[str, Any]:
        with self._lock:
            if not self._accepting_work or self._state not in {READY, PROCESSING}:
                raise OperationalResilienceError("runtime_not_accepting_work")
            if request_identifier in self._active:
                raise OperationalResilienceError("duplicate_active_traversal_denied")
            if len(self._active) >= self.budgets.maximum_simultaneous_local_requests:
                self._record(
                    "queue_saturation",
                    reason="simultaneous_request_limit_reached",
                    request_identifier=request_identifier,
                    stage=stage,
                )
                raise OperationalResilienceError("simultaneous_request_limit_reached")
            self._active[request_identifier] = stage
            if self._state == READY:
                self._transition(PROCESSING, event_type="runtime_processing", reason="traversal_started")
            return self._record(
                "traversal_supervision_started",
                reason="bounded_processing",
                request_identifier=request_identifier,
                stage=stage,
            )

    def advance_traversal(self, request_identifier: str, stage: str) -> dict[str, Any]:
        with self._lock:
            if request_identifier not in self._active:
                raise OperationalResilienceError("active_traversal_missing")
            self._active[request_identifier] = stage
            return self._record(
                "traversal_stage_observed",
                reason="stage_progress",
                request_identifier=request_identifier,
                stage=stage,
            )

    def complete_traversal(self, request_identifier: str, *, result: str) -> dict[str, Any]:
        with self._lock:
            stage = self._active.pop(request_identifier, None)
            if stage is None:
                raise OperationalResilienceError("active_traversal_missing")
            record = self._record(
                "traversal_supervision_completed",
                reason=f"terminal_result:{result}",
                request_identifier=request_identifier,
                stage=stage,
            )
            if not self._active:
                if self._state == DRAINING:
                    self._transition(STOPPING, event_type="runtime_stopping", reason="drain_complete")
                    self._transition(STOPPED, event_type="shutdown_complete", reason="clean_shutdown")
                elif self._state == PROCESSING:
                    self._transition(READY, event_type="runtime_ready", reason="traversal_complete")
            return record

    def register_pending_capability(self, capability_identifier: str) -> None:
        with self._lock:
            if not self.can_issue_capability():
                raise OperationalResilienceError("capability_issuance_blocked_by_lifecycle")
            if capability_identifier in self._pending_capabilities:
                raise OperationalResilienceError("duplicate_capability_reference")
            self._pending_capabilities.add(capability_identifier)

    def consume_pending_capability(self, capability_identifier: str) -> bool:
        with self._lock:
            if not self.can_issue_capability() or capability_identifier not in self._pending_capabilities:
                return False
            self._pending_capabilities.remove(capability_identifier)
            return True

    def can_issue_capability(self) -> bool:
        return (
            self._accepting_work
            and not self._shutdown_requested
            and self._state in {READY, PROCESSING}
        )

    def request_shutdown(self, *, invalidate_active: bool = False) -> dict[str, Any]:
        with self._lock:
            if self._state == STOPPED:
                return self._record("shutdown_complete", reason="shutdown_already_complete")
            if self._state in {NOT_STARTED, QUARANTINED}:
                self._accepting_work = False
                if self._state == NOT_STARTED:
                    self._transition(FAILED_CLOSED, event_type="shutdown_requested", reason="runtime_not_started")
                return self.status()
            self._accepting_work = False
            self._shutdown_requested = True
            self._pending_capabilities.clear()
            self._record("shutdown_requested", reason="operator_shutdown")
            if self._active and not invalidate_active:
                if self._state != DRAINING:
                    self._transition(DRAINING, event_type="runtime_draining", reason="active_work_draining")
                return self.status()
            if self._active:
                for request_identifier, stage in sorted(self._active.items()):
                    self._record(
                        "traversal_invalidated",
                        reason="shutdown_incomplete_work_invalidated",
                        request_identifier=request_identifier,
                        stage=stage,
                    )
                self._active.clear()
            if self._state not in {STOPPING, STOPPED}:
                if self._state not in {DRAINING, READY, PROCESSING, FAILED_CLOSED}:
                    raise OperationalResilienceError("shutdown_state_invalid")
                if self._state == FAILED_CLOSED:
                    self._transition(RECOVERY_REQUIRED, event_type="recovery_required", reason="shutdown_after_failure")
                    return self.status()
                if self._state != DRAINING:
                    self._transition(DRAINING, event_type="runtime_draining", reason="no_new_work")
                self._transition(STOPPING, event_type="runtime_stopping", reason="shutdown_flush_complete")
                self._transition(STOPPED, event_type="shutdown_complete", reason="clean_shutdown")
            return self.status()

    def unexpected_termination(self, reason: str) -> dict[str, Any]:
        with self._lock:
            self._accepting_work = False
            self._shutdown_requested = True
            self._active.clear()
            self._pending_capabilities.clear()
            self._crash_count += 1
            if self._crash_count > self.budgets.maximum_restart_attempts:
                if self._state != FAILED_CLOSED:
                    self._transition(
                        FAILED_CLOSED,
                        event_type="unexpected_termination",
                        reason=reason,
                    )
                self._transition(
                    QUARANTINED,
                    event_type="restart_limit_reached",
                    reason="crash_loop_bounded",
                )
            else:
                if self._state != FAILED_CLOSED:
                    self._transition(
                        FAILED_CLOSED,
                        event_type="unexpected_termination",
                        reason=reason,
                    )
                self._transition(
                    RECOVERY_REQUIRED,
                    event_type="recovery_required",
                    reason="unexpected_termination",
                )
            return self.status()

    def begin_recovery(self) -> dict[str, Any]:
        with self._lock:
            if self._state != RECOVERY_REQUIRED:
                raise OperationalResilienceError("recovery_not_required")
            self._recovery_count += 1
            if self._recovery_count > self.budgets.maximum_recovery_attempts:
                self._transition(
                    QUARANTINED,
                    event_type="recovery_rejected",
                    reason="recovery_attempt_limit_reached",
                )
                raise OperationalResilienceError("recovery_attempt_limit_reached")
            self._transition(
                RECOVERY_VALIDATION,
                event_type="recovery_initiated",
                reason="full_revalidation_required",
            )
            return self.status()

    def complete_recovery(
        self,
        measurement: Mapping[str, Any],
        recovery_record: Mapping[str, Any],
    ) -> dict[str, Any]:
        with self._lock:
            if self._state != RECOVERY_VALIDATION:
                raise OperationalResilienceError("recovery_validation_not_active")
            assessment = assess_recovery_record(
                recovery_record,
                current_runtime_identity=str(measurement.get("runtime_identity", "")),
            )
            if assessment["required_action"] == "MEASURED_STARTUP_REVALIDATION_REQUIRED":
                self._transition(
                    FAILED_CLOSED,
                    event_type="recovery_rejected",
                    reason="runtime_identity_mismatch",
                )
                raise OperationalResilienceError("runtime_identity_mismatch")
            if not _measurement_valid(measurement) or assessment["quarantine_required"]:
                self._transition(
                    QUARANTINED,
                    event_type="recovery_rejected",
                    reason=str(assessment["reason"]),
                )
                raise OperationalResilienceError(str(assessment["reason"]))
            self._measurement = deepcopy(dict(measurement))
            self._accepting_work = True
            self._shutdown_requested = False
            self._active.clear()
            self._pending_capabilities.clear()
            self._transition(
                READY,
                event_type="recovery_complete",
                reason=str(assessment["required_action"]),
            )
            return {**self.status(), "recovery_assessment": assessment}

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "lifecycle_version": LIFECYCLE_VERSION,
                "runtime_id": self.runtime_id,
                "lifecycle_state": self._state,
                "accepting_work": self._accepting_work,
                "shutdown_requested": self._shutdown_requested,
                "active_traversal_count": len(self._active),
                "active_stages": deepcopy(self._active),
                "pending_capability_count": len(self._pending_capabilities),
                "crash_count": self._crash_count,
                "restart_count": self._restart_count,
                "recovery_count": self._recovery_count,
                "runtime_identity": (
                    self._measurement.get("runtime_identity")
                    if self._measurement is not None
                    else None
                ),
                "authority_granted": False,
                "resume_authority": False,
                "record_count": len(self._records),
            }

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(self._records)


def build_recovery_record(
    *,
    request_fingerprint: str,
    runtime_identity: str,
    repository_commit: str,
    stage: str,
    decision: str | None,
    execution_result: str | None,
    effect_status: str,
    state_hash: str | None,
) -> dict[str, Any]:
    payload = {
        "record_version": RECOVERY_RECORD_VERSION,
        "request_fingerprint": request_fingerprint,
        "runtime_identity": runtime_identity,
        "repository_commit": repository_commit,
        "stage": stage,
        "decision": decision,
        "execution_result": execution_result,
        "effect_status": effect_status,
        "state_hash": state_hash,
        "resume_authority": False,
    }
    return {**payload, "record_digest": generate_digest(payload)}


def assess_recovery_record(
    value: Mapping[str, Any],
    *,
    current_runtime_identity: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _recovery_assessment("record_not_mapping", "QUARANTINE", True)
    required = {
        "record_version", "request_fingerprint", "runtime_identity",
        "repository_commit", "stage", "decision", "execution_result",
        "effect_status", "state_hash", "resume_authority", "record_digest",
    }
    if set(value) != required or value.get("record_version") != RECOVERY_RECORD_VERSION:
        return _recovery_assessment("record_schema_invalid", "QUARANTINE", True)
    payload = {key: value[key] for key in required if key != "record_digest"}
    if value.get("record_digest") != generate_digest(payload):
        return _recovery_assessment("record_digest_invalid", "QUARANTINE", True)
    if value.get("resume_authority") is not False:
        return _recovery_assessment("resume_authority_forbidden", "QUARANTINE", True)
    if value.get("runtime_identity") != current_runtime_identity:
        return _recovery_assessment(
            "runtime_identity_mismatch",
            "MEASURED_STARTUP_REVALIDATION_REQUIRED",
            False,
        )
    stage = value.get("stage")
    decision = value.get("decision")
    effect = value.get("effect_status")
    if stage in {"adapter", "eie", "skg_dtn", "bridge", "hard_entry_pending"}:
        return _recovery_assessment("no_governed_state", "FULL_INGRESS_REQUIRED", False)
    if decision in {"DENY", "ESCALATE"}:
        return _recovery_assessment("terminal_decision_conserved", "FULL_REENTRY_REQUIRED", False)
    if stage in {
        "state_construction", "collective_attach", "root_of_trust",
        "procedural_truth", "classification", "licensing", "governance_pending",
    }:
        return _recovery_assessment("state_not_current", "FULL_PATH_REVALIDATION_REQUIRED", False)
    if stage in {"domain_failed", "aurion_failed"}:
        return _recovery_assessment("candidate_rejection_conserved", "BOUNDED_NEW_CANDIDATE_REENTRY", False)
    if stage == "execution_gate_converged" and effect == "NOT_ATTEMPTED":
        return _recovery_assessment("capability_uncertain", "CAPABILITY_INVALIDATE_AND_REVALIDATE", False)
    if stage == "synthetic_effect_attempt" or effect in {"UNKNOWN", "AMBIGUOUS", "PARTIAL"}:
        return _recovery_assessment("effect_status_uncertain", "RECONCILIATION_REQUIRED_NO_RETRY", False)
    if stage == "audit_finalisation":
        return _recovery_assessment("terminal_evidence_incomplete", "EVIDENCE_REPAIR_NON_EXECUTING", False)
    if stage == "terminal_complete":
        return _recovery_assessment("terminal_history_read_only", "NO_AUTOMATIC_RESUME", False)
    return _recovery_assessment("stage_unknown", "QUARANTINE", True)


def _recovery_assessment(reason: str, action: str, quarantine: bool) -> dict[str, Any]:
    return {
        "valid_for_recovery_evidence": not quarantine,
        "quarantine_required": quarantine,
        "reason": reason,
        "required_action": action,
        "resume_authority": False,
        "automatic_effect_retry": False,
        "authority_granted": False,
    }


def persist_recovery_record(
    path: Path,
    record: Mapping[str, Any],
    *,
    allowed_root: Path,
) -> Path:
    root = allowed_root.resolve()
    target = path.resolve(strict=False)
    if not target.is_relative_to(root) or target.suffix.lower() != ".json":
        raise OperationalResilienceError("recovery_record_path_invalid")
    assessment = assess_recovery_record(
        record,
        current_runtime_identity=str(record.get("runtime_identity", "")),
    )
    if assessment["quarantine_required"]:
        raise OperationalResilienceError(str(assessment["reason"]))
    atomic_json(target, dict(record))
    return target


def quarantine_recovery_record(
    path: Path,
    *,
    allowed_root: Path,
    quarantine_root: Path,
) -> dict[str, Any]:
    root = allowed_root.resolve()
    source = path.resolve(strict=True)
    destination_root = quarantine_root.resolve(strict=False)
    if not source.is_relative_to(root) or not destination_root.is_relative_to(root):
        raise OperationalResilienceError("quarantine_path_invalid")
    raw = source.read_bytes()
    digest = sha256_bytes(raw)
    destination_root.mkdir(parents=True, exist_ok=True)
    destination = destination_root / f"{source.stem}.quarantined.{digest}.json"
    if destination.exists():
        raise OperationalResilienceError("quarantine_record_exists")
    os.replace(source, destination)
    return {
        "status": "QUARANTINED",
        "source_digest": digest,
        "size_bytes": len(raw),
        "quarantine_path": str(destination),
        "authority_granted": False,
    }


def _default_process_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class RuntimeOwnershipManager:
    """Exclusive local process ownership with validated stale-lock recovery."""

    def __init__(
        self,
        lock_path: Path,
        *,
        allowed_root: Path,
        process_exists: Callable[[int], bool] = _default_process_exists,
    ) -> None:
        self.allowed_root = allowed_root.resolve()
        self.lock_path = lock_path.resolve(strict=False)
        if not self.lock_path.is_relative_to(self.allowed_root) or self.lock_path.suffix != ".json":
            raise OperationalResilienceError("runtime_lock_path_invalid")
        self._process_exists = process_exists
        self._owner_token: str | None = None

    def _read(self) -> dict[str, Any]:
        try:
            value = json.loads(self.lock_path.read_text("utf-8"))
        except Exception as exc:
            raise OperationalResilienceError("runtime_lock_corrupt") from exc
        if not isinstance(value, dict) or set(value) != {
            "ownership_version", "runtime_id", "runtime_identity",
            "repository_commit", "pid", "owner_token", "record_digest",
        }:
            raise OperationalResilienceError("runtime_lock_schema_invalid")
        payload = {key: item for key, item in value.items() if key != "record_digest"}
        if value.get("ownership_version") != OWNERSHIP_VERSION or value.get("record_digest") != generate_digest(payload):
            raise OperationalResilienceError("runtime_lock_integrity_invalid")
        return value

    def claim(
        self,
        *,
        runtime_id: str,
        runtime_identity: str,
        repository_commit: str,
        pid: int | None = None,
    ) -> dict[str, Any]:
        self.allowed_root.mkdir(parents=True, exist_ok=True)
        selected_pid = os.getpid() if pid is None else pid
        stale_record: dict[str, Any] | None = None
        if self.lock_path.exists():
            existing = self._read()
            if self._process_exists(int(existing["pid"])):
                raise OperationalResilienceError("duplicate_runtime_ownership")
            stale_digest = str(existing["record_digest"])
            stale_path = self.lock_path.with_name(
                f"{self.lock_path.stem}.stale.{stale_digest}.json"
            )
            if stale_path.exists():
                raise OperationalResilienceError("stale_runtime_lock_already_preserved")
            os.replace(self.lock_path, stale_path)
            stale_record = {**existing, "stale_lock_path": str(stale_path)}
        owner_token = uuid.uuid4().hex
        payload = {
            "ownership_version": OWNERSHIP_VERSION,
            "runtime_id": runtime_id,
            "runtime_identity": runtime_identity,
            "repository_commit": repository_commit,
            "pid": selected_pid,
            "owner_token": owner_token,
        }
        record = {**payload, "record_digest": generate_digest(payload)}
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(record, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            raise OperationalResilienceError("duplicate_runtime_ownership") from exc
        self._owner_token = owner_token
        return {
            "status": "RUNTIME_OWNERSHIP_CLAIMED",
            "record": deepcopy(record),
            "stale_owner_recovered": stale_record is not None,
            "stale_record": deepcopy(stale_record),
            "authority_granted": False,
        }

    def release(self) -> dict[str, Any]:
        if self._owner_token is None:
            raise OperationalResilienceError("runtime_ownership_not_held")
        existing = self._read()
        if existing.get("owner_token") != self._owner_token:
            raise OperationalResilienceError("runtime_ownership_token_mismatch")
        os.unlink(self.lock_path)
        self._owner_token = None
        return {"status": "RUNTIME_OWNERSHIP_RELEASED", "authority_granted": False}


class SupervisedCanonicalRuntime:
    """Lifecycle wrapper around the existing canonical runtime authority."""

    def __init__(self, runtime: Any, lifecycle: RuntimeLifecycleController) -> None:
        self.runtime = runtime
        self.lifecycle = lifecycle

    def traverse(self, request: Mapping[str, Any], *, request_id: str, **kwargs: Any) -> Any:
        self.lifecycle.begin_traversal(request_id)
        try:
            result = self.runtime.traverse(request, request_id=request_id, **kwargs)
        except Exception:
            self.lifecycle.unexpected_termination("unhandled_traversal_exception")
            raise
        terminal = result.get("state", {}) if isinstance(result, Mapping) else {}
        self.lifecycle.complete_traversal(
            request_id,
            result=f"{terminal.get('decision')}:{terminal.get('execution_result')}",
        )
        return result

    def issue_execution_capability(self, *args: Any, **kwargs: Any) -> Any:
        if not self.lifecycle.can_issue_capability():
            raise OperationalResilienceError("capability_issuance_blocked_by_lifecycle")
        return self.runtime.issue_execution_capability(*args, **kwargs)

    def replay(self, *args: Any, **kwargs: Any) -> Any:
        if self.lifecycle.state not in {READY, PROCESSING}:
            raise OperationalResilienceError("replay_blocked_by_lifecycle")
        return self.runtime.replay(*args, **kwargs)
