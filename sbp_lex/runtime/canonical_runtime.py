from __future__ import annotations

from copy import deepcopy
from threading import RLock
from typing import Any, Dict, Mapping

from sbp_lex.api.access_control import security_mode
from sbp_lex.audit.pipeline_replay_ledger import PIPELINE_REPLAY_LEDGER
from sbp_lex.connector.recovery import CONNECTOR_RECOVERY
from sbp_lex.execution.capability import CANONICAL_RUNTIME_ID, build_execution_traversal_authority
from sbp_lex.persistence.integrity_store import RUNTIME_INTEGRITY_STORE
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.runtime.chronology import CANONICAL_CHRONOLOGY
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS
from sbp_lex.runtime.measured_startup import (
    default_measured_startup_service,
    ensure_measured_startup,
)
from sbp_lex.security.pqc import generate_digest


class CanonicalRuntime:
    """Single V1 execution authority for dual-pipeline traversal."""

    def __init__(self) -> None:
        self.runtime_id = CANONICAL_RUNTIME_ID
        self.started_at = "CANONICAL_RUNTIME_START"
        self.last_result: Dict[str, Any] | None = None
        self.traversal_count = 0
        self._authority_lock = RLock()
        self._pending_execution_authorities: Dict[str, Dict[str, Any]] = {}

    def status(self) -> Dict[str, Any]:
        chronology_ok, chronology_failures = CANONICAL_CHRONOLOGY.verify()
        events_ok, event_failures = RUNTIME_EVENTS.verify()
        replay_ok, replay_failures = PIPELINE_REPLAY_LEDGER.verify()
        connector_ok, connector_failures = CONNECTOR_RECOVERY.verify()
        persistence_ok, persistence_failures = RUNTIME_INTEGRITY_STORE.verify()
        measurement = default_measured_startup_service().status()
        return {
            "runtime_id": self.runtime_id,
            "api_security_mode": security_mode(),
            "started_at": self.started_at,
            "traversal_count": self.traversal_count,
            "chronology_valid": chronology_ok,
            "chronology_failures": chronology_failures,
            "event_bus_valid": events_ok,
            "event_bus_failures": event_failures,
            "replay_ledger_valid": replay_ok,
            "replay_ledger_failures": replay_failures,
            "connector_recovery_valid": connector_ok,
            "connector_recovery_failures": connector_failures,
            "persistence_valid": persistence_ok,
            "persistence_failures": persistence_failures,
            "measured_startup_status": measurement["status"],
            "measured_runtime_identity": measurement["runtime_identity"],
            "approved_runtime_baseline": measurement["approved_baseline_identifier"],
            "runtime_measurement_digest": measurement["measurement_digest"],
            "last_decision": self.last_result.get("decision") if self.last_result else None,
            "last_execution_result": self.last_result.get("execution_result") if self.last_result else None,
            "last_audit_hash": self.last_result.get("audit_hash") if self.last_result else None,
        }

    def traverse(
        self,
        request: Mapping[str, Any],
        *,
        request_id: str | None = None,
        pre_context_signals: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        ensure_measured_startup()
        runtime_request_id = request_id or generate_digest({"action": request.get("action"), "payload": request.get("payload", {})})[:24]
        traversal_started_event = RUNTIME_EVENTS.emit(
            "traversal_started", {"request_id": runtime_request_id, "action": request.get("action")},
        )
        state = run_dual_pipeline(deepcopy(dict(request)), deepcopy(dict(pre_context_signals)) if pre_context_signals else None)
        with self._authority_lock:
            self.traversal_count += 1
            self.last_result = deepcopy(state)
            replay_entry = PIPELINE_REPLAY_LEDGER.append(state)
            persistence_record = RUNTIME_INTEGRITY_STORE.append_state_summary(state)
            traversal_completed_event = RUNTIME_EVENTS.emit(
                "traversal_completed",
                {
                    "request_id": runtime_request_id,
                    "request_fingerprint": state.get("request_fingerprint"),
                    "decision": state.get("decision"),
                    "execution_result": state.get("execution_result"),
                    "pipeline_mode": state.get("pipeline_mode"),
                    "audit_hash": state.get("audit_hash"),
                    "traversal_started_event_hash": traversal_started_event.get("event_hash"),
                    "replay_ledger_hash": replay_entry.get("ledger_hash"),
                    "persistence_record_hash": persistence_record.get("record_hash"),
                },
            )
            execution_authority = None
            if state.get("decision") == "ALLOW" and state.get("execution_result") == "EXECUTE":
                execution_authority = build_execution_traversal_authority(
                    state, runtime_id=self.runtime_id, request_id=runtime_request_id,
                    traversal_started_event=traversal_started_event,
                    traversal_completed_event=traversal_completed_event,
                )
                if len(self._pending_execution_authorities) >= 1024:
                    oldest = next(iter(self._pending_execution_authorities))
                    self._pending_execution_authorities.pop(oldest, None)
                self._pending_execution_authorities[execution_authority["authority_digest"]] = {
                    "authority": deepcopy(execution_authority),
                    "state": deepcopy(state),
                }
        return {
            "runtime": self.runtime_id,
            "request_id": runtime_request_id,
            "state": state,
            "execution_authority_reference": execution_authority.get("authority_digest") if execution_authority else None,
            "replay_ledger_entry": replay_entry,
            "persistence_record": persistence_record,
        }

    def issue_execution_capability(
        self, reference: str, *, execution_service: Any,
        specification_id: str, parameters: Mapping[str, Any] | str,
        **temporal_policy: Any,
    ) -> Dict[str, Any]:
        if not isinstance(reference, str) or not reference:
            raise ValueError("execution_authority_reference_invalid")
        with self._authority_lock:
            pending = self._pending_execution_authorities.pop(reference, None)
        if pending is None:
            raise ValueError("execution_authority_reference_unavailable")
        return execution_service.issue(
            pending["state"], traversal_authority=pending["authority"],
            specification_id=specification_id, parameters=parameters,
            **temporal_policy,
        )

    def replay(
        self,
        request: Mapping[str, Any],
        *,
        replay_count: int = 2,
        pre_context_signals: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        ensure_measured_startup()
        with self._authority_lock:
            RUNTIME_EVENTS.emit("replay_started", {"action": request.get("action"), "replay_count": replay_count})
            result = run_replay_check(request=request, pre_context_signals=pre_context_signals, replay_count=replay_count)
            RUNTIME_EVENTS.emit("replay_completed", {"matched": result.get("matched"), "replay_hash": result.get("replay_hash")})
        return result


CANONICAL_RUNTIME = CanonicalRuntime()
