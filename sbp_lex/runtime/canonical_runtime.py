from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.api.access_control import security_mode
from sbp_lex.audit.pipeline_replay_ledger import PIPELINE_REPLAY_LEDGER
from sbp_lex.connector.recovery import CONNECTOR_RECOVERY
from sbp_lex.persistence.integrity_store import RUNTIME_INTEGRITY_STORE
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.runtime.chronology import CANONICAL_CHRONOLOGY
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS
from sbp_lex.security.pqc import generate_digest


class CanonicalRuntime:
    """Single V1 execution authority for dual-pipeline traversal."""

    def __init__(self) -> None:
        self.runtime_id = "SBP_LEX_V1_CANONICAL_RUNTIME"
        self.started_at = "CANONICAL_RUNTIME_START"
        self.last_result: Dict[str, Any] | None = None
        self.traversal_count = 0

    def status(self) -> Dict[str, Any]:
        chronology_ok, chronology_failures = CANONICAL_CHRONOLOGY.verify()
        events_ok, event_failures = RUNTIME_EVENTS.verify()
        replay_ok, replay_failures = PIPELINE_REPLAY_LEDGER.verify()
        connector_ok, connector_failures = CONNECTOR_RECOVERY.verify()
        persistence_ok, persistence_failures = RUNTIME_INTEGRITY_STORE.verify()
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
        runtime_request_id = request_id or generate_digest({"action": request.get("action"), "payload": request.get("payload", {})})[:24]
        RUNTIME_EVENTS.emit("traversal_started", {"request_id": runtime_request_id, "action": request.get("action")})
        state = run_dual_pipeline(deepcopy(dict(request)), deepcopy(dict(pre_context_signals)) if pre_context_signals else None)
        self.traversal_count += 1
        self.last_result = deepcopy(state)
        replay_entry = PIPELINE_REPLAY_LEDGER.append(state)
        persistence_record = RUNTIME_INTEGRITY_STORE.append_state_summary(state)
        RUNTIME_EVENTS.emit(
            "traversal_completed",
            {
                "request_id": runtime_request_id,
                "request_fingerprint": state.get("request_fingerprint"),
                "decision": state.get("decision"),
                "execution_result": state.get("execution_result"),
                "pipeline_mode": state.get("pipeline_mode"),
                "audit_hash": state.get("audit_hash"),
                "replay_ledger_hash": replay_entry.get("ledger_hash"),
                "persistence_record_hash": persistence_record.get("record_hash"),
            },
        )
        return {
            "runtime": self.runtime_id,
            "request_id": runtime_request_id,
            "state": state,
            "replay_ledger_entry": replay_entry,
            "persistence_record": persistence_record,
        }

    def replay(
        self,
        request: Mapping[str, Any],
        *,
        replay_count: int = 2,
        pre_context_signals: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        RUNTIME_EVENTS.emit("replay_started", {"action": request.get("action"), "replay_count": replay_count})
        result = run_replay_check(request=request, pre_context_signals=pre_context_signals, replay_count=replay_count)
        RUNTIME_EVENTS.emit("replay_completed", {"matched": result.get("matched"), "replay_hash": result.get("replay_hash")})
        return result


CANONICAL_RUNTIME = CanonicalRuntime()
