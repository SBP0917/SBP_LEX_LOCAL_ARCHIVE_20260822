from __future__ import annotations

from copy import deepcopy
from threading import RLock
from typing import Any, Dict, Mapping

from sbp_lex.api.access_control import security_mode
from sbp_lex.audit.pipeline_replay_ledger import PIPELINE_REPLAY_LEDGER
from sbp_lex.connector.recovery import CONNECTOR_RECOVERY
from sbp_lex.execution.capability import (
    CANONICAL_RUNTIME_ID,
    MEASURED_STARTUP_BINDING_FIELDS,
    ExecutionIntegrityService,
    build_execution_traversal_authority,
    verify_capability,
    verify_execution_traversal_authority,
)
from sbp_lex.persistence.integrity_store import RUNTIME_INTEGRITY_STORE
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.hard_ingress import adapt_external_request
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.runtime.chronology import CANONICAL_CHRONOLOGY
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS
from sbp_lex.runtime.measured_startup import (
    default_measured_startup_service,
    ensure_measured_startup,
)
from sbp_lex.runtime.terminal_custody import durable_custody_bindings
from sbp_lex.runtime.traversal_receipt import (
    OPERATIONAL_TRAVERSAL,
    build_traversal_receipt,
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
        self._active_traversals: set[str] = set()

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
            "startup_attestation_digest": measurement[
                "startup_attestation_digest"
            ],
            "measured_startup_sequence": measurement["startup_sequence"],
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
        active_key = runtime_request_id
        with self._authority_lock:
            if active_key in self._active_traversals:
                raise ValueError("duplicate_active_traversal_denied")
            self._active_traversals.add(active_key)
        try:
            measurement = ensure_measured_startup()
            adapter_result, _ = adapt_external_request(request)
            request_fingerprint = (
                adapter_result.request_fingerprint
                if adapter_result is not None
                else generate_digest(dict(request))
            )
            traversal_started_event = RUNTIME_EVENTS.emit(
                "traversal_started",
                {
                    "request_id": runtime_request_id,
                    "request_fingerprint": request_fingerprint,
                    "action": request.get("action"),
                    **{
                        field: measurement[field]
                        for field in MEASURED_STARTUP_BINDING_FIELDS
                    },
                },
            )
            runtime_traversal_receipt = build_traversal_receipt(
                purpose=OPERATIONAL_TRAVERSAL,
                request_fingerprint=request_fingerprint,
                measurement=measurement,
                traversal_started_event=traversal_started_event,
                request_id=runtime_request_id,
                action=str(request.get("action", "")),
                runtime_id=self.runtime_id,
            )
            state = run_dual_pipeline(
                deepcopy(dict(request)),
                deepcopy(dict(pre_context_signals))
                if pre_context_signals
                else None,
                runtime_traversal_receipt=runtime_traversal_receipt,
                runtime_receipt_purpose=OPERATIONAL_TRAVERSAL,
            )
            custody_bindings = durable_custody_bindings(
                state, require=True
            )
            if custody_bindings is None:  # pragma: no cover - require=True
                raise RuntimeError("terminal_custody_bindings_required")
            with self._authority_lock:
                replay_entry = PIPELINE_REPLAY_LEDGER.append(state)
                if any(
                    replay_entry.get(field) != expected
                    for field, expected in custody_bindings.items()
                ):
                    raise RuntimeError(
                        "replay_ledger_terminal_custody_mismatch"
                    )
                replay_ok, replay_failures = PIPELINE_REPLAY_LEDGER.verify()
                if not replay_ok:
                    raise RuntimeError(
                        "replay_ledger_integrity_invalid:"
                        + ",".join(replay_failures)
                    )
                persistence_record = RUNTIME_INTEGRITY_STORE.append_state_summary(
                    state
                )
                if any(
                    persistence_record.get(field) != expected
                    for field, expected in custody_bindings.items()
                ):
                    raise RuntimeError(
                        "persistence_terminal_custody_mismatch"
                    )
                persistence_ok, persistence_failures = (
                    RUNTIME_INTEGRITY_STORE.verify()
                )
                if not persistence_ok:
                    raise RuntimeError(
                        "persistence_integrity_invalid:"
                        + ",".join(persistence_failures)
                    )
                traversal_completed_event = RUNTIME_EVENTS.emit(
                    "traversal_completed",
                    {
                        "request_id": runtime_request_id,
                        "request_fingerprint": state.get(
                            "request_fingerprint"
                        ),
                        "decision": state.get("decision"),
                        "execution_result": state.get("execution_result"),
                        "pipeline_mode": state.get("pipeline_mode"),
                        "audit_hash": state.get("audit_hash"),
                        "traversal_started_event_hash": (
                            traversal_started_event.get("event_hash")
                        ),
                        "replay_ledger_hash": replay_entry.get("ledger_hash"),
                        "persistence_record_hash": persistence_record.get(
                            "record_hash"
                        ),
                        **custody_bindings,
                    },
                )
                execution_authority = None
                if (
                    state.get("decision") == "ALLOW"
                    and state.get("execution_result") == "EXECUTE"
                ):
                    execution_authority = build_execution_traversal_authority(
                        state,
                        runtime_id=self.runtime_id,
                        request_id=runtime_request_id,
                        traversal_started_event=traversal_started_event,
                        traversal_completed_event=traversal_completed_event,
                    )
                    pending = {
                        "authority": deepcopy(execution_authority),
                        "state": deepcopy(state),
                    }
                    if len(self._pending_execution_authorities) >= 1024:
                        oldest = next(iter(self._pending_execution_authorities))
                        self._pending_execution_authorities.pop(oldest, None)
                    self._pending_execution_authorities[
                        execution_authority["authority_digest"]
                    ] = pending
                committed_result = deepcopy(state)
                self.last_result = committed_result
                self.traversal_count += 1
            return {
                "runtime": self.runtime_id,
                "request_id": runtime_request_id,
                "state": state,
                "execution_authority_reference": (
                    execution_authority.get("authority_digest")
                    if execution_authority
                    else None
                ),
                "replay_ledger_entry": replay_entry,
                "persistence_record": persistence_record,
            }
        finally:
            with self._authority_lock:
                self._active_traversals.discard(active_key)

    def issue_execution_capability(
        self, reference: str, *, execution_service: Any,
        specification_id: str, parameters: Mapping[str, Any] | str,
        **temporal_policy: Any,
    ) -> Dict[str, Any]:
        if not isinstance(reference, str) or not reference:
            raise ValueError("execution_authority_reference_invalid")
        if type(execution_service) is not ExecutionIntegrityService:
            raise ValueError("execution_service_invalid")
        with self._authority_lock:
            pending = self._pending_execution_authorities.pop(reference, None)
        if pending is None:
            raise ValueError("execution_authority_reference_unavailable")
        authority = pending.get("authority")
        state = pending.get("state")
        if (
            not isinstance(authority, Mapping)
            or not isinstance(state, Mapping)
            or authority.get("authority_digest") != reference
            or not verify_execution_traversal_authority(authority, state)
        ):
            raise ValueError("execution_authority_reference_integrity_invalid")
        capability = ExecutionIntegrityService.issue(
            execution_service,
            state,
            traversal_authority=authority,
            specification_id=specification_id, parameters=parameters,
            **temporal_policy,
        )
        authority_payload = authority.get("payload", {})
        expected_bindings = {
            "request_id": authority_payload.get("request_id"),
            "request_fingerprint": authority_payload.get(
                "request_fingerprint"
            ),
            "traversal_authority_digest": reference,
            "eie_identifier": authority_payload.get("eie_identifier"),
            "eie_digest": authority_payload.get("eie_digest"),
            "canonical_state_hash": authority_payload.get(
                "canonical_state_hash"
            ),
            "pipeline_mode": authority_payload.get("pipeline_mode"),
            "convergence_result": authority_payload.get(
                "convergence_result"
            ),
            "audit_lineage_identifier": authority_payload.get(
                "audit_lineage_identifier"
            ),
            **{
                field: authority_payload.get(field)
                for field in MEASURED_STARTUP_BINDING_FIELDS
            },
        }
        if (
            not verify_capability(capability)
            or any(
                capability.get(field) != expected
                for field, expected in expected_bindings.items()
            )
            or execution_service.store.state(
                str(capability.get("capability_id"))
            )
            != "PENDING"
        ):
            raise ValueError("execution_capability_issuance_invalid")
        return deepcopy(capability)

    def replay(
        self,
        request: Mapping[str, Any],
        *,
        replay_count: int = 2,
        pre_context_signals: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        ensure_measured_startup()
        with self._authority_lock:
            if self._active_traversals:
                raise ValueError("replay_during_active_traversal_denied")
            RUNTIME_EVENTS.emit("replay_started", {"action": request.get("action"), "replay_count": replay_count})
            result = run_replay_check(request=request, pre_context_signals=pre_context_signals, replay_count=replay_count)
            RUNTIME_EVENTS.emit("replay_completed", {"matched": result.get("matched"), "replay_hash": result.get("replay_hash")})
        return result


CANONICAL_RUNTIME = CanonicalRuntime()
