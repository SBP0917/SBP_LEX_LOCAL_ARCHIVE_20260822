from __future__ import annotations

from copy import deepcopy
from threading import Lock
from typing import Any, Dict, List, Mapping

from sbp_lex.runtime.chronology import CANONICAL_CHRONOLOGY
from sbp_lex.security.pqc import generate_digest

MAX_EVENT_PAYLOAD_KEYS = 64
MAX_EVENT_PAYLOAD_STRING_LENGTH = 4096
ALLOWED_EVENT_TYPES = {
    "traversal_started",
    "traversal_completed",
    "replay_started",
    "replay_completed",
    "api_access_rejected",
    "api_admission_rejected",
    "api_transport_rejected",
    "api_transport_observed",
    "api_schema_rejected",
    "connector_envelope_rejected",
    "connector_envelope_accepted",
    "connector_interruption_recorded",
    "persistence_record_appended",
    "runtime_integrity_checked",
    "startup_requested",
    "startup_validation_started",
    "startup_validated",
    "startup_rejected",
    "runtime_ready",
    "runtime_processing",
    "runtime_draining",
    "runtime_stopping",
    "shutdown_requested",
    "shutdown_complete",
    "unexpected_termination",
    "recovery_required",
    "recovery_initiated",
    "recovery_rejected",
    "recovery_complete",
    "backup_created",
    "backup_rejected",
    "restore_initiated",
    "restore_rejected",
    "restore_complete",
    "resource_warning",
    "resource_limit_reached",
    "queue_saturation",
    "traversal_timeout",
    "candidate_limit_reached",
    "restart_limit_reached",
    "ledger_corruption",
    "quarantine_created",
    "cryptographic_provider_missing",
    "cryptographic_downgrade_attempt",
    "signature_verification_failure",
    "capability_invalidated",
    "ambiguous_effect",
    "fault_injection_activated",
    "soak_started",
    "soak_completed",
    "soak_failed",
    "traversal_supervision_started",
    "traversal_stage_observed",
    "traversal_supervision_completed",
    "traversal_invalidated",
}


def sanitise_event_text(value: str, *, limit: int) -> str:
    escaped = "".join(
        {"\r": "\\r", "\n": "\\n", "\t": "\\t"}.get(character, character)
        if ord(character) >= 32 or character in "\r\n\t"
        else f"\\u{ord(character):04x}"
        for character in value
    )
    return escaped[:limit]


def _safe_payload(payload: Mapping[str, Any] | None) -> Dict[str, Any]:
    raw = dict(payload or {})
    safe: Dict[str, Any] = {}
    for index, (key, value) in enumerate(raw.items()):
        if index >= MAX_EVENT_PAYLOAD_KEYS:
            safe["payload_truncated"] = True
            break
        key_text = sanitise_event_text(str(key), limit=128)
        if isinstance(value, str):
            safe[key_text] = sanitise_event_text(
                value, limit=MAX_EVENT_PAYLOAD_STRING_LENGTH
            )
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[key_text] = value
        else:
            safe[key_text] = generate_digest(value)
    return safe


class RuntimeEventBus:
    """Append-only event bus for APK/runtime observability."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._events: List[Dict[str, Any]] = []

    def emit(self, event_type: str, payload: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        event_name = event_type if event_type in ALLOWED_EVENT_TYPES else "runtime_integrity_checked"
        safe_payload = _safe_payload(payload)
        if event_name != event_type:
            safe_payload["original_event_type_hash"] = generate_digest(event_type)
            safe_payload["event_type_rewritten"] = True
        event = CANONICAL_CHRONOLOGY.append(event_type=event_name, payload=safe_payload)
        with self._lock:
            self._events.append(deepcopy(event))
        return event

    def latest(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            limit = max(1, min(int(limit), 500))
            return deepcopy(self._events[-limit:])

    def since(self, sequence: int, *, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            limit = max(1, min(int(limit), 1000))
            events = [event for event in self._events if int(event.get("sequence", 0)) > int(sequence)]
            return deepcopy(events[:limit])

    def verify(self) -> tuple[bool, list[str]]:
        chronology_ok, chronology_failures = CANONICAL_CHRONOLOGY.verify()
        failures = list(chronology_failures)
        with self._lock:
            previous_sequence = 0
            for index, event in enumerate(self._events):
                sequence = int(event.get("sequence", 0))
                if sequence <= previous_sequence:
                    failures.append(f"event_sequence_not_increasing:{index}")
                if event.get("event_type") not in ALLOWED_EVENT_TYPES:
                    failures.append(f"event_type_not_allowed:{index}")
                previous_sequence = sequence
        return chronology_ok and len(failures) == 0, failures

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


RUNTIME_EVENTS = RuntimeEventBus()
