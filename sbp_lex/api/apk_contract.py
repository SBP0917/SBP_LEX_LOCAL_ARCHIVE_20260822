from __future__ import annotations

from typing import Any, Mapping

APK_ALLOWED_EVENT_TYPES = {
    "traversal_started",
    "traversal_completed",
    "replay_started",
    "replay_completed",
    "api_access_rejected",
    "api_schema_rejected",
    "connector_envelope_rejected",
    "connector_envelope_accepted",
    "connector_interruption_recorded",
    "persistence_record_appended",
    "runtime_integrity_checked",
}

APK_REQUIRED_STATUS_FIELDS = {
    "runtime_id",
    "api_security_mode",
    "traversal_count",
    "chronology_valid",
    "event_bus_valid",
    "replay_ledger_valid",
    "connector_recovery_valid",
    "persistence_valid",
}


def validate_apk_event(event: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(event, Mapping):
        return False, ["event_not_mapping"]
    if not isinstance(event.get("sequence"), int):
        failures.append("event_sequence_required")
    if event.get("event_type") not in APK_ALLOWED_EVENT_TYPES:
        failures.append("event_type_not_allowed")
    if not isinstance(event.get("event_hash"), str) or not event.get("event_hash"):
        failures.append("event_hash_required")
    if event.get("timestamp_authority") != "CANONICAL_RUNTIME":
        failures.append("timestamp_authority_invalid")
    return len(failures) == 0, failures


def validate_runtime_status_contract(status: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(status, Mapping):
        return False, ["status_not_mapping"]
    for field in APK_REQUIRED_STATUS_FIELDS:
        if field not in status:
            failures.append(f"status_field_missing:{field}")
    for field in ("chronology_valid", "event_bus_valid", "replay_ledger_valid", "connector_recovery_valid", "persistence_valid"):
        if field in status and not isinstance(status.get(field), bool):
            failures.append(f"status_field_not_bool:{field}")
    return len(failures) == 0, failures
