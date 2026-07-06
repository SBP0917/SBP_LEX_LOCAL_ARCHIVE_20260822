from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class MaintenanceLogEntry:
    timestamp: str
    action_name: str
    result: str


def build_maintenance_log_entry(action_name: str, result: str) -> MaintenanceLogEntry:
    return MaintenanceLogEntry(datetime.now(UTC).isoformat(), action_name, result)
