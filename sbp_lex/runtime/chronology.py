from __future__ import annotations

from copy import deepcopy
from threading import Lock
from typing import Any, Dict, List, Mapping

from sbp_lex.security.pqc import generate_digest


class CanonicalChronology:
    """Single-runtime deterministic chronology authority for V1."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._sequence = 0
        self._events: List[Dict[str, Any]] = []

    def append(self, *, event_type: str, payload: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        with self._lock:
            self._sequence += 1
            previous_hash = self._events[-1]["event_hash"] if self._events else "GENESIS"
            event = {
                "sequence": self._sequence,
                "timestamp": f"CHRONOLOGY_EVENT_{self._sequence:012d}",
                "timestamp_authority": "CANONICAL_RUNTIME",
                "event_type": event_type,
                "payload": deepcopy(dict(payload or {})),
                "previous_hash": previous_hash,
            }
            event["event_hash"] = generate_digest(event)
            self._events.append(deepcopy(event))
            return event

    def latest(self) -> Dict[str, Any] | None:
        with self._lock:
            return deepcopy(self._events[-1]) if self._events else None

    def export(self) -> List[Dict[str, Any]]:
        with self._lock:
            return deepcopy(self._events)

    def verify(self) -> tuple[bool, list[str]]:
        with self._lock:
            failures: list[str] = []
            previous_hash = "GENESIS"
            for index, event in enumerate(self._events):
                if event.get("previous_hash") != previous_hash:
                    failures.append(f"chronology_link_broken:{index}")
                payload = {k: v for k, v in event.items() if k != "event_hash"}
                if generate_digest(payload) != event.get("event_hash"):
                    failures.append(f"chronology_hash_mismatch:{index}")
                previous_hash = str(event.get("event_hash"))
            return len(failures) == 0, failures


CANONICAL_CHRONOLOGY = CanonicalChronology()
