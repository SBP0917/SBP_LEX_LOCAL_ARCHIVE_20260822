from __future__ import annotations

from copy import deepcopy
from threading import Lock
from typing import Any, Dict, List, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

CHRONOLOGY_ID = "SBP_LEX_V1_CANONICAL_CHRONOLOGY"


def build_chronology_checkpoint(events: List[Mapping[str, Any]]) -> Dict[str, Any]:
    payload = {
        "chronology_id": CHRONOLOGY_ID,
        "event_count": len(events),
        "head_hash": events[-1].get("event_hash") if events else "GENESIS",
        "checkpoint_authority": "CANONICAL_RUNTIME",
    }
    return {
        "payload": payload,
        "checkpoint_hash": generate_digest(payload),
        "signature": sign_payload(payload),
    }


def verify_chronology_checkpoint(
    events: List[Mapping[str, Any]], checkpoint: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    expected = build_chronology_checkpoint(events)["payload"]
    payload = checkpoint.get("payload", {}) if isinstance(checkpoint, Mapping) else {}
    if (
        not isinstance(payload, Mapping)
        or dict(payload) != expected
        or checkpoint.get("checkpoint_hash") != generate_digest(dict(payload))
        or not verify_signature(payload, checkpoint.get("signature", {}))
    ):
        failures.append("chronology_checkpoint_mismatch")
    return not failures, failures


def compare_chronology_heads(
    trusted: Mapping[str, Any], candidate: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    trusted_payload = trusted.get("payload", {})
    candidate_payload = candidate.get("payload", {})
    if not verify_signature(trusted_payload, trusted.get("signature", {})):
        return False, ["trusted_chronology_checkpoint_invalid"]
    if not verify_signature(candidate_payload, candidate.get("signature", {})):
        return False, ["insider_modification_detected"]
    if candidate_payload.get("event_count", -1) < trusted_payload.get("event_count", -1):
        return False, ["rollback_rejected"]
    if (
        candidate_payload.get("event_count") == trusted_payload.get("event_count")
        and candidate_payload.get("head_hash") != trusted_payload.get("head_hash")
    ):
        return False, ["split_history_detected"]
    return True, []


class CanonicalChronology:
    """Single-runtime deterministic chronology authority for V1."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._sequence = 0
        self._events: List[Dict[str, Any]] = []
        self._checkpoint = build_chronology_checkpoint(self._events)

    def append(self, *, event_type: str, payload: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        with self._lock:
            self._sequence += 1
            previous_hash = self._events[-1]["event_hash"] if self._events else "GENESIS"
            event_payload = {
                "sequence": self._sequence,
                "timestamp": f"CHRONOLOGY_EVENT_{self._sequence:012d}",
                "timestamp_authority": "CANONICAL_RUNTIME",
                "event_type": event_type,
                "payload": deepcopy(dict(payload or {})),
                "previous_hash": previous_hash,
            }
            event = {
                **event_payload,
                "event_hash": generate_digest(event_payload),
                "signature": sign_payload(event_payload),
            }
            self._events.append(deepcopy(event))
            self._checkpoint = build_chronology_checkpoint(self._events)
            return event

    def latest(self) -> Dict[str, Any] | None:
        with self._lock:
            return deepcopy(self._events[-1]) if self._events else None

    def export(self) -> List[Dict[str, Any]]:
        with self._lock:
            return deepcopy(self._events)

    def checkpoint(self) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._checkpoint)

    def verify(self) -> tuple[bool, list[str]]:
        with self._lock:
            failures: list[str] = []
            previous_hash = "GENESIS"
            for index, event in enumerate(self._events):
                expected_sequence = index + 1
                if event.get("sequence") != expected_sequence:
                    failures.append(f"chronology_sequence_invalid:{index}")
                if event.get("timestamp") != f"CHRONOLOGY_EVENT_{expected_sequence:012d}":
                    failures.append(f"chronology_timestamp_invalid:{index}")
                if event.get("timestamp_authority") != "CANONICAL_RUNTIME":
                    failures.append(f"chronology_timestamp_authority_invalid:{index}")
                if event.get("previous_hash") != previous_hash:
                    failures.append(f"chronology_link_broken:{index}")
                payload = {k: v for k, v in event.items() if k not in {"event_hash", "signature"}}
                if generate_digest(payload) != event.get("event_hash"):
                    failures.append(f"chronology_hash_mismatch:{index}")
                if not verify_signature(payload, event.get("signature", {})):
                    failures.append(f"chronology_signature_invalid:{index}")
                previous_hash = str(event.get("event_hash"))
            checkpoint_ok, checkpoint_failures = verify_chronology_checkpoint(
                self._events, self._checkpoint
            )
            failures.extend(checkpoint_failures)
            return len(failures) == 0 and checkpoint_ok, failures


CANONICAL_CHRONOLOGY = CanonicalChronology()
