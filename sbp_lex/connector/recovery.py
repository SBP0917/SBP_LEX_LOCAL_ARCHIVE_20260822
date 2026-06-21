from __future__ import annotations

from copy import deepcopy
from threading import Lock
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


def build_recovery_checkpoint(history: list[Mapping[str, Any]]) -> Dict[str, Any]:
    payload = {
        "store_id": "SBP_LEX_V1_CONNECTOR_RECOVERY",
        "record_count": len(history),
        "head_hash": history[-1].get("checkpoint_hash") if history else "GENESIS",
        "checkpoint_authority": "CANONICAL_RUNTIME",
    }
    return {
        "payload": payload,
        "checkpoint_hash": generate_digest(payload),
        "signature": sign_payload(payload),
    }


class ConnectorRecoveryStore:
    """In-memory V1 recovery/checkpoint store for connector interruption recovery."""

    def __init__(self) -> None:
        self._checkpoints: dict[str, Dict[str, Any]] = {}
        self._history: list[Dict[str, Any]] = []
        self._claimed_request_ids: set[str] = set()
        self._lock = Lock()
        self._checkpoint = build_recovery_checkpoint(self._history)

    def exists(self, request_id: str) -> bool:
        with self._lock:
            return request_id in self._checkpoints or request_id in self._claimed_request_ids

    def claim(self, request_id: str) -> bool:
        with self._lock:
            if request_id in self._checkpoints or request_id in self._claimed_request_ids:
                return False
            self._claimed_request_ids.add(request_id)
            return True

    def save(self, request_id: str, state: Mapping[str, Any], *, source: str | None = None) -> Dict[str, Any]:
        with self._lock:
            previous_hash = self._history[-1]["checkpoint_hash"] if self._history else "GENESIS"
            sequence = len(self._history) + 1
            checkpoint_payload = {
                "sequence": sequence,
                "request_id": request_id,
                "source": source or "connector",
                "request_fingerprint": state.get("request_fingerprint"),
                "state_hash": state.get("state_hash"),
                "decision": state.get("decision"),
                "execution_result": state.get("execution_result"),
                "audit_hash": state.get("audit_hash"),
                "pipeline_mode": state.get("pipeline_mode"),
                "previous_hash": previous_hash,
                "timestamp": f"CONNECTOR_CHECKPOINT_{sequence:012d}",
                "timestamp_authority": "CANONICAL_RUNTIME",
            }
            checkpoint = {
                **checkpoint_payload,
                "checkpoint_hash": generate_digest(checkpoint_payload),
                "signature": sign_payload(checkpoint_payload),
            }
            self._checkpoints[request_id] = deepcopy(checkpoint)
            self._claimed_request_ids.discard(request_id)
            self._history.append(deepcopy(checkpoint))
            self._checkpoint = build_recovery_checkpoint(self._history)
            return checkpoint

    def save_rejection(self, request_id: str, *, failures: list[str], source: str = "connector") -> Dict[str, Any]:
        with self._lock:
            previous_hash = self._history[-1]["checkpoint_hash"] if self._history else "GENESIS"
            sequence = len(self._history) + 1
            payload = {
                "sequence": sequence,
                "request_id": request_id or "REJECTED_UNKNOWN_REQUEST",
                "source": source,
                "accepted": False,
                "failures": list(failures),
                "previous_hash": previous_hash,
                "timestamp": f"CONNECTOR_REJECTION_{sequence:012d}",
                "timestamp_authority": "CANONICAL_RUNTIME",
            }
            record = {
                **payload,
                "checkpoint_hash": generate_digest(payload),
                "signature": sign_payload(payload),
            }
            self._history.append(deepcopy(record))
            self._checkpoint = build_recovery_checkpoint(self._history)
            return record

    def get(self, request_id: str) -> Dict[str, Any] | None:
        with self._lock:
            checkpoint = self._checkpoints.get(request_id)
            return deepcopy(checkpoint) if checkpoint else None

    def export(self) -> list[Dict[str, Any]]:
        with self._lock:
            return deepcopy(list(self._checkpoints.values()))

    def export_history(self) -> list[Dict[str, Any]]:
        with self._lock:
            return deepcopy(self._history)

    def checkpoint(self) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._checkpoint)

    def verify(self) -> tuple[bool, list[str]]:
        with self._lock:
            failures: list[str] = []
            previous_hash = "GENESIS"
            for index, checkpoint in enumerate(self._history):
                signature = checkpoint.get("signature", {})
                payload = {
                    key: value
                    for key, value in checkpoint.items()
                    if key not in {"checkpoint_hash", "signature"}
                }
                if checkpoint.get("previous_hash") != previous_hash:
                    failures.append(f"connector_checkpoint_link_broken:{index}")
                if checkpoint.get("checkpoint_hash") != generate_digest(payload):
                    failures.append(f"connector_checkpoint_hash_mismatch:{index}")
                if not verify_signature(payload, signature):
                    failures.append(f"connector_checkpoint_signature_invalid:{index}")
                previous_hash = str(checkpoint.get("checkpoint_hash"))
            expected_checkpoint = build_recovery_checkpoint(self._history)["payload"]
            checkpoint_payload = self._checkpoint.get("payload", {})
            if (
                checkpoint_payload != expected_checkpoint
                or self._checkpoint.get("checkpoint_hash")
                != generate_digest(checkpoint_payload)
                or not verify_signature(
                    checkpoint_payload, self._checkpoint.get("signature", {})
                )
            ):
                failures.append("recovery_state_rejected")
            return len(failures) == 0, failures


CONNECTOR_RECOVERY = ConnectorRecoveryStore()
