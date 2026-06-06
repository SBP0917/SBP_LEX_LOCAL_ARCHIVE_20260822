from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


class ConnectorRecoveryStore:
    """In-memory V1 recovery/checkpoint store for connector interruption recovery."""

    def __init__(self) -> None:
        self._checkpoints: dict[str, Dict[str, Any]] = {}
        self._history: list[Dict[str, Any]] = []

    def exists(self, request_id: str) -> bool:
        return request_id in self._checkpoints

    def save(self, request_id: str, state: Mapping[str, Any], *, source: str | None = None) -> Dict[str, Any]:
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
        self._history.append(deepcopy(checkpoint))
        return checkpoint

    def save_rejection(self, request_id: str, *, failures: list[str], source: str = "connector") -> Dict[str, Any]:
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
        record = {**payload, "checkpoint_hash": generate_digest(payload), "signature": sign_payload(payload)}
        self._history.append(deepcopy(record))
        return record

    def get(self, request_id: str) -> Dict[str, Any] | None:
        checkpoint = self._checkpoints.get(request_id)
        return deepcopy(checkpoint) if checkpoint else None

    def export(self) -> list[Dict[str, Any]]:
        return deepcopy(list(self._checkpoints.values()))

    def export_history(self) -> list[Dict[str, Any]]:
        return deepcopy(self._history)

    def verify(self) -> tuple[bool, list[str]]:
        failures: list[str] = []
        previous_hash = "GENESIS"
        for index, checkpoint in enumerate(self._history):
            signature = checkpoint.get("signature", {})
            payload = {key: value for key, value in checkpoint.items() if key not in {"checkpoint_hash", "signature"}}
            if checkpoint.get("previous_hash") != previous_hash:
                failures.append(f"connector_checkpoint_link_broken:{index}")
            if checkpoint.get("checkpoint_hash") != generate_digest(payload):
                failures.append(f"connector_checkpoint_hash_mismatch:{index}")
            if not verify_signature(payload, signature):
                failures.append(f"connector_checkpoint_signature_invalid:{index}")
            previous_hash = str(checkpoint.get("checkpoint_hash"))
        return len(failures) == 0, failures


CONNECTOR_RECOVERY = ConnectorRecoveryStore()
