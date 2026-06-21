from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


def _checkpoint_payload(entries: List[Mapping[str, Any]]) -> Dict[str, Any]:
    return {
        "record_count": len(entries),
        "head_hash": entries[-1].get("ledger_hash") if entries else "GENESIS",
        "checkpoint_authority": "CANONICAL_RUNTIME",
    }


def build_replay_ledger_checkpoint(entries: List[Mapping[str, Any]]) -> Dict[str, Any]:
    payload = _checkpoint_payload(entries)
    return {
        "payload": payload,
        "checkpoint_hash": generate_digest(payload),
        "signature": sign_payload(payload),
    }


def verify_replay_ledger_entries(
    entries: List[Mapping[str, Any]], checkpoint: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    previous_hash = "GENESIS"
    for index, item in enumerate(entries):
        payload = {key: value for key, value in item.items() if key not in {"ledger_hash", "signature"}}
        if item.get("sequence") != index + 1:
            failures.append(f"ledger_sequence_invalid:{index}")
        if item.get("previous_hash") != previous_hash:
            failures.append(f"ledger_link_broken:{index}")
        if generate_digest(payload) != item.get("ledger_hash"):
            failures.append(f"ledger_corruption:{index}")
        if not verify_signature(payload, item.get("signature", {})):
            failures.append(f"ledger_signature_invalid:{index}")
        previous_hash = str(item.get("ledger_hash"))
    checkpoint_payload = checkpoint.get("payload", {}) if isinstance(checkpoint, Mapping) else {}
    if (
        not isinstance(checkpoint_payload, Mapping)
        or checkpoint.get("checkpoint_hash") != generate_digest(dict(checkpoint_payload))
        or not verify_signature(checkpoint_payload, checkpoint.get("signature", {}))
        or dict(checkpoint_payload) != _checkpoint_payload(entries)
    ):
        failures.append("ledger_checkpoint_mismatch")
    return not failures, failures


class PipelineReplayLedger:
    def __init__(self) -> None:
        self._ledger: List[Dict[str, Any]] = []
        self._checkpoint = build_replay_ledger_checkpoint(self._ledger)

    def append(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        previous_hash = self._ledger[-1]["ledger_hash"] if self._ledger else "GENESIS"
        sequence = len(self._ledger) + 1
        payload = {
            "sequence": sequence,
            "timestamp": f"REPLAY_LEDGER_EVENT_{sequence:012d}",
            "timestamp_authority": "CANONICAL_RUNTIME",
            "request_fingerprint": state.get("request_fingerprint"),
            "pipeline_mode": state.get("pipeline_mode"),
            "decision": state.get("decision"),
            "state_hash": state.get("state_hash"),
            "audit_hash": state.get("audit_hash"),
            "convergence_hash": state.get("pipeline_convergence", {}).get("convergence_hash"),
            "previous_hash": previous_hash,
        }
        entry = {**payload, "ledger_hash": generate_digest(payload), "signature": sign_payload(payload)}
        self._ledger.append(deepcopy(entry))
        self._checkpoint = build_replay_ledger_checkpoint(self._ledger)
        return entry

    def verify(self) -> tuple[bool, list[str]]:
        return verify_replay_ledger_entries(self._ledger, self._checkpoint)

    def export(self) -> List[Dict[str, Any]]:
        return deepcopy(self._ledger)

    def checkpoint(self) -> Dict[str, Any]:
        return deepcopy(self._checkpoint)

    def size(self) -> int:
        return len(self._ledger)


PIPELINE_REPLAY_LEDGER = PipelineReplayLedger()
