from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


class PipelineReplayLedger:
    def __init__(self) -> None:
        self._ledger: List[Dict[str, Any]] = []

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
        return entry

    def verify(self) -> tuple[bool, list[str]]:
        failures: list[str] = []
        previous_hash = "GENESIS"
        for index, item in enumerate(self._ledger):
            payload = {key: value for key, value in item.items() if key not in {"ledger_hash", "signature"}}
            if item.get("previous_hash") != previous_hash:
                failures.append(f"ledger_link_broken:{index}")
            if generate_digest(payload) != item.get("ledger_hash"):
                failures.append(f"ledger_corruption:{index}")
            if not verify_signature(payload, item.get("signature", {})):
                failures.append(f"ledger_signature_invalid:{index}")
            previous_hash = str(item.get("ledger_hash"))
        return len(failures) == 0, failures

    def export(self) -> List[Dict[str, Any]]:
        return deepcopy(self._ledger)

    def size(self) -> int:
        return len(self._ledger)


PIPELINE_REPLAY_LEDGER = PipelineReplayLedger()
