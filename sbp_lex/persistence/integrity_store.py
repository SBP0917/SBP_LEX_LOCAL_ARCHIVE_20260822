from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

DEFAULT_STORE_PATH = Path(os.environ.get("SBP_LEX_INTEGRITY_STORE", "runtime_artifacts/integrity_store.jsonl"))


class IntegrityStore:
    """Append-only runtime integrity store for audit/replay summaries."""

    def __init__(self, path: Path = DEFAULT_STORE_PATH) -> None:
        self.path = path
        self._records: List[Dict[str, Any]] = []
        self._loaded = False

    def _load_once(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                self._records.append(record)

    def append_state_summary(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        self._load_once()
        previous_hash = self._records[-1]["record_hash"] if self._records else "GENESIS"
        sequence = len(self._records) + 1
        payload = {
            "sequence": sequence,
            "timestamp": f"PERSISTENCE_RECORD_{sequence:012d}",
            "timestamp_authority": "CANONICAL_RUNTIME",
            "request_fingerprint": state.get("request_fingerprint"),
            "state_hash": state.get("state_hash"),
            "decision": state.get("decision"),
            "execution_result": state.get("execution_result"),
            "audit_hash": state.get("audit_hash"),
            "convergence_hash": state.get("pipeline_convergence", {}).get("convergence_hash"),
            "previous_hash": previous_hash,
        }
        record = {**payload, "record_hash": generate_digest(payload), "signature": sign_payload(payload)}
        self._records.append(deepcopy(record))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":"), default=str) + "\n")
        return record

    def verify(self) -> tuple[bool, list[str]]:
        self._load_once()
        failures: list[str] = []
        previous_hash = "GENESIS"
        for index, record in enumerate(self._records):
            payload = {key: value for key, value in record.items() if key not in {"record_hash", "signature"}}
            if record.get("previous_hash") != previous_hash:
                failures.append(f"persistence_link_broken:{index}")
            if record.get("record_hash") != generate_digest(payload):
                failures.append(f"persistence_hash_mismatch:{index}")
            if not verify_signature(payload, record.get("signature", {})):
                failures.append(f"persistence_signature_invalid:{index}")
            previous_hash = str(record.get("record_hash"))
        return len(failures) == 0, failures

    def export(self) -> List[Dict[str, Any]]:
        self._load_once()
        return deepcopy(self._records)


RUNTIME_INTEGRITY_STORE = IntegrityStore()
