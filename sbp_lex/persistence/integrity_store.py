from __future__ import annotations

import json
import os
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.api.schema_validation import loads_strict_json

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ARTIFACT_ROOT = (REPOSITORY_ROOT / "runtime_artifacts").resolve()
DEFAULT_STORE_PATH = Path(
    os.environ.get("SBP_LEX_INTEGRITY_STORE", "runtime_artifacts/integrity_store.jsonl")
)


def resolve_integrity_store_path(
    path: Path, *, allowed_root: Path = RUNTIME_ARTIFACT_ROOT
) -> Path:
    root = allowed_root.resolve()
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    candidate = candidate.resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("integrity_store_path_outside_runtime_artifacts")
    if candidate.suffix.lower() != ".jsonl":
        raise ValueError("integrity_store_path_must_be_jsonl")
    return candidate


def _checkpoint_payload(records: List[Mapping[str, Any]]) -> Dict[str, Any]:
    return {
        "store_id": "SBP_LEX_V1_RUNTIME_INTEGRITY_STORE",
        "record_count": len(records),
        "head_hash": records[-1].get("record_hash") if records else "GENESIS",
        "checkpoint_authority": "CANONICAL_RUNTIME",
    }


def build_integrity_store_checkpoint(
    records: List[Mapping[str, Any]],
) -> Dict[str, Any]:
    payload = _checkpoint_payload(records)
    return {
        "payload": payload,
        "checkpoint_hash": generate_digest(payload),
        "signature": sign_payload(payload),
    }


def quarantine_poisoned_integrity_store(
    path: Path = DEFAULT_STORE_PATH,
    *,
    allowed_root: Path = RUNTIME_ARTIFACT_ROOT,
    quarantine_dir: Path | None = None,
) -> Dict[str, Any]:
    store = IntegrityStore(path, allowed_root=allowed_root)
    valid, failures = store.verify()
    if valid:
        raise RuntimeError("integrity_store_valid")
    source = store.path
    if not source.exists():
        raise FileNotFoundError(source)
    digest = sha256(source.read_bytes()).hexdigest()
    destination_dir = (
        quarantine_dir.resolve()
        if quarantine_dir is not None
        else source.parent / "quarantine"
    )
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{source.stem}.poisoned.{digest}{source.suffix}"
    if destination.exists():
        raise FileExistsError(destination)
    size = source.stat().st_size
    source.replace(destination)

    checkpoint_destination = None
    if store.checkpoint_path.exists():
        checkpoint_destination = destination.with_suffix(
            destination.suffix + ".checkpoint.json"
        )
        if checkpoint_destination.exists():
            raise FileExistsError(checkpoint_destination)
        store.checkpoint_path.replace(checkpoint_destination)

    return {
        "source": str(source),
        "quarantine_path": str(destination),
        "checkpoint_quarantine_path": (
            str(checkpoint_destination) if checkpoint_destination is not None else None
        ),
        "sha256": digest,
        "size": size,
        "failures": failures,
    }


def verify_integrity_records(
    records: List[Mapping[str, Any]], checkpoint: Mapping[str, Any] | None
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    previous_hash = "GENESIS"
    for index, record in enumerate(records):
        payload = {
            key: value
            for key, value in record.items()
            if key not in {"record_hash", "signature"}
        }
        if record.get("sequence") != index + 1:
            failures.append(f"persistence_sequence_invalid:{index}")
        if record.get("previous_hash") != previous_hash:
            failures.append(f"persistence_link_broken:{index}")
        if record.get("record_hash") != generate_digest(payload):
            failures.append(f"persistence_hash_mismatch:{index}")
        if not verify_signature(payload, record.get("signature", {})):
            failures.append(f"persistence_signature_invalid:{index}")
        previous_hash = str(record.get("record_hash"))
    if records and checkpoint is None:
        failures.append("persistence_checkpoint_missing")
    elif checkpoint is not None:
        payload = checkpoint.get("payload", {})
        if (
            not isinstance(payload, Mapping)
            or dict(payload) != _checkpoint_payload(records)
            or checkpoint.get("checkpoint_hash") != generate_digest(dict(payload))
            or not verify_signature(payload, checkpoint.get("signature", {}))
        ):
            failures.append("persistence_poisoning_detected")
    if failures and "persistence_poisoning_detected" not in failures:
        failures.append("persistence_poisoning_detected")
    return not failures, failures


class IntegrityStore:
    """Append-only runtime integrity store for audit/replay summaries."""

    def __init__(
        self,
        path: Path = DEFAULT_STORE_PATH,
        *,
        allowed_root: Path = RUNTIME_ARTIFACT_ROOT,
    ) -> None:
        self.path = resolve_integrity_store_path(path, allowed_root=allowed_root)
        self.checkpoint_path = self.path.with_suffix(self.path.suffix + ".checkpoint.json")
        self._records: List[Dict[str, Any]] = []
        self._load_failures: list[str] = []
        self._checkpoint: Dict[str, Any] | None = None
        self._loaded = False

    def _load_once(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.path.exists():
            return
        for index, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                record = loads_strict_json(line)
            except (json.JSONDecodeError, ValueError):
                self._load_failures.append(f"persistence_parse_failure:{index}")
                continue
            if isinstance(record, dict):
                self._records.append(record)
            else:
                self._load_failures.append(f"persistence_record_not_mapping:{index}")
        if self.checkpoint_path.exists():
            try:
                checkpoint = loads_strict_json(
                    self.checkpoint_path.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, ValueError):
                self._load_failures.append("persistence_checkpoint_parse_failure")
            else:
                if isinstance(checkpoint, dict):
                    self._checkpoint = checkpoint
                else:
                    self._load_failures.append("persistence_checkpoint_not_mapping")

    def append_state_summary(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        self._load_once()
        chain_ok, chain_failures = verify_integrity_records(
            self._records,
            self._checkpoint if self._checkpoint is not None else (
                build_integrity_store_checkpoint(self._records)
                if self._records and not self._load_failures
                else None
            ),
        )
        if self._load_failures or not chain_ok:
            raise RuntimeError(
                "persistence_poisoning_detected:"
                + ",".join(self._load_failures + chain_failures)
            )
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
        self._checkpoint = build_integrity_store_checkpoint(self._records)
        self.checkpoint_path.write_text(
            json.dumps(
                self._checkpoint,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            + "\n",
            encoding="utf-8",
        )
        return record

    def verify(self) -> tuple[bool, list[str]]:
        self._load_once()
        _, record_failures = verify_integrity_records(
            self._records, self._checkpoint
        )
        failures = list(self._load_failures) + record_failures
        return len(failures) == 0, failures

    def export(self) -> List[Dict[str, Any]]:
        self._load_once()
        return deepcopy(self._records)

    def checkpoint(self) -> Dict[str, Any] | None:
        self._load_once()
        return deepcopy(self._checkpoint)


RUNTIME_INTEGRITY_STORE = IntegrityStore()
