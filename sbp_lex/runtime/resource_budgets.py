from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from typing import Mapping, Sequence

from sbp_lex.api.schema_validation import (
    MAX_EVIDENCE_ITEMS,
    MAX_JSON_DEPTH,
    MAX_JSON_KEYS,
    MAX_LIST_LENGTH,
    MAX_PRE_CONTEXT_SIGNAL_KEYS,
    MAX_RUNTIME_REQUEST_BYTES,
    MAX_STRING_LENGTH,
)
from sbp_lex.aurion15.runtime.runner import MAX_CANDIDATE_ATTEMPTS
from sbp_lex.recovery.common import atomic_json
from sbp_lex.security.pqc import generate_digest


RESOURCE_BUDGET_VERSION = "PASS8_DESKTOP_V1_RESOURCE_BUDGET_POLICY_V1"
MAX_EVENT_PAYLOAD_KEYS = 64
MAX_EVENT_PAYLOAD_STRING_LENGTH = 4096


@dataclass(frozen=True)
class ResourceBudgetPolicy:
    """Central evidence view of existing and Pass 8 operational bounds."""

    maximum_request_bytes: int = MAX_RUNTIME_REQUEST_BYTES
    maximum_eie_bytes: int = 262_144
    maximum_json_depth: int = MAX_JSON_DEPTH
    maximum_json_keys: int = MAX_JSON_KEYS
    maximum_string_length: int = MAX_STRING_LENGTH
    maximum_list_length: int = MAX_LIST_LENGTH
    maximum_evidence_references: int = MAX_EVIDENCE_ITEMS
    maximum_corroboration_sources: int = MAX_EVIDENCE_ITEMS
    maximum_collective_signal_bytes: int = 262_144
    maximum_collective_signal_keys: int = MAX_PRE_CONTEXT_SIGNAL_KEYS
    maximum_token_count: int = 64
    maximum_duplicate_token_names: int = 0
    maximum_candidate_attempts: int = MAX_CANDIDATE_ATTEMPTS
    maximum_candidate_count: int = MAX_CANDIDATE_ATTEMPTS
    maximum_aurion_attempts: int = MAX_CANDIDATE_ATTEMPTS
    maximum_domain_fallback_attempts: int = 3
    maximum_replay_entries_loaded: int = 4096
    maximum_audit_event_keys: int = MAX_EVENT_PAYLOAD_KEYS
    maximum_audit_event_string_length: int = MAX_EVENT_PAYLOAD_STRING_LENGTH
    maximum_queue_depth: int = 32
    maximum_simultaneous_local_requests: int = 4
    maximum_traversal_seconds: int = 300
    maximum_evidence_output_bytes: int = 8_388_608
    maximum_temporary_artefacts: int = 128
    maximum_recovery_attempts: int = 3
    maximum_restart_attempts: int = 3
    maximum_failure_records: int = 1024

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


USAGE_TO_BUDGET = {
    "request_bytes": "maximum_request_bytes",
    "eie_bytes": "maximum_eie_bytes",
    "json_depth": "maximum_json_depth",
    "json_keys": "maximum_json_keys",
    "string_length": "maximum_string_length",
    "list_length": "maximum_list_length",
    "evidence_references": "maximum_evidence_references",
    "corroboration_sources": "maximum_corroboration_sources",
    "collective_signal_bytes": "maximum_collective_signal_bytes",
    "collective_signal_keys": "maximum_collective_signal_keys",
    "token_count": "maximum_token_count",
    "duplicate_token_names": "maximum_duplicate_token_names",
    "candidate_attempts": "maximum_candidate_attempts",
    "candidate_count": "maximum_candidate_count",
    "aurion_attempts": "maximum_aurion_attempts",
    "domain_fallback_attempts": "maximum_domain_fallback_attempts",
    "replay_entries_loaded": "maximum_replay_entries_loaded",
    "audit_event_keys": "maximum_audit_event_keys",
    "audit_event_string_length": "maximum_audit_event_string_length",
    "queue_depth": "maximum_queue_depth",
    "simultaneous_local_requests": "maximum_simultaneous_local_requests",
    "traversal_seconds": "maximum_traversal_seconds",
    "evidence_output_bytes": "maximum_evidence_output_bytes",
    "temporary_artefacts": "maximum_temporary_artefacts",
    "recovery_attempts": "maximum_recovery_attempts",
    "restart_attempts": "maximum_restart_attempts",
    "failure_records": "maximum_failure_records",
}


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    failures: tuple[str, ...]
    measured: dict[str, int]


def validate_resource_usage(
    usage: Mapping[str, int],
    *,
    policy: ResourceBudgetPolicy | None = None,
) -> BudgetDecision:
    selected = policy or ResourceBudgetPolicy()
    failures: list[str] = []
    measured: dict[str, int] = {}
    for name, value in sorted(usage.items()):
        if name not in USAGE_TO_BUDGET:
            failures.append(f"resource_metric_unknown:{name}")
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            failures.append(f"resource_metric_invalid:{name}")
            continue
        measured[name] = value
        maximum = getattr(selected, USAGE_TO_BUDGET[name])
        if value > maximum:
            failures.append(f"resource_limit_reached:{name}")
    return BudgetDecision(not failures, tuple(failures), measured)


class BoundedLocalCapacity:
    """Atomic single-host admission counter; it never grants authority."""

    def __init__(self, maximum: int) -> None:
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0:
            raise ValueError("local_capacity_bound_invalid")
        self.maximum = maximum
        self._active: set[str] = set()
        self._lock = RLock()

    def acquire(self, request_identifier: str) -> bool:
        if not isinstance(request_identifier, str) or not request_identifier:
            raise ValueError("request_identifier_invalid")
        with self._lock:
            if request_identifier in self._active or len(self._active) >= self.maximum:
                return False
            self._active.add(request_identifier)
            return True

    def release(self, request_identifier: str) -> None:
        with self._lock:
            self._active.discard(request_identifier)

    def status(self) -> dict[str, int]:
        with self._lock:
            return {"active": len(self._active), "maximum": self.maximum}


def build_resource_budget_snapshot(
    policy: ResourceBudgetPolicy | None = None,
) -> dict[str, object]:
    selected = policy or ResourceBudgetPolicy()
    payload: dict[str, object] = {
        "resource_budget_version": RESOURCE_BUDGET_VERSION,
        "desktop_scope": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "operational_authority": False,
        "limits": selected.as_dict(),
        "usage_metric_count": len(USAGE_TO_BUDGET),
        "usage_to_budget": dict(sorted(USAGE_TO_BUDGET.items())),
        "validation_status": "PASS",
    }
    return {**payload, "snapshot_digest": generate_digest(payload)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pass 8 resource budget evidence")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = build_resource_budget_snapshot()
    if args.output:
        atomic_json(Path(args.output), result)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
