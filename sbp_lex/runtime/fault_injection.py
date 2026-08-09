from __future__ import annotations

import os
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sbp_lex.security.pqc import generate_digest


FAULT_INJECTION_VERSION = "PASS8_DESKTOP_V1_TEST_FAULT_INJECTION_V1"
TEST_ENABLE_VARIABLE = "SBP_LEX_TEST_FAULT_INJECTION"

CRITICAL_SEAMS = frozenset({
    "measured_startup", "eie_validation", "skg_contract_validation",
    "dtn_contract_validation", "bridge_validation", "hard_entry",
    "state_construction", "collective_attachment", "root_of_trust",
    "procedural_truth", "classification", "licensing", "governance",
    "grc", "domain", "aurion", "token_verification", "hash_chain_append",
    "execution_gate", "capability_issuance", "capability_consumption",
    "synthetic_effect_acknowledgement", "audit_finalisation", "replay_write",
    "persistence_write", "security_integrity_ledger_write", "shutdown",
    "backup", "restore", "cryptographic_provider_lookup",
    "signature_creation", "signature_verification",
})

FAULT_CLASSES = frozenset({
    "exception", "timeout", "malformed_return", "missing_return",
    "stale_return", "duplicated_return", "corrupted_bytes", "partial_write",
    "permission_denied", "provider_unavailable", "wrong_provider",
    "wrong_algorithm_metadata", "invalid_key_id", "revoked_key",
    "interrupted_operation", "process_termination_simulation",
    "memory_allocation_failure", "thread_creation_failure",
    "disk_space_exhaustion", "file_handle_exhaustion", "clock_source_failure",
    "nonce_source_failure",
})


class FaultInjectionDisabled(RuntimeError):
    pass


class InjectedFault(RuntimeError):
    def __init__(self, record: Mapping[str, Any]) -> None:
        self.record = deepcopy(dict(record))
        super().__init__(str(record.get("reason", "injected_fault")))


@dataclass(frozen=True)
class FaultSpec:
    fault_id: str
    seam: str
    fault_class: str
    request_fingerprint: str


class TestFaultInjector:
    """Deterministic fault seam available only under explicit test enablement."""

    __test__ = False

    def __init__(
        self,
        faults: Mapping[str, FaultSpec],
        *,
        explicitly_enabled: bool,
        environ: Mapping[str, str] | None = None,
        event_sink: Callable[[str, Mapping[str, Any]], Any] | None = None,
    ) -> None:
        source = os.environ if environ is None else environ
        if not explicitly_enabled or source.get(TEST_ENABLE_VARIABLE) != "1":
            raise FaultInjectionDisabled("fault_injection_unavailable_normal_runtime")
        self._faults = dict(faults)
        self._event_sink = event_sink
        self._records: list[dict[str, Any]] = []
        for seam, fault in self._faults.items():
            if seam != fault.seam or seam not in CRITICAL_SEAMS:
                raise ValueError("fault_seam_invalid")
            if fault.fault_class not in FAULT_CLASSES:
                raise ValueError("fault_class_invalid")
            if not fault.fault_id or not fault.request_fingerprint:
                raise ValueError("fault_identity_invalid")

    def trigger(self, seam: str, *, request_fingerprint: str) -> Any:
        fault = self._faults.get(seam)
        if fault is None:
            return None
        if request_fingerprint != fault.request_fingerprint:
            return None
        payload = {
            "fault_injection_version": FAULT_INJECTION_VERSION,
            "fault_id": fault.fault_id,
            "seam": fault.seam,
            "fault_class": fault.fault_class,
            "request_fingerprint": request_fingerprint,
            "reason": f"test_fault:{fault.seam}:{fault.fault_class}",
            "test_only": True,
            "authority_granted": False,
            "execution_result": "HALT",
        }
        record = {**payload, "fault_digest": generate_digest(payload)}
        self._records.append(record)
        if self._event_sink is not None:
            self._event_sink("fault_injection_activated", payload)
        if fault.fault_class == "missing_return":
            return {"fault_record": deepcopy(record), "value": None}
        if fault.fault_class == "malformed_return":
            return {"fault_record": deepcopy(record), "value": {"malformed": object()}}
        if fault.fault_class == "stale_return":
            return {"fault_record": deepcopy(record), "value": {"stale": True}}
        if fault.fault_class == "duplicated_return":
            return {"fault_record": deepcopy(record), "value": [{"duplicate": 1}, {"duplicate": 1}]}
        if fault.fault_class == "corrupted_bytes":
            return {"fault_record": deepcopy(record), "value": b"\x00CORRUPTED\xff"}
        if fault.fault_class == "partial_write":
            return {"fault_record": deepcopy(record), "value": b'{"partial":'}
        if fault.fault_class in {"wrong_provider", "wrong_algorithm_metadata", "invalid_key_id", "revoked_key"}:
            return {
                "fault_record": deepcopy(record),
                "value": {"cryptographic_profile_valid": False, "reason": fault.fault_class},
            }
        raise InjectedFault(record)

    def records(self) -> list[dict[str, Any]]:
        return deepcopy(self._records)
