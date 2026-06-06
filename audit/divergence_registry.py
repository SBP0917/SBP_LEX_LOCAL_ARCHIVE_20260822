from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from sbp_lex.security.pqc import generate_digest


class DivergenceRegistry:
    def __init__(self) -> None:
        self._registry: List[Dict[str, Any]] = []

    def register(
        self,
        *,
        divergence_type: str,
        stage: str,
        expected: Any,
        actual: Any,
        severity: str,
        request_fingerprint: str | None = None,
    ) -> Dict[str, Any]:
        sequence = len(self._registry) + 1
        record = {
            "sequence": sequence,
            "timestamp": f"DIVERGENCE_EVENT_{sequence:012d}",
            "timestamp_authority": "CANONICAL_RUNTIME",
            "divergence_type": divergence_type,
            "stage": stage,
            "expected": deepcopy(expected),
            "actual": deepcopy(actual),
            "severity": severity,
            "request_fingerprint": request_fingerprint,
        }
        record["divergence_hash"] = generate_digest(record)
        self._registry.append(deepcopy(record))
        return record

    def register_parity_divergence(
        self,
        *,
        stage: str,
        expected: Any,
        actual: Any,
        request_fingerprint: str | None = None,
        severity: str = "HIGH",
    ) -> Dict[str, Any]:
        return self.register(
            divergence_type="PARITY_DIVERGENCE",
            stage=stage,
            expected=expected,
            actual=actual,
            severity=severity,
            request_fingerprint=request_fingerprint,
        )

    def register_runtime_divergence(
        self,
        *,
        stage: str,
        expected: Any,
        actual: Any,
        request_fingerprint: str | None = None,
        severity: str = "MEDIUM",
    ) -> Dict[str, Any]:
        return self.register(
            divergence_type="RUNTIME_DIVERGENCE",
            stage=stage,
            expected=expected,
            actual=actual,
            severity=severity,
            request_fingerprint=request_fingerprint,
        )

    def verify(self) -> tuple[bool, list[str]]:
        failures: list[str] = []
        for index, item in enumerate(self._registry):
            rebuilt = {key: value for key, value in item.items() if key != "divergence_hash"}
            if generate_digest(rebuilt) != item.get("divergence_hash"):
                failures.append(f"DIVERGENCE_REGISTRY_CORRUPTION:{index}")
        return len(failures) == 0, failures

    def export(self) -> List[Dict[str, Any]]:
        return deepcopy(self._registry)

    def count(self) -> int:
        return len(self._registry)

    def by_severity(self, severity: str) -> List[Dict[str, Any]]:
        return [item for item in self._registry if item.get("severity") == severity]

    def by_type(self, divergence_type: str) -> List[Dict[str, Any]]:
        return [item for item in self._registry if item.get("divergence_type") == divergence_type]
