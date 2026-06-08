from __future__ import annotations

from typing import Any, Dict, Mapping, Protocol

DOMAIN_PASS = "pass"
DOMAIN_FAIL = "fail"
DOMAIN_ESCALATE = "escalate"


class DomainEngine(Protocol):
    name: str

    def evaluate(self, state: Mapping[str, Any]) -> Dict[str, Any]:
        ...


def make_domain_result(
    *,
    domain: str,
    result: str,
    reason: str,
    failures: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
) -> Dict[str, Any]:
    if result not in {DOMAIN_PASS, DOMAIN_FAIL, DOMAIN_ESCALATE}:
        result = DOMAIN_FAIL

    return {
        "domain": domain,
        "result": result,
        "reason": reason,
        "failures": failures or [],
        "evidence": evidence or {},
    }


def domain_result_has_failed(result: Mapping[str, Any]) -> bool:
    return result.get("result") in {DOMAIN_FAIL, DOMAIN_ESCALATE}
