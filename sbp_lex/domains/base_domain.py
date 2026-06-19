from __future__ import annotations

from typing import Any, Dict, Mapping, Protocol

DOMAIN_PASS = "pass"
DOMAIN_REFINE_CANDIDATE = "refine_candidate"
DOMAIN_REDEFINE_CANDIDATE = "redefine_candidate"
DOMAIN_REQUIRE_NEXT_CANDIDATE = "require_next_candidate"
DOMAIN_ESCALATE = "escalate"
DOMAIN_RESULTS = {
    DOMAIN_PASS,
    DOMAIN_REFINE_CANDIDATE,
    DOMAIN_REDEFINE_CANDIDATE,
    DOMAIN_REQUIRE_NEXT_CANDIDATE,
    DOMAIN_ESCALATE,
}

# Compatibility alias for existing domain engines. Legacy failure now requests
# a governed candidate change and never propagates the uncontrolled "fail" value.
DOMAIN_FAIL = DOMAIN_REQUIRE_NEXT_CANDIDATE


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
    if result == "fail":
        result = DOMAIN_REQUIRE_NEXT_CANDIDATE
    elif result not in DOMAIN_RESULTS:
        result = DOMAIN_ESCALATE

    return {
        "domain": domain,
        "result": result,
        "reason": reason,
        "failures": failures or [],
        "evidence": evidence or {},
    }


def domain_result_has_failed(result: Mapping[str, Any]) -> bool:
    return result.get("result") != DOMAIN_PASS
