from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.domains.base_domain import DOMAIN_ESCALATE, DOMAIN_FAIL
from sbp_lex.domains.legal_domain import LegalDomain
from sbp_lex.domains.operational_domain import OperationalDomain
from sbp_lex.domains.risk_domain import RiskDomain
from sbp_lex.domains.sovereign_domain import SovereignDomain
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry

DOMAIN_ENGINES = [
    LegalDomain(),
    SovereignDomain(),
    OperationalDomain(),
    RiskDomain(),
]


def run_domain_wrap(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    if working_state.get("governance_result") != "ALLOW":
        working_state["domain_result"] = DOMAIN_FAIL
        working_state["decision"] = working_state.get("decision", "DENY")
        working_state["execution_result"] = "HALT"
        working_state.setdefault("governance_feedback", {})["domain_wrap"] = {
            "result": DOMAIN_FAIL,
            "reason": "governance_not_allowed",
            "domain_results": [],
        }
        return append_hash_entry(
            working_state,
            stage="domain_wrap",
            payload={"domain_result": DOMAIN_FAIL, "reason": "governance_not_allowed"},
        )

    domain_results = []
    failures: list[str] = []
    escalations: list[str] = []

    for domain in DOMAIN_ENGINES:
        result = domain.evaluate(working_state)
        domain_results.append(result)

        if result.get("result") == DOMAIN_FAIL:
            failures.append(result.get("domain", "unknown_domain"))

        if result.get("result") == DOMAIN_ESCALATE:
            escalations.append(result.get("domain", "unknown_domain"))

    if escalations:
        final_result = DOMAIN_ESCALATE
        reason = "domain_escalation_required"
        working_state["decision"] = "ESCALATE"
        working_state["execution_result"] = "HALT"
    elif failures:
        final_result = DOMAIN_FAIL
        reason = "domain_validation_failed"
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
    else:
        final_result = "pass"
        reason = "domain_wrap_passed"

    working_state["domain_result"] = final_result

    working_state.setdefault("governance_feedback", {})["domain_wrap"] = {
        "result": final_result,
        "reason": reason,
        "domain_results": domain_results,
        "failures": failures,
        "escalations": escalations,
    }

    if final_result == "pass":
        working_state = issue_token(
            working_state,
            name="domain",
            issued_at_stage="domain_wrap",
            payload={
                "domain_result": final_result,
                "domain_results": domain_results,
            },
        )

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "domain_wrap",
            "result": final_result,
            "reason": reason,
            "failures": failures,
            "escalations": escalations,
        }
    )

    return append_hash_entry(
        working_state,
        stage="domain_wrap",
        payload={
            "domain_result": final_result,
            "reason": reason,
            "domain_results": domain_results,
        },
      )
