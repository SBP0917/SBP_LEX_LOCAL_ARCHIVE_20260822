from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.governance.admissibility_engine import run_admissibility_evaluation
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry
from sbp_lex.shared.results import enforce_result
from sbp_lex.security.authority_boundary import validate_canonical_upstream


def run_governance(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    upstream_valid, upstream_failures = validate_canonical_upstream(
        working_state,
        required_tokens=("authority", "procedural_truth", "classification", "licensing"),
    )

    working_state = run_admissibility_evaluation(working_state)

    admissibility = working_state.get("governance_feedback", {}).get("admissibility", {})

    governance_result = enforce_result("governance", admissibility.get("result", "DENY"))
    governance_reason = admissibility.get("reason", "governance_reason_unset")
    failures = list(admissibility.get("failures", [])) + upstream_failures
    if not upstream_valid:
        governance_result = "DENY"
        governance_reason = "confused_deputy_rejected"

    working_state["governance_result"] = governance_result
    working_state["governance_reason"] = governance_reason

    if governance_result == "ALLOW":
        working_state = issue_token(
            working_state,
            name="governance",
            issued_at_stage="governance",
            payload={
                "governance_result": governance_result,
                "governance_reason": governance_reason,
                "authority_first_result": working_state.get("authority_first_result"),
                "procedural_truth_result": working_state.get("procedural_truth_result"),
                "classification_result": working_state.get("classification_result"),
                "licensing_result": working_state.get("licensing_result"),
            },
        )
    elif governance_result == "ESCALATE":
        working_state["decision"] = "ESCALATE"
        working_state["execution_result"] = "HALT"
    else:
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state["last_denied_fingerprint"] = working_state.get("request_fingerprint")

    working_state.setdefault("governance_feedback", {})["governance"] = {
        "result": governance_result,
        "reason": governance_reason,
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "governance",
            "result": governance_result,
            "reason": governance_reason,
        }
    )

    return append_hash_entry(
        working_state,
        stage="governance",
        payload={
            "governance_result": governance_result,
            "governance_reason": governance_reason,
            "failures": failures,
        },
  )
