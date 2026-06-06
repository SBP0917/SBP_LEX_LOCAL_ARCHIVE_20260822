from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.governance.governance_rules import determine_governance_result
from sbp_lex.shared.hash_chain import append_hash_entry


def run_admissibility_evaluation(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    determination = determine_governance_result(working_state)

    working_state.setdefault("governance_feedback", {})["admissibility"] = {
        "result": determination["result"],
        "reason": determination["reason"],
        "failures": determination["failures"],
        "escalation_required": determination["escalation_required"],
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "governance_admissibility",
            "result": determination["result"],
            "reason": determination["reason"],
        }
    )

    return append_hash_entry(
        working_state,
        stage="governance",
        payload={
            "substage": "admissibility",
            "result": determination["result"],
            "reason": determination["reason"],
            "failures": determination["failures"],
        },
    )
