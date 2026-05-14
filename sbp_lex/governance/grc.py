from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.governance.reentry_engine import evaluate_reentry
from sbp_lex.shared.hash_chain import append_hash_entry
from sbp_lex.shared.results import enforce_result


def run_grc(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    governance_result = enforce_result("governance", working_state.get("governance_result", "DENY"))
    governance_reason = working_state.get("governance_reason", "governance_reason_unset")
    reentry = evaluate_reentry(working_state)

    if governance_result == "ALLOW":
        grc_outcome = {
            "structured_result": "ALLOW",
            "controlled_return": False,
            "persistent_inoperability": False,
            "safe_state_required": False,
            "reentry": reentry,
            "denial_reason": None,
            "escalation_path": None,
        }
    elif governance_result == "ESCALATE":
        grc_outcome = {
            "structured_result": "ESCALATE",
            "controlled_return": True,
            "persistent_inoperability": True,
            "safe_state_required": True,
            "reentry": reentry,
            "denial_reason": governance_reason,
            "escalation_path": "authority_review_required",
        }
        working_state["decision"] = "ESCALATE"
        working_state["execution_result"] = "HALT"
    else:
        grc_outcome = {
            "structured_result": "DENY",
            "controlled_return": True,
            "persistent_inoperability": True,
            "safe_state_required": True,
            "reentry": reentry,
            "denial_reason": governance_reason,
            "escalation_path": None,
        }
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state["last_denied_fingerprint"] = working_state.get("request_fingerprint")

    working_state.setdefault("governance_feedback", {})["grc"] = grc_outcome

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "grc",
            "structured_result": grc_outcome["structured_result"],
            "persistent_inoperability": grc_outcome["persistent_inoperability"],
            "safe_state_required": grc_outcome["safe_state_required"],
            "reentry": reentry,
        }
    )

    return append_hash_entry(
        working_state,
        stage="governance",
        payload={
            "substage": "grc",
            "governance_result": governance_result,
            "grc_outcome": grc_outcome,
        },
    )
