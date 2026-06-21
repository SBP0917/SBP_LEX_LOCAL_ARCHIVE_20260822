from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.governance.engine import run_governance
from sbp_lex.governance.grc import run_grc


def run_governance_pipeline(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    working_state = run_governance(working_state)
    working_state = run_grc(working_state)

    if (
        working_state.get("governance_result") == "ALLOW"
        and working_state.get("grc_result") == "PASS"
    ):
        return working_state

    if working_state.get("governance_result") == "ESCALATE":
        working_state["decision"] = "ESCALATE"
        working_state["execution_result"] = "HALT"
        return working_state

    working_state["decision"] = "DENY"
    working_state["execution_result"] = "HALT"
    working_state["last_denied_fingerprint"] = working_state.get("request_fingerprint")
    return working_state
