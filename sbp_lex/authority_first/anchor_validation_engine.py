from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry

VALID_RESULTS = {"PASS", "FAIL", "ESCALATE"}


def run_anchor_validation(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    authority = str(working_state.get("resolved_authority", "")).strip()
    jurisdiction = str(working_state.get("jurisdiction", "")).strip()
    collective_status = working_state.get("collective_signal_status")

    failures: list[str] = []

    if not authority:
        failures.append("authority_missing")

    if not jurisdiction:
        failures.append("jurisdiction_missing")

    if collective_status != "ATTACHED":
        failures.append("collective_signals_not_attached")

    passed = len(failures) == 0

    working_state["authority_first_result"] = "PASS" if passed else "FAIL"
    working_state["authority_first_reason"] = "anchor_validation_complete" if passed else ",".join(failures)

    working_state.setdefault("governance_feedback", {})["anchor_validation"] = {
        "result": working_state["authority_first_result"],
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "anchor_validation",
            "result": working_state["authority_first_result"],
            "failures": failures,
        }
    )

    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "anchor_validation",
            "result": working_state["authority_first_result"],
            "failures": failures,
        },
  )
