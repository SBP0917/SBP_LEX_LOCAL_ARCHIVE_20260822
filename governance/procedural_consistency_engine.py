from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


def run_procedural_consistency(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    failures: list[str] = []

    governance_feedback = working_state.get("governance_feedback", {})

    evidence_validation = governance_feedback.get("evidence_validation", {})
    corroboration = governance_feedback.get("corroboration", {})
    threshold_conditioning = governance_feedback.get("threshold_conditioning", {})

    if evidence_validation.get("result") != "PASS":
        failures.append("evidence_validation_failed")

    if corroboration.get("result") != "PASS":
        failures.append("corroboration_failed")

    if threshold_conditioning.get("result") != "PASS":
        failures.append("threshold_conditioning_failed")

    result = "PASS" if len(failures) == 0 else "FAIL"

    working_state.setdefault("governance_feedback", {})["procedural_consistency"] = {
        "result": result,
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "procedural_consistency",
            "result": result,
            "failures": failures,
        }
    )

    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "procedural_consistency",
            "result": result,
            "failures": failures,
        },
    )
