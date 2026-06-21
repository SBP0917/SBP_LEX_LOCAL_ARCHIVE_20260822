from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.governance.evidence_engine import run_evidence_validation
from sbp_lex.governance.corroboration_engine import run_corroboration_validation
from sbp_lex.governance.threshold_conditioning_engine import run_threshold_conditioning
from sbp_lex.governance.procedural_consistency_engine import run_procedural_consistency
from sbp_lex.governance.procedural_truth_engine import finalize_procedural_truth

PROCEDURAL_TRUTH_ORDER = [
    run_evidence_validation,
    run_threshold_conditioning,
    run_corroboration_validation,
    run_procedural_consistency,
    finalize_procedural_truth,
]


def run_procedural_truth_pipeline(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    for engine in PROCEDURAL_TRUTH_ORDER:
        working_state = engine(working_state)

        if working_state.get("procedural_truth_result") == "FAIL":
            working_state["decision"] = (
                "ESCALATE"
                if working_state.get("procedural_truth_failure_outcome") == "ESCALATE"
                else "DENY"
            )
            working_state["execution_result"] = "HALT"
            working_state["execution_verified"] = False
            working_state["governed_reentry"] = {
                "reentry_permitted": False,
                "retry_eligible": False,
                "reason": "procedural_truth_failure_requires_corrected_state",
                "required_action": "full_retraversal_after_correction",
                "required_corrections": [
                    "corrected_evidence",
                    "corrected_source_package",
                    "corrected_validation_state",
                    "full_retraversal",
                ],
            }
            return working_state

    if working_state.get("procedural_truth_result") != "PASS":
        working_state["procedural_truth_result"] = "FAIL"
        working_state["decision"] = (
            "ESCALATE"
            if working_state.get("procedural_truth_failure_outcome") == "ESCALATE"
            else "DENY"
        )
        working_state["execution_result"] = "HALT"

    return working_state
