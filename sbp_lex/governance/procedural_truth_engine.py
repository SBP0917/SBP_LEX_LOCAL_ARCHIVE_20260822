from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry


def finalize_procedural_truth(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    governance_feedback = working_state.get("governance_feedback", {})

    failures: list[str] = []

    required_checks = [
        "evidence_validation",
        "corroboration",
        "threshold_conditioning",
        "procedural_consistency",
    ]

    for check in required_checks:
        result = governance_feedback.get(check, {}).get("result")
        if result != "PASS":
            failures.append(check)

    passed = len(failures) == 0
    corroboration = governance_feedback.get("corroboration", {})
    threshold_failures = governance_feedback.get("threshold_conditioning", {}).get("failures", [])
    if passed:
        pt_outcome = "PT_PASS"
        failure_outcome = None
    elif threshold_failures:
        pt_outcome = "PT_FAIL"
        failure_outcome = "FAIL"
    else:
        failure_outcome = corroboration.get("failure_outcome", "REFINE")
        pt_outcome = "PT_ESCALATE" if failure_outcome == "ESCALATE" else "PT_REFINE"

    deterministic_failures = sorted(
        set(
            failures
            + list(threshold_failures)
            + ([] if passed else list(working_state.get("pt_evidence_envelope", {}).get("deterministic_failure_reasons", [])))
        )
    )

    working_state["procedural_truth_result"] = "PASS" if passed else "FAIL"
    working_state["procedural_truth_outcome"] = pt_outcome
    working_state["procedural_truth_failure_reasons"] = deterministic_failures
    working_state["procedural_truth_failure_outcome"] = failure_outcome

    if passed:
        working_state = issue_token(
            working_state,
            name="procedural_truth",
            issued_at_stage="procedural_truth",
            payload={
                "procedural_truth_result": "PASS",
                "procedural_truth_outcome": pt_outcome,
                "pt_evidence_envelope_digest": working_state.get("pt_evidence_envelope_digest"),
                "checks": required_checks,
            },
        )

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "procedural_truth_finalization",
            "result": working_state["procedural_truth_result"],
            "failures": failures,
            "pt_outcome": pt_outcome,
            "deterministic_failure_reasons": deterministic_failures,
            "failure_outcome": failure_outcome,
        }
    )

    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "procedural_truth_finalization",
            "result": working_state["procedural_truth_result"],
            "failures": failures,
            "pt_outcome": pt_outcome,
            "deterministic_failure_reasons": deterministic_failures,
            "failure_outcome": failure_outcome,
        },
    )
