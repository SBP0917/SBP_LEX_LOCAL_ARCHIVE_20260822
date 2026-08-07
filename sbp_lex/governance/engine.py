from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.governance.admissibility_engine import run_admissibility_evaluation
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.results import enforce_result
from sbp_lex.security.authority_boundary import validate_canonical_upstream
from sbp_lex.security.governed_stage_evidence import (
    append_governance_history,
    append_stage_finalisation,
    build_stage_evidence,
    invalidate_from_stage,
    live_state_hash_valid,
    stage_already_completed,
    stage_token_payload,
    validate_constraint_continuity,
)
from sbp_lex.shared.hash_chain import rebuild_state_hash


def run_governance(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    state_hash_entering_stage = working_state.get("state_hash")
    boundary_failures: list[str] = []
    already_completed = stage_already_completed(working_state, "governance")
    if not live_state_hash_valid(working_state):
        boundary_failures.append("governance_entry_state_hash_invalid")
    working_state = invalidate_from_stage(working_state, "governance")
    if already_completed:
        boundary_failures.append("governance_reentry_requires_full_retraversal")
    upstream_valid, upstream_failures = validate_canonical_upstream(
        working_state,
        required_tokens=("authority", "procedural_truth", "classification", "licensing"),
    )

    working_state = run_admissibility_evaluation(working_state)

    admissibility = working_state.get("governance_feedback", {}).get("admissibility", {})

    governance_result = enforce_result("governance", admissibility.get("result", "DENY"))
    governance_reason = admissibility.get("reason", "governance_reason_unset")
    constraints_valid, constraint_failures = validate_constraint_continuity(
        working_state, through_stage="licensing"
    )
    if not constraints_valid:
        boundary_failures.extend(constraint_failures)
    failures = sorted(
        set(
            list(admissibility.get("failures", []))
            + upstream_failures
            + boundary_failures
        )
    )
    if not upstream_valid or boundary_failures:
        governance_result = "DENY"
        governance_reason = "confused_deputy_rejected"

    working_state["governance_result"] = governance_result
    working_state["governance_reason"] = governance_reason

    if governance_result == "ESCALATE":
        working_state["decision"] = "ESCALATE"
        working_state["execution_result"] = "HALT"
    elif governance_result == "DENY":
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state["last_denied_fingerprint"] = working_state.get("request_fingerprint")

    working_state.setdefault("governance_feedback", {})["governance"] = {
        "result": governance_result,
        "reason": governance_reason,
        "failures": failures,
    }

    working_state["governance_state"] = {
        "result": governance_result,
        "reason": governance_reason,
        "failures": failures,
        "admissibility": deepcopy(dict(admissibility)),
        "authority_first_result": working_state.get("authority_first_result"),
        "procedural_truth_result": working_state.get("procedural_truth_result"),
        "classification_result": working_state.get("classification_result"),
        "licensing_result": working_state.get("licensing_result"),
    }
    working_state = append_governance_history(
        working_state,
        result=governance_result,
        reason=governance_reason,
        failures=failures,
    )

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "governance",
            "result": governance_result,
            "reason": governance_reason,
        }
    )

    working_state["state_hash"] = rebuild_state_hash(working_state)
    working_state["governance_evidence"] = build_stage_evidence(
        working_state,
        stage="governance",
        state_hash_entering_stage=state_hash_entering_stage,
    )
    if governance_result == "ALLOW":
        working_state = issue_token(
            working_state,
            name="governance",
            issued_at_stage="governance",
            payload=stage_token_payload(working_state, "governance"),
        )
    return append_stage_finalisation(working_state, stage="governance")
