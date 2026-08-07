from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.governance.reentry_engine import evaluate_reentry
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.authority_boundary import validate_governance_handoff_to_grc
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.results import enforce_result
from sbp_lex.security.governed_stage_evidence import (
    append_stage_finalisation,
    build_stage_evidence,
    invalidate_from_stage,
    stage_already_completed,
    stage_token_payload,
)
from sbp_lex.shared.hash_chain import rebuild_state_hash


def run_grc(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    state_hash_entering_stage = working_state.get("state_hash")
    already_completed = stage_already_completed(working_state, "grc")
    handoff_valid, handoff_failures = validate_governance_handoff_to_grc(
        working_state
    )
    working_state = invalidate_from_stage(working_state, "grc")
    if already_completed:
        handoff_failures = sorted(
            set(
                handoff_failures
                + ["grc_reentry_requires_full_retraversal"]
            )
        )
        handoff_valid = False

    governance_result = enforce_result("governance", working_state.get("governance_result", "DENY"))
    governance_reason = working_state.get("governance_reason", "governance_reason_unset")
    if not handoff_valid:
        governance_result = "DENY"
        governance_reason = "grc_upstream_invalid"
        working_state["governance_result"] = governance_result
        working_state["governance_reason"] = governance_reason
    reentry = evaluate_reentry(working_state)

    if governance_result == "ALLOW" and handoff_valid:
        grc_result = "PASS" if (
            not reentry.get("prior_denied_fingerprint")
            or reentry.get("reentry_permitted") is True
        ) else "DENY"
        grc_reason = (
            "governed_response_pass"
            if grc_result == "PASS"
            else "governed_reentry_not_permitted"
        )
        grc_outcome = {
            "structured_result": "ALLOW" if grc_result == "PASS" else "DENY",
            "controlled_return": grc_result != "PASS",
            "persistent_inoperability": grc_result != "PASS",
            "safe_state_required": grc_result != "PASS",
            "reentry": reentry,
            "denial_reason": None,
            "escalation_path": None,
        }
    elif governance_result == "ESCALATE":
        grc_result = "ESCALATE"
        grc_reason = governance_reason
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
        grc_result = "DENY"
        grc_reason = governance_reason
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

    working_state["grc_result"] = grc_result
    working_state["grc_reason"] = grc_reason
    working_state["governed_reentry"] = reentry
    if grc_result != "PASS":
        working_state["decision"] = "ESCALATE" if grc_result == "ESCALATE" else "DENY"
        working_state["execution_result"] = "HALT"
        working_state["last_denied_fingerprint"] = working_state.get("request_fingerprint")

    working_state.setdefault("governance_feedback", {})["grc"] = grc_outcome
    working_state["governance_feedback"]["grc"]["failures"] = sorted(
        set(handoff_failures)
    )

    history = working_state.get("governance_feedback", {}).get("history", [])
    context = working_state.get("context", {}) or {}
    working_state["grc_state"] = {
        "result": grc_result,
        "reason": grc_reason,
        "governance_result": governance_result,
        "governance_reason": governance_reason,
        "outcome": deepcopy(grc_outcome),
        "reentry": deepcopy(reentry),
        "governance_history_digest": generate_digest(history),
        "reentry_input_snapshot": {
            "last_denied_fingerprint": working_state.get(
                "last_denied_fingerprint"
            ),
            "prior_denied_fingerprint": context.get(
                "prior_denied_fingerprint"
            ),
            "material_change_declared": context.get(
                "material_change_declared", False
            ),
            "material_change_reason": context.get("material_change_reason"),
            "escalation_path_available": context.get(
                "escalation_path_available", False
            ),
        },
        "failures": sorted(set(handoff_failures)),
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "grc",
            "structured_result": grc_outcome["structured_result"],
            "persistent_inoperability": grc_outcome["persistent_inoperability"],
            "safe_state_required": grc_outcome["safe_state_required"],
            "reentry": reentry,
        }
    )

    working_state["state_hash"] = rebuild_state_hash(working_state)
    working_state["grc_evidence"] = build_stage_evidence(
        working_state,
        stage="grc",
        state_hash_entering_stage=state_hash_entering_stage,
    )
    working_state = issue_token(
        working_state,
        name="grc",
        issued_at_stage="grc",
        payload=stage_token_payload(working_state, "grc"),
    )

    return append_stage_finalisation(working_state, stage="grc")
