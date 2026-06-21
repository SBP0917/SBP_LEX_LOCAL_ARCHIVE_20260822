from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.threshold_tokens import (
    issue_threshold_bundle_token,
    issue_threshold_component_tokens,
)
from sbp_lex.governance.procedural_truth_envelope import qualified_sources
from sbp_lex.shared.hash_chain import append_hash_entry


def run_corroboration_validation(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    envelope = working_state.get("pt_evidence_envelope", {})
    evidence = envelope.get("source_records", []) if isinstance(envelope, Mapping) else []

    corroboration_required = int(working_state.get("corroboration_required", 0))
    qualified = qualified_sources(evidence)
    evidence_count = len(qualified)

    corroboration_met = evidence_count >= corroboration_required

    working_state["corroboration_met"] = corroboration_met
    threshold_snapshot = working_state.setdefault("governance_feedback", {}).get(
        "threshold_snapshot", {}
    )
    threshold_snapshot["qualified_evidence_count"] = evidence_count
    threshold_snapshot["corroboration_met"] = corroboration_met

    result = "PASS" if corroboration_met else "FAIL"
    tier = str(working_state.get("safety_profile", {}).get("computed_tier", "TOP"))
    failure_outcome = None if corroboration_met else (
        "ESCALATE" if tier == "TOP" else "REFINE"
    )

    working_state.setdefault("governance_feedback", {})["corroboration"] = {
        "result": result,
        "corroboration_required": corroboration_required,
        "evidence_count": evidence_count,
        "raw_evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        "tier": tier,
        "failure_outcome": failure_outcome,
    }

    working_state = issue_threshold_component_tokens(
        working_state,
        issued_at_stage="procedural_truth",
    )

    working_state = issue_threshold_bundle_token(
        working_state,
        issued_at_stage="procedural_truth",
    )

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "corroboration",
            "result": result,
            "corroboration_required": corroboration_required,
            "evidence_count": evidence_count,
        }
    )

    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "corroboration",
            "result": result,
            "corroboration_required": corroboration_required,
            "evidence_count": evidence_count,
        },
    )
