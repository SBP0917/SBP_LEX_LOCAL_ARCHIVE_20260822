from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.config.thresholds import apply_thresholds
from sbp_lex.shared.hash_chain import append_hash_entry
from sbp_lex.governance.procedural_truth_envelope import validate_pt_evidence_envelope


def run_threshold_conditioning(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    conditioned_state = apply_thresholds(working_state)

    threshold_snapshot = conditioned_state.get("governance_feedback", {}).get("threshold_snapshot", {})

    envelope_valid, failures = validate_pt_evidence_envelope(conditioned_state)
    result = "PASS" if envelope_valid else "FAIL"

    conditioned_state.setdefault("governance_feedback", {})["threshold_conditioning"] = {
        "result": result,
        "threshold_snapshot": threshold_snapshot,
        "failures": failures,
    }

    conditioned_state.setdefault("audit_trace", []).append(
        {
            "stage": "threshold_conditioning",
            "result": result,
            "computed_tier": threshold_snapshot.get("computed_tier"),
        }
    )

    return append_hash_entry(
        conditioned_state,
        stage="procedural_truth",
        payload={
            "substage": "threshold_conditioning",
            "computed_tier": threshold_snapshot.get("computed_tier"),
            "financial_tier": threshold_snapshot.get("financial_tier"),
        },
    )
