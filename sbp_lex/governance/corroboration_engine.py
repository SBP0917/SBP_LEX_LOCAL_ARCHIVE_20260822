from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.config.thresholds import validate_threshold_conditioning_state
from sbp_lex.security.threshold_tokens import (
    required_threshold_token_names,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.hash_chain import append_hash_entry


def run_corroboration_validation(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    envelope = working_state.get("pt_evidence_envelope", {})
    evidence = envelope.get("source_records", []) if isinstance(envelope, Mapping) else []
    envelope = envelope if isinstance(envelope, Mapping) else {}

    corroboration_required = int(working_state.get("corroboration_required", 0))
    assessment = (
        envelope.get("source_assessment", {})
        if isinstance(envelope, Mapping)
        else {}
    )
    assessment = assessment if isinstance(assessment, Mapping) else {}
    evidence_count = int(assessment.get("source_count_qualifying", 0))

    threshold_consistent = (
        corroboration_required in {2, 3, 5}
        and envelope.get("threshold_requirement") == corroboration_required
        and assessment.get("corroboration_required")
        == corroboration_required
    )
    threshold_valid, threshold_failures = validate_threshold_conditioning_state(
        working_state,
        require_complete=True,
        require_observation=False,
    )
    threshold_consistent = threshold_consistent and threshold_valid
    corroboration_met = (
        threshold_consistent and evidence_count >= corroboration_required
    )

    working_state["corroboration_met"] = corroboration_met
    threshold_snapshot = working_state.setdefault("governance_feedback", {}).get(
        "threshold_snapshot", {}
    )
    threshold_snapshot["qualified_evidence_count"] = evidence_count
    threshold_snapshot["corroboration_met"] = corroboration_met
    threshold_state = working_state.get("threshold_conditioning_state", {})
    threshold_state = (
        threshold_state if isinstance(threshold_state, Mapping) else {}
    )
    threshold_payload = threshold_state.get("payload", {})
    threshold_payload = (
        deepcopy(dict(threshold_payload))
        if isinstance(threshold_payload, Mapping)
        else {}
    )
    if threshold_payload:
        threshold_payload["qualified_evidence_count"] = evidence_count
        threshold_payload["corroboration_met"] = corroboration_met
        threshold_state_digest = generate_digest(threshold_payload)
        working_state["threshold_conditioning_state"] = {
            "payload": threshold_payload,
            "threshold_state_digest": threshold_state_digest,
        }
        threshold_snapshot.update(deepcopy(threshold_payload))
        threshold_snapshot["threshold_state_digest"] = threshold_state_digest

    result = "PASS" if corroboration_met else "FAIL"
    tier = str(working_state.get("safety_profile", {}).get("computed_tier", "TOP"))
    failure_outcome = None if corroboration_met else (
        "ESCALATE" if tier == "TOP" else "REFINE"
    )

    working_state.setdefault("governance_feedback", {})["corroboration"] = {
        "result": result,
        "corroboration_required": corroboration_required,
        "evidence_count": evidence_count,
        "qualifying_source_count": evidence_count,
        "raw_evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        "rejected_source_count": assessment.get("source_count_rejected", 0),
        "duplicate_source_count": assessment.get("source_count_duplicates", 0),
        "source_identity_summary": deepcopy(
            assessment.get("source_identity_summary", [])
        ),
        "threshold_consistent": threshold_consistent,
        "threshold_validation_failures": threshold_failures,
        "evidentiary_sufficiency_result": assessment.get(
            "evidentiary_sufficiency_result"
        ),
        "source_assessment_digest": assessment.get(
            "source_assessment_digest"
        ),
        "tier": tier,
        "failure_outcome": failure_outcome,
    }

    tokens = working_state.setdefault("tokens", {})
    tokens.pop("threshold_bundle", None)
    for token_name in required_threshold_token_names():
        tokens.pop(token_name, None)
    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "corroboration",
            "result": result,
            "corroboration_required": corroboration_required,
            "evidence_count": evidence_count,
            "source_assessment_digest": assessment.get(
                "source_assessment_digest"
            ),
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
            "qualifying_source_count": evidence_count,
            "evidentiary_sufficiency_result": assessment.get(
                "evidentiary_sufficiency_result"
            ),
            "source_assessment_digest": assessment.get(
                "source_assessment_digest"
            ),
            "request_fingerprint": working_state.get("request_fingerprint"),
            "eie_digest": working_state.get("eie_hash"),
            "state_hash": working_state.get("state_hash"),
        },
    )
