from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import CONVERGENCE_VERSION
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.domain_aurion_evidence import (
    constraint_snapshot as domain_aurion_constraint_snapshot,
    stage_projection as domain_aurion_stage_projection,
    validate_handoff_evidence,
    validate_stage_evidence as validate_domain_aurion_stage_evidence,
    validate_stage_history as validate_domain_aurion_stage_history,
)
from sbp_lex.security.governed_stage_evidence import (
    stage_projection as governed_stage_projection,
    validate_stage_evidence as validate_governed_stage_evidence,
)


ROOT_PT_PARITY_FIELDS = [
    "root_result",
    "root_reason",
    "root_evidence_digest",
    "procedural_truth_result",
    "procedural_truth_outcome",
    "pt_evidence_digest",
    "qualifying_source_count",
    "evidentiary_sufficiency_result",
    "computed_tier",
    "corroboration_required",
    "corroboration_observed",
]

GOVERNED_STAGE_PARITY_FIELDS = [
    "classification_result",
    "classification_reason",
    "classification_state_digest",
    "classification_live_state_digest",
    "classification_evidence_valid",
    "classification_evidence_failures_digest",
    "classification_evidence_digest",
    "classification_token_digest",
    "licensing_result",
    "licensing_reason",
    "licensing_state_digest",
    "licensing_live_state_digest",
    "licensing_evidence_valid",
    "licensing_evidence_failures_digest",
    "licensing_evidence_digest",
    "licensing_token_digest",
    "governance_result",
    "governance_reason",
    "governance_state_digest",
    "governance_live_state_digest",
    "governance_evidence_valid",
    "governance_evidence_failures_digest",
    "governance_evidence_digest",
    "governance_token_digest",
    "governance_history_digest",
    "grc_result",
    "grc_reason",
    "grc_state_digest",
    "grc_live_state_digest",
    "grc_evidence_valid",
    "grc_evidence_failures_digest",
    "grc_evidence_digest",
    "grc_token_digest",
    "governed_reentry_digest",
    "governed_constraint_digest",
]

DOMAIN_AURION_PARITY_FIELDS = [
    "domain_result",
    "domain_reason",
    "domain_state_digest",
    "domain_live_state_digest",
    "domain_evidence_valid",
    "domain_evidence_failures_digest",
    "domain_evidence_digest",
    "domain_token_digest",
    "domain_history_digest",
    "domain_history_valid",
    "domain_history_failures_digest",
    "domain_attempt_count",
    "domain_max_attempts",
    "domain_attempts_digest",
    "domain_results_digest",
    "domain_candidate_digest",
    "aurion15_result",
    "aurion_reason",
    "aurion_state_digest",
    "aurion_live_state_digest",
    "aurion_evidence_valid",
    "aurion_evidence_failures_digest",
    "aurion_evidence_digest",
    "aurion_token_digest",
    "aurion_history_digest",
    "aurion_history_valid",
    "aurion_history_failures_digest",
    "candidate_attempt_count",
    "generated_candidate_set_digest",
    "candidate_validations_digest",
    "admissible_candidate_set_digest",
    "ordered_candidate_set_digest",
    "rejected_candidates_digest",
    "selected_candidate_digest",
    "selected_pathway_digest",
    "domain_aurion_constraint_digest",
    "execution_convergence_handoff_digest",
    "execution_convergence_handoff_valid",
    "execution_convergence_handoff_failures_digest",
]

CONVERGENCE_COMPARISON_FIELDS = [
    "decision",
    "execution_result",
    *ROOT_PT_PARITY_FIELDS,
    *GOVERNED_STAGE_PARITY_FIELDS,
    *DOMAIN_AURION_PARITY_FIELDS,
]


def _record_digest(record: object, *names: str) -> object:
    if not isinstance(record, Mapping):
        return None
    for name in names:
        if record.get(name) not in (None, ""):
            return record.get(name)
    return None


def _record_payload(record: object) -> Mapping[str, Any]:
    if not isinstance(record, Mapping):
        return {}
    payload = record.get("payload", {})
    return payload if isinstance(payload, Mapping) else {}


def build_pipeline_convergence_proof(*, pipeline_a: Mapping[str, Any], pipeline_b: Mapping[str, Any] | None = None, mode: str) -> Dict[str, Any]:
    a_summary = _state_summary(pipeline_a)
    b_summary = _state_summary(pipeline_b) if pipeline_b is not None else None
    matched = True
    mismatches: list[str] = []
    if pipeline_b is not None:
        for key in CONVERGENCE_COMPARISON_FIELDS:
            if a_summary.get(key) != b_summary.get(key):
                matched = False
                mismatches.append(key)
    payload = {
        "version": CONVERGENCE_VERSION,
        "mode": mode,
        "pipeline_a": a_summary,
        "pipeline_b": b_summary,
        "comparison_fields": CONVERGENCE_COMPARISON_FIELDS,
        "root_pt_comparison_fields": ROOT_PT_PARITY_FIELDS,
        "governed_stage_comparison_fields": GOVERNED_STAGE_PARITY_FIELDS,
        "domain_aurion_comparison_fields": DOMAIN_AURION_PARITY_FIELDS,
        "root_pt_matched": (
            all(
                a_summary.get(field) == b_summary.get(field)
                for field in ROOT_PT_PARITY_FIELDS
            )
            if b_summary is not None
            else None
        ),
        "governed_stage_matched": (
            all(
                a_summary.get(field) == b_summary.get(field)
                for field in GOVERNED_STAGE_PARITY_FIELDS
            )
            if b_summary is not None
            else None
        ),
        "domain_aurion_matched": (
            all(
                a_summary.get(field) == b_summary.get(field)
                for field in DOMAIN_AURION_PARITY_FIELDS
            )
            if b_summary is not None
            else None
        ),
        "matched": matched,
        "mismatches": mismatches,
        "near_match_reconciliation_used": False,
    }
    signature = sign_payload(payload)
    return {**payload, "convergence_hash": generate_digest(payload), "signature": signature, "verified": verify_signature(payload, signature)}


def _state_summary(state: Mapping[str, Any] | None) -> Dict[str, Any] | None:
    if state is None:
        return None
    tokens = state.get("tokens", {})
    root_evidence = state.get("root_of_trust_evidence", {})
    root_payload = _record_payload(root_evidence)
    pt_evidence = state.get("procedural_truth_evidence", {})
    pt_payload = _record_payload(pt_evidence)
    certification = state.get("procedural_truth_certification", {})
    certification = (
        certification if isinstance(certification, Mapping) else {}
    )
    envelope = state.get("pt_evidence_envelope", {})
    envelope = envelope if isinstance(envelope, Mapping) else {}
    threshold_snapshot = state.get("governance_feedback", {}).get(
        "threshold_snapshot", {}
    )
    threshold_snapshot = (
        threshold_snapshot
        if isinstance(threshold_snapshot, Mapping)
        else {}
    )
    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash"),
        "pipeline_mode": state.get("pipeline_mode"),
        "governance_result": state.get("governance_result"),
        "domain_result": state.get("domain_result"),
        "aurion15_result": state.get("aurion15_result"),
        "execution_result": state.get("execution_result"),
        "decision": state.get("decision"),
        "threshold_bundle_hash": tokens.get("threshold_bundle", {}).get("digest"),
        "token_bundle_hash": tokens.get("token_bundle", {}).get("digest"),
        "audit_hash": state.get("audit_hash"),
        "root_result": state.get("authority_first_result"),
        "root_reason": state.get("authority_first_reason"),
        "root_evidence_digest": _record_digest(
            root_evidence, "root_evidence_digest", "evidence_digest"
        )
        or state.get("root_of_trust_evidence_anchor", {}).get(
            "anchor_digest"
        ),
        "root_stage_results_digest": generate_digest(
            root_payload.get(
                "stage_results",
                root_evidence.get(
                    "stage_results",
                    state.get("governance_feedback", {}).get(
                        "root_of_trust_stage_results", {}
                    ),
                )
                if isinstance(root_evidence, Mapping)
                else {},
            )
        ),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "procedural_truth_outcome": state.get("procedural_truth_outcome"),
        "pt_evidence_digest": _record_digest(
            pt_evidence,
            "pt_evidence_digest",
            "procedural_truth_evidence_digest",
            "evidence_digest",
        ),
        "qualifying_source_count": pt_payload.get(
            "source_count_qualifying",
            pt_payload.get(
                "qualifying_source_count",
                envelope.get("qualifying_source_count"),
            ),
        ),
        "evidentiary_sufficiency_result": pt_payload.get(
            "evidentiary_sufficiency_result",
            certification.get("certification_status"),
        ),
        "computed_tier": pt_payload.get(
            "computed_tier",
            pt_payload.get(
                "tier",
                state.get("safety_profile", {}).get("computed_tier"),
            ),
        ),
        "corroboration_required": pt_payload.get(
            "corroboration_required", state.get("corroboration_required")
        ),
        "corroboration_observed": pt_payload.get(
            "corroboration_observed",
            threshold_snapshot.get(
                "qualified_evidence_count",
                envelope.get("qualifying_source_count"),
            ),
        ),
        **governed_stage_summary(state),
        **domain_aurion_summary(state),
    }


def governed_stage_summary(state: Mapping[str, Any]) -> Dict[str, Any]:
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}

    def stage_values(stage: str) -> tuple[object, object, object, bool, str]:
        evidence = state.get(f"{stage}_evidence", {})
        evidence = evidence if isinstance(evidence, Mapping) else {}
        payload = evidence.get("payload", {})
        payload = payload if isinstance(payload, Mapping) else {}
        valid, failures = validate_governed_stage_evidence(state, stage)
        return (
            payload.get("stage_state_digest"),
            evidence.get("evidence_digest"),
            generate_digest(governed_stage_projection(state, stage)),
            valid,
            generate_digest(failures),
        )

    (
        classification_state_digest,
        classification_evidence_digest,
        classification_live_state_digest,
        classification_evidence_valid,
        classification_evidence_failures_digest,
    ) = stage_values("classification")
    (
        licensing_state_digest,
        licensing_evidence_digest,
        licensing_live_state_digest,
        licensing_evidence_valid,
        licensing_evidence_failures_digest,
    ) = stage_values("licensing")
    (
        governance_state_digest,
        governance_evidence_digest,
        governance_live_state_digest,
        governance_evidence_valid,
        governance_evidence_failures_digest,
    ) = stage_values("governance")
    (
        grc_state_digest,
        grc_evidence_digest,
        grc_live_state_digest,
        grc_evidence_valid,
        grc_evidence_failures_digest,
    ) = stage_values("grc")
    history = state.get("governance_feedback", {}).get("history", [])
    classification = state.get("classification", {})
    classification = classification if isinstance(classification, Mapping) else {}
    constraints = {
        "computed_tier": state.get("safety_profile", {}).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "resolved_authority": state.get("resolved_authority"),
        "jurisdiction": state.get("jurisdiction"),
        "autonomy_level": classification.get("autonomy_level"),
        "autonomy_ceiling": classification.get("autonomy_ceiling"),
        "operational_scope": classification.get("operational_scope"),
        "licensing_scope": state.get("licensing_scope"),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "procedural_truth_outcome": state.get("procedural_truth_outcome"),
    }
    return {
        "classification_result": state.get("classification_result"),
        "classification_reason": state.get("classification_reason"),
        "classification_state_digest": classification_state_digest,
        "classification_live_state_digest": classification_live_state_digest,
        "classification_evidence_valid": classification_evidence_valid,
        "classification_evidence_failures_digest": classification_evidence_failures_digest,
        "classification_evidence_digest": classification_evidence_digest,
        "classification_token_digest": tokens.get("classification", {}).get(
            "digest"
        ),
        "licensing_result": state.get("licensing_result"),
        "licensing_reason": state.get("licensing_reason"),
        "licensing_state_digest": licensing_state_digest,
        "licensing_live_state_digest": licensing_live_state_digest,
        "licensing_evidence_valid": licensing_evidence_valid,
        "licensing_evidence_failures_digest": licensing_evidence_failures_digest,
        "licensing_evidence_digest": licensing_evidence_digest,
        "licensing_token_digest": tokens.get("licensing", {}).get("digest"),
        "governance_result": state.get("governance_result"),
        "governance_reason": state.get("governance_reason"),
        "governance_state_digest": governance_state_digest,
        "governance_live_state_digest": governance_live_state_digest,
        "governance_evidence_valid": governance_evidence_valid,
        "governance_evidence_failures_digest": governance_evidence_failures_digest,
        "governance_evidence_digest": governance_evidence_digest,
        "governance_token_digest": tokens.get("governance", {}).get("digest"),
        "governance_history_digest": generate_digest(history),
        "grc_result": state.get("grc_result"),
        "grc_reason": state.get("grc_reason"),
        "grc_state_digest": grc_state_digest,
        "grc_live_state_digest": grc_live_state_digest,
        "grc_evidence_valid": grc_evidence_valid,
        "grc_evidence_failures_digest": grc_evidence_failures_digest,
        "grc_evidence_digest": grc_evidence_digest,
        "grc_token_digest": tokens.get("grc", {}).get("digest"),
        "governed_reentry_digest": generate_digest(
            state.get("governed_reentry", {})
        ),
        "governed_constraint_digest": generate_digest(constraints),
    }


def domain_aurion_summary(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the exact live and signed Domain/Aurion parity surface."""
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    feedback = state.get("governance_feedback", {})
    feedback = feedback if isinstance(feedback, Mapping) else {}
    domain_feedback = feedback.get("domain_wrap", {})
    domain_feedback = (
        domain_feedback if isinstance(domain_feedback, Mapping) else {}
    )
    aurion_feedback = feedback.get("aurion", {})
    aurion_feedback = (
        aurion_feedback if isinstance(aurion_feedback, Mapping) else {}
    )
    histories = state.get("domain_aurion_history", {})
    histories = histories if isinstance(histories, Mapping) else {}

    def stage_values(stage: str) -> Dict[str, Any]:
        evidence = state.get(f"{stage}_evidence", {})
        evidence = evidence if isinstance(evidence, Mapping) else {}
        payload = evidence.get("payload", {})
        payload = payload if isinstance(payload, Mapping) else {}
        evidence_valid, evidence_failures = (
            validate_domain_aurion_stage_evidence(state, stage)
        )
        history_valid, history_failures = (
            validate_domain_aurion_stage_history(state, stage)
        )
        history = histories.get(stage, [])
        return {
            "state_digest": payload.get("stage_state_digest"),
            "live_state_digest": generate_digest(
                domain_aurion_stage_projection(state, stage)
            ),
            "evidence_valid": evidence_valid,
            "evidence_failures_digest": generate_digest(
                evidence_failures
            ),
            "evidence_digest": evidence.get("evidence_digest"),
            "history_digest": generate_digest(history),
            "history_valid": history_valid,
            "history_failures_digest": generate_digest(
                history_failures
            ),
        }

    domain_values = stage_values("domain")
    aurion_values = stage_values("aurion")
    domain_candidate = state.get("domain_candidate", {})
    domain_candidate = (
        domain_candidate if isinstance(domain_candidate, Mapping) else {}
    )
    selected_candidate = state.get("current_candidate", {})
    selected_candidate = (
        selected_candidate
        if isinstance(selected_candidate, Mapping)
        else {}
    )
    selected_pathway = selected_candidate.get("pathway", {})
    selected_pathway = (
        selected_pathway if isinstance(selected_pathway, Mapping) else {}
    )
    handoff = state.get("execution_convergence_handoff", {})
    handoff = handoff if isinstance(handoff, Mapping) else {}
    handoff_valid, handoff_failures = validate_handoff_evidence(state)
    return {
        "domain_result": state.get("domain_result"),
        "domain_reason": state.get("domain_reason"),
        "domain_state_digest": domain_values["state_digest"],
        "domain_live_state_digest": domain_values["live_state_digest"],
        "domain_evidence_valid": domain_values["evidence_valid"],
        "domain_evidence_failures_digest": domain_values[
            "evidence_failures_digest"
        ],
        "domain_evidence_digest": domain_values["evidence_digest"],
        "domain_token_digest": (
            tokens.get("domain", {}).get("digest")
            if isinstance(tokens.get("domain", {}), Mapping)
            else None
        ),
        "domain_history_digest": domain_values["history_digest"],
        "domain_history_valid": domain_values["history_valid"],
        "domain_history_failures_digest": domain_values[
            "history_failures_digest"
        ],
        "domain_attempt_count": domain_feedback.get("attempt_count"),
        "domain_max_attempts": domain_feedback.get("max_attempts"),
        "domain_attempts_digest": generate_digest(
            domain_feedback.get("attempts")
        ),
        "domain_results_digest": generate_digest(
            domain_feedback.get("domain_results")
        ),
        "domain_candidate_digest": generate_digest(dict(domain_candidate)),
        "aurion15_result": state.get("aurion15_result"),
        "aurion_reason": state.get("aurion_reason"),
        "aurion_state_digest": aurion_values["state_digest"],
        "aurion_live_state_digest": aurion_values["live_state_digest"],
        "aurion_evidence_valid": aurion_values["evidence_valid"],
        "aurion_evidence_failures_digest": aurion_values[
            "evidence_failures_digest"
        ],
        "aurion_evidence_digest": aurion_values["evidence_digest"],
        "aurion_token_digest": (
            tokens.get("aurion", {}).get("digest")
            if isinstance(tokens.get("aurion", {}), Mapping)
            else None
        ),
        "aurion_history_digest": aurion_values["history_digest"],
        "aurion_history_valid": aurion_values["history_valid"],
        "aurion_history_failures_digest": aurion_values[
            "history_failures_digest"
        ],
        "candidate_attempt_count": state.get("candidate_attempt_count"),
        "generated_candidate_set_digest": generate_digest(
            aurion_feedback.get("generated_candidates")
        ),
        "candidate_validations_digest": generate_digest(
            {
                "generated": aurion_feedback.get("candidate_validations"),
                "ranked": aurion_feedback.get(
                    "ranked_candidate_validations"
                ),
            }
        ),
        "admissible_candidate_set_digest": generate_digest(
            aurion_feedback.get("admissible_candidates")
        ),
        "ordered_candidate_set_digest": generate_digest(
            aurion_feedback.get("ranked_candidates")
        ),
        "rejected_candidates_digest": generate_digest(
            aurion_feedback.get("rejected_candidates")
        ),
        "selected_candidate_digest": generate_digest(
            dict(selected_candidate)
        ),
        "selected_pathway_digest": generate_digest(dict(selected_pathway)),
        "domain_aurion_constraint_digest": generate_digest(
            domain_aurion_constraint_snapshot(state)
        ),
        "execution_convergence_handoff_digest": handoff.get(
            "handoff_digest"
        ),
        "execution_convergence_handoff_valid": handoff_valid,
        "execution_convergence_handoff_failures_digest": generate_digest(
            handoff_failures
        ),
    }


def verify_convergence_proof(proof: Mapping[str, Any]) -> bool:
    payload = {
        "version": proof.get("version"),
        "mode": proof.get("mode"),
        "pipeline_a": proof.get("pipeline_a"),
        "pipeline_b": proof.get("pipeline_b"),
        "comparison_fields": proof.get("comparison_fields"),
        "root_pt_comparison_fields": proof.get(
            "root_pt_comparison_fields"
        ),
        "root_pt_matched": proof.get("root_pt_matched"),
        "governed_stage_comparison_fields": proof.get(
            "governed_stage_comparison_fields"
        ),
        "governed_stage_matched": proof.get("governed_stage_matched"),
        "domain_aurion_comparison_fields": proof.get(
            "domain_aurion_comparison_fields"
        ),
        "domain_aurion_matched": proof.get("domain_aurion_matched"),
        "matched": proof.get("matched"),
        "mismatches": proof.get("mismatches"),
        "near_match_reconciliation_used": proof.get(
            "near_match_reconciliation_used"
        ),
    }
    cryptographically_valid = (
        proof.get("convergence_hash") == generate_digest(payload)
        and verify_signature(payload, proof.get("signature", {}))
    )
    if not cryptographically_valid:
        return False
    if proof.get("comparison_fields") != CONVERGENCE_COMPARISON_FIELDS:
        return False
    if proof.get("root_pt_comparison_fields") != ROOT_PT_PARITY_FIELDS:
        return False
    if proof.get("governed_stage_comparison_fields") != (
        GOVERNED_STAGE_PARITY_FIELDS
    ):
        return False
    if proof.get("domain_aurion_comparison_fields") != (
        DOMAIN_AURION_PARITY_FIELDS
    ):
        return False
    if proof.get("near_match_reconciliation_used") is not False:
        return False
    pipeline_a = proof.get("pipeline_a")
    pipeline_b = proof.get("pipeline_b")
    if not isinstance(pipeline_a, Mapping):
        return False
    if pipeline_b is None:
        expected_mismatches: list[str] = []
        expected_root_pt_matched = None
        expected_governed_stage_matched = None
        expected_domain_aurion_matched = None
    elif isinstance(pipeline_b, Mapping):
        expected_mismatches = [
            field
            for field in CONVERGENCE_COMPARISON_FIELDS
            if pipeline_a.get(field) != pipeline_b.get(field)
        ]
        expected_root_pt_matched = all(
            pipeline_a.get(field) == pipeline_b.get(field)
            for field in ROOT_PT_PARITY_FIELDS
        )
        expected_governed_stage_matched = all(
            pipeline_a.get(field) == pipeline_b.get(field)
            for field in GOVERNED_STAGE_PARITY_FIELDS
        )
        expected_domain_aurion_matched = all(
            pipeline_a.get(field) == pipeline_b.get(field)
            for field in DOMAIN_AURION_PARITY_FIELDS
        )
    else:
        return False
    return (
        proof.get("mismatches") == expected_mismatches
        and proof.get("matched") is (not expected_mismatches)
        and proof.get("root_pt_matched") is expected_root_pt_matched
        and proof.get("governed_stage_matched")
        is expected_governed_stage_matched
        and proof.get("domain_aurion_matched")
        is expected_domain_aurion_matched
    )
