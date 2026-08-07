from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import CONVERGENCE_VERSION
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


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

CONVERGENCE_COMPARISON_FIELDS = [
    "decision",
    "execution_result",
    "governance_result",
    "domain_result",
    "aurion15_result",
    *ROOT_PT_PARITY_FIELDS,
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
        "root_pt_matched": (
            all(
                a_summary.get(field) == b_summary.get(field)
                for field in ROOT_PT_PARITY_FIELDS
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
        "matched": proof.get("matched"),
        "mismatches": proof.get("mismatches"),
        "near_match_reconciliation_used": proof.get(
            "near_match_reconciliation_used"
        ),
    }
    return proof.get("convergence_hash") == generate_digest(payload) and verify_signature(payload, proof.get("signature", {}))
