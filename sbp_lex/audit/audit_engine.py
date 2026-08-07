from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.audit_finalisation import build_audit_record, finalise_audit
from sbp_lex.security.authority_boundary import validate_root_pt_eligibility
from sbp_lex.shared.hash_chain import append_hash_entry


def run_audit(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    root_evidence = working_state.get("root_of_trust_evidence", {})
    root_payload = (
        root_evidence.get("payload", {})
        if isinstance(root_evidence, Mapping)
        else {}
    )
    root_payload = root_payload if isinstance(root_payload, Mapping) else {}
    pt_evidence = working_state.get("procedural_truth_evidence", {})
    pt_payload = (
        pt_evidence.get("payload", {})
        if isinstance(pt_evidence, Mapping)
        else {}
    )
    pt_payload = pt_payload if isinstance(pt_payload, Mapping) else {}
    envelope = working_state.get("pt_evidence_envelope", {})
    envelope = envelope if isinstance(envelope, Mapping) else {}
    certification = working_state.get(
        "procedural_truth_certification", {}
    )
    certification = (
        certification if isinstance(certification, Mapping) else {}
    )
    threshold_snapshot = working_state.get("governance_feedback", {}).get(
        "threshold_snapshot", {}
    )
    threshold_snapshot = (
        threshold_snapshot
        if isinstance(threshold_snapshot, Mapping)
        else {}
    )
    root_pt_eligible, root_pt_eligibility_failures = (
        validate_root_pt_eligibility(working_state)
    )

    def record_digest(record: object, *names: str) -> object:
        if not isinstance(record, Mapping):
            return None
        for name in names:
            if record.get(name) not in (None, ""):
                return record.get(name)
        return None

    root_lineage = {
        "stage": "root_of_trust",
        "root_result": working_state.get("authority_first_result"),
        "root_reason": working_state.get("authority_first_reason"),
        "root_evidence_digest": record_digest(
            root_evidence, "root_evidence_digest", "evidence_digest"
        )
        or working_state.get("root_of_trust_evidence_anchor", {}).get(
            "anchor_digest"
        ),
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "state_hash_entering_root": root_payload.get(
            "state_hash_entering_root",
            working_state.get("root_of_trust_evidence_anchor", {})
            .get("payload", {})
            .get("state_hash"),
        ),
        "collective_signal_digest": root_payload.get(
            "collective_signal_digest",
            working_state.get("collective_signals", {}).get("digest"),
        ),
        "stage_results": root_payload.get(
            "stage_results",
            root_evidence.get(
                "stage_results",
                working_state.get("governance_feedback", {}).get(
                    "root_of_trust_stage_results", {}
                ),
            )
            if isinstance(root_evidence, Mapping)
            else {},
        ),
    }
    pt_lineage = {
        "stage": "procedural_truth",
        "procedural_truth_result": working_state.get(
            "procedural_truth_result"
        ),
        "procedural_truth_outcome": working_state.get(
            "procedural_truth_outcome"
        ),
        "pt_evidence_digest": record_digest(
            pt_evidence,
            "pt_evidence_digest",
            "procedural_truth_evidence_digest",
            "evidence_digest",
        ),
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "state_hash": pt_payload.get(
            "state_hash",
            certification.get("state_hash"),
        ),
        "source_count_total": pt_payload.get(
            "source_count_total", len(envelope.get("source_records", []))
        ),
        "source_count_qualifying": pt_payload.get(
            "source_count_qualifying",
            pt_payload.get(
                "qualifying_source_count",
                envelope.get("qualifying_source_count"),
            ),
        ),
        "corroboration_required": pt_payload.get(
            "corroboration_required",
            working_state.get("corroboration_required"),
        ),
        "corroboration_observed": pt_payload.get(
            "corroboration_observed",
            threshold_snapshot.get(
                "qualified_evidence_count",
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
                working_state.get("safety_profile", {}).get(
                    "computed_tier"
                ),
            ),
        ),
        "root_pt_eligible": root_pt_eligible,
        "root_pt_eligibility_failures": root_pt_eligibility_failures,
    }
    audit_state = {
        "request_fingerprint": working_state.get("request_fingerprint"),
        "state_hash": working_state.get("state_hash"),
        "decision": working_state.get("decision"),
        "execution_verified": working_state.get("execution_verified", False),
        "convergence_hash": working_state.get("convergence_hash"),
        "audit_chain": working_state.get("hash_chain", []),
        "pipeline_mode": working_state.get("pipeline_mode"),
        "integration_evidence": {
            "stage_order": working_state.get("integration_stage_order", []),
            "hard_entry_gate": working_state.get("hard_entry_gate", {}),
            "collective_signal_evidence": working_state.get("collective_signal_evidence", {}),
            "ap_acf_precheck_result": working_state.get("ap_acf_precheck_result"),
            "authority_first_result": working_state.get("authority_first_result"),
            "root_of_trust_lineage": root_lineage,
            "root_of_trust_evidence": root_evidence,
            "procedural_truth_result": working_state.get("procedural_truth_result"),
            "procedural_truth_lineage": pt_lineage,
            "procedural_truth_evidence": pt_evidence,
            "procedural_truth_binding": {
                "eie_hash": working_state.get("eie_hash"),
                "traversal_id": working_state.get("traversal_id"),
                "source_payload_hash": working_state.get("source_payload_hash"),
                "request_fingerprint": working_state.get("request_fingerprint"),
                "state_hash": working_state.get("state_hash"),
                "pt_envelope_digest": working_state.get("pt_evidence_envelope_digest"),
                "threshold_tier": envelope.get("threshold_tier"),
                "threshold_requirement": envelope.get("threshold_requirement"),
                "qualifying_source_count": envelope.get("qualifying_source_count"),
                "pt_outcome": working_state.get("procedural_truth_outcome"),
                "procedural_truth_certification": working_state.get("procedural_truth_certification", {}),
                "skg_truth_foundation_metadata": working_state.get("pt_evidence_envelope", {}).get("skg_truth_foundation_metadata", {}),
                "dtn_contextual_verification_metadata": working_state.get("pt_evidence_envelope", {}).get("dtn_contextual_verification_metadata", {}),
                "pt_failure_reasons": working_state.get("procedural_truth_failure_reasons", []),
                "source_provenance_summary": working_state.get("pt_evidence_envelope", {}).get("source_summary", {}),
                "root_of_trust_evidence_anchor": working_state.get("root_of_trust_evidence_anchor", {}),
            },
            "threshold_snapshot": working_state.get("governance_feedback", {}).get("threshold_snapshot", {}),
            "classification_result": working_state.get("classification_result"),
            "licensing_result": working_state.get("licensing_result"),
            "governance_result": working_state.get("governance_result"),
            "grc_result": working_state.get("grc_result"),
            "domain_wrap": working_state.get("governance_feedback", {}).get("domain_wrap", {}),
            "aurion15_result": working_state.get("aurion15_result"),
            "token_verification_failures": working_state.get("token_verification_failures", []),
            "token_chain_reference": working_state.get("root_of_trust_evidence_anchor", {}).get("payload", {}).get("token_chain_reference"),
            "audit_chain_reference": working_state.get("root_of_trust_evidence_anchor", {}).get("payload", {}).get("audit_chain_reference"),
            "execution_reason": working_state.get("execution_reason", ""),
            "operational_state": working_state.get("operational_state"),
            "governed_reentry": working_state.get("governed_reentry", {}),
        },
    }
    audit_record = build_audit_record(audit_state)
    audit_finalisation = finalise_audit(audit_record) if audit_record.get("valid") else {"audit_complete": False, "reason": audit_record.get("reason")}
    working_state["audit_record"] = audit_record
    working_state["audit_hash"] = audit_record.get("audit_hash", "")
    working_state["audit_finalisation"] = audit_finalisation
    working_state.setdefault("audit_trace", []).append({"stage": "audit", "audit_hash": working_state["audit_hash"], "audit_complete": audit_finalisation.get("audit_complete", False)})
    return append_hash_entry(working_state, stage="audit", payload={"audit_hash": working_state["audit_hash"], "audit_complete": audit_finalisation.get("audit_complete", False)})
