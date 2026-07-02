from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.audit_finalisation import build_audit_record, finalise_audit
from sbp_lex.shared.hash_chain import append_hash_entry


def run_audit(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
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
            "procedural_truth_result": working_state.get("procedural_truth_result"),
            "procedural_truth_binding": {
                "eie_hash": working_state.get("eie_hash"),
                "traversal_id": working_state.get("traversal_id"),
                "source_payload_hash": working_state.get("source_payload_hash"),
                "request_fingerprint": working_state.get("request_fingerprint"),
                "state_hash": working_state.get("state_hash"),
                "pt_envelope_digest": working_state.get("pt_evidence_envelope_digest"),
                "threshold_tier": working_state.get("pt_evidence_envelope", {}).get("threshold_tier"),
                "threshold_requirement": working_state.get("pt_evidence_envelope", {}).get("threshold_requirement"),
                "qualifying_source_count": working_state.get("pt_evidence_envelope", {}).get("qualifying_source_count"),
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
