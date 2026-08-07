from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.authority_first.anchor_validation_engine import run_anchor_validation
from sbp_lex.authority_first.attestation_engine import run_attestation
from sbp_lex.authority_first.attestation_consensus_engine import run_attestation_consensus
from sbp_lex.authority_first.truth_anchor_engine import run_truth_anchor
from sbp_lex.authority_first.truth_continuity_engine import run_truth_continuity
from sbp_lex.authority_first.truth_expiry_engine import run_truth_expiry
from sbp_lex.authority_first.truth_revocation_engine import run_truth_revocation
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.control_chain_validation import validate_eie_binding, validate_skg_dtn_binding
from sbp_lex.shared.state_builder import validate_boundary_protection

ROOT_OF_TRUST_ORDER = [
    run_anchor_validation,
    run_attestation,
    run_attestation_consensus,
    run_truth_anchor,
    run_truth_continuity,
    run_truth_expiry,
    run_truth_revocation,
]


FAIL_KEYS = {
    "anchor_validation": "anchor_validation",
    "attestation": "attestation",
    "attestation_consensus": "attestation_consensus",
    "truth_anchor": "truth_anchor",
    "truth_continuity": "truth_continuity",
    "truth_expiry": "truth_expiry",
    "truth_revocation": "truth_revocation",
}


def run_root_of_trust(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    envelope = working_state.get("pt_evidence_envelope")
    eie = working_state.get("eie", {})
    anchor_failures: list[str] = []
    if working_state.get("hard_entry_gate", {}).get("accepted") is not True:
        anchor_failures.append("hard_entry_not_accepted")
    boundary_valid, boundary_failures = validate_boundary_protection(
        working_state
    )
    if not boundary_valid:
        anchor_failures.extend(boundary_failures)
    if not isinstance(envelope, Mapping) or not envelope:
        anchor_failures.append("pt_evidence_envelope_missing")
        envelope = {}
    elif working_state.get("pt_evidence_envelope_digest") != generate_digest(dict(envelope)):
        anchor_failures.append("pt_evidence_envelope_digest_invalid")
    if envelope.get("request_fingerprint") != working_state.get("request_fingerprint"):
        anchor_failures.append("pt_envelope_request_fingerprint_mismatch")
    eie_valid, eie_failures = validate_eie_binding(working_state)
    if not eie_valid:
        anchor_failures.extend(eie_failures)
    skg_dtn_valid, skg_dtn_failures = validate_skg_dtn_binding(working_state)
    if not skg_dtn_valid:
        anchor_failures.extend(skg_dtn_failures)
    if working_state.get("hard_entry_gate", {}).get("request_fingerprint") != working_state.get("request_fingerprint"):
        anchor_failures.append("hard_entry_request_fingerprint_mismatch")
    if not isinstance(eie, Mapping) or eie.get("canonical_traversal_state") is not True:
        anchor_failures.append("eie_canonical_traversal_state_missing")
        eie = {}
    if working_state.get("eie_hash") != eie.get("eie_hash"):
        anchor_failures.append("eie_hash_mismatch")
    if isinstance(envelope, Mapping) and envelope.get("eie_hash") != working_state.get("eie_hash"):
        anchor_failures.append("pt_envelope_eie_hash_mismatch")
    skg_metadata = envelope.get("skg_truth_foundation_metadata", {}) if isinstance(envelope, Mapping) else {}
    dtn_metadata = envelope.get("dtn_contextual_verification_metadata", {}) if isinstance(envelope, Mapping) else {}
    anchor_payload = {
        "eie_identity": {
            "object_type": eie.get("object_type"),
            "eie_version": eie.get("eie_version"),
            "request_fingerprint": working_state.get("request_fingerprint"),
        },
        "eie_hash": working_state.get("eie_hash"),
        "source_payload_hash": working_state.get("source_payload_hash"),
        "adapter_identity": eie.get("adapter_identity"),
        "source_system_identity": eie.get("source_system_identity"),
        "request_fingerprint": working_state.get("request_fingerprint"),
        "skg_digest": envelope.get("skg_digest") if isinstance(envelope, Mapping) else None,
        "skg_verification_status": skg_metadata.get("skg_verification_status") if isinstance(skg_metadata, Mapping) else None,
        "skg_enrichment_hash": skg_metadata.get("skg_enrichment_hash") if isinstance(skg_metadata, Mapping) else None,
        "dtn_digest": envelope.get("dtn_digest") if isinstance(envelope, Mapping) else None,
        "dtn_contextualisation_status": dtn_metadata.get("dtn_contextualisation_status") if isinstance(dtn_metadata, Mapping) else None,
        "dtn_enrichment_hash": dtn_metadata.get("dtn_enrichment_hash") if isinstance(dtn_metadata, Mapping) else None,
        "pre_context_digest": envelope.get("pre_context_digest") if isinstance(envelope, Mapping) else None,
        "evidence_package_hash": envelope.get("pre_context_digest") if isinstance(envelope, Mapping) else None,
        "authority_reference_hash": generate_digest(skg_metadata) if isinstance(skg_metadata, Mapping) else None,
        "pt_evidence_envelope_digest": working_state.get("pt_evidence_envelope_digest"),
        "state_hash": working_state.get("state_hash"),
        "traversal_id": working_state.get("traversal_id"),
        "timestamp_freshness_reference": envelope.get("freshness_status") if isinstance(envelope, Mapping) else None,
        "token_chain_reference": generate_digest(working_state.get("token_trace", [])),
        "audit_chain_reference": generate_digest(working_state.get("audit_trace", [])),
    }
    for field, value in anchor_payload.items():
        if not isinstance(value, str) or not value:
            if not isinstance(value, Mapping):
                anchor_failures.append(f"root_anchor_missing:{field}")
    anchor_signature = sign_payload(anchor_payload)
    working_state["root_of_trust_evidence_anchor"] = {
        "valid": not anchor_failures and verify_signature(anchor_payload, anchor_signature),
        "anchor_digest": generate_digest(anchor_payload),
        "payload": anchor_payload,
        "signature": anchor_signature,
            "authority": "CANONICAL_RUNTIME_ROOT_OF_TRUST",
            "anchorage_status": "VALID" if not anchor_failures else "INVALID",
            "failures": sorted(set(anchor_failures)),
        }
    working_state["root_anchor_bound_state_hash"] = anchor_payload.get("state_hash")
    if anchor_failures:
        working_state["authority_first_result"] = "FAIL"
        working_state["authority_first_reason"] = "root_of_trust_evidence_anchor_invalid"
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state.setdefault("governance_feedback", {})["root_of_trust_evidence_anchor"] = {
            "result": "FAIL",
            "failures": sorted(set(anchor_failures)),
        }
        working_state.setdefault("audit_trace", []).append(
            {
                "stage": "root_of_trust_runner",
                "event": "ROOT_OF_TRUST_EVIDENCE_ANCHOR_FAILURE",
                "failures": sorted(set(anchor_failures)),
            }
        )
        return working_state

    for engine in ROOT_OF_TRUST_ORDER:
        working_state = engine(working_state)

        engine_name = engine.__name__.replace("run_", "")
        governance_feedback = working_state.get("governance_feedback", {})
        engine_feedback = governance_feedback.get(engine_name, {})

        if engine_feedback.get("result") == "FAIL":
            working_state["authority_first_result"] = "FAIL"
            working_state["decision"] = "DENY"
            working_state["execution_result"] = "HALT"
            working_state.setdefault("audit_trace", []).append(
                {
                    "stage": "root_of_trust_runner",
                    "event": "ROOT_OF_TRUST_FAILURE",
                    "failed_engine": engine_name,
                }
            )
            return working_state

    working_state["authority_first_result"] = "PASS"
    working_state["authority_first_reason"] = "root_of_trust_chain_complete"

    working_state = issue_token(
        working_state,
        name="authority",
        issued_at_stage="root_of_trust",
        payload={
            "authority_result": "PASS",
            "root_chain_complete": True,
            "evidence_anchor_digest": working_state["root_of_trust_evidence_anchor"]["anchor_digest"],
        },
    )

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "root_of_trust_runner",
            "event": "ROOT_OF_TRUST_COMPLETE",
            "evidence_anchor_digest": working_state["root_of_trust_evidence_anchor"]["anchor_digest"],
        }
    )

    return working_state
