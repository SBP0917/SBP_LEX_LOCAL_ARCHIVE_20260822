from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.hash_chain import append_hash_entry


def run_truth_anchor(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []
    feedback = working_state.get("governance_feedback", {})
    if feedback.get("attestation_consensus", {}).get("result") != "PASS":
        failures.append("attestation_consensus_not_passed")
    context = working_state.get("root_of_trust_context", {})
    material = working_state.get("collective_attachment", {}).get(
        "root_trust_material", {}
    )
    truth_material = material.get("truth", {}) if isinstance(
        material, Mapping
    ) else {}
    if not isinstance(truth_material, Mapping):
        failures.append("truth_material_missing")
        truth_material = {}
    if truth_material.get("status") not in {"VALID", "REVOKED", "EXPIRED"}:
        failures.append("truth_anchor_status_malformed")
    payload = {
        "schema_version": "desktop-v1.truth-anchor.v1",
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "canonical_request_identity": working_state.get(
            "request_identity_digest"
        ),
        "state_hash_entering_root": context.get("state_hash_entering_root"),
        "root_context_digest": context.get("context_digest"),
        "collective_signal_digest": working_state.get(
            "collective_signals", {}
        ).get("digest"),
        "collective_attachment_hash": working_state.get(
            "collective_attachment", {}
        ).get("attachment_hash"),
        "root_trust_material_digest": material.get("material_digest")
        if isinstance(material, Mapping)
        else None,
        "pt_evidence_envelope_digest": working_state.get(
            "pt_evidence_envelope_digest"
        ),
        "token_chain_reference": context.get(
            "token_chain_reference_entering_root"
        ),
        "audit_chain_reference": context.get(
            "audit_chain_reference_entering_root"
        ),
        "authority_identity": context.get("authority_identity"),
        "jurisdiction": context.get("jurisdiction"),
        "attestation_identities": context.get(
            "attestation_identities", []
        ),
        "logical_timestamp": context.get("logical_timestamp"),
        "nonce": context.get("nonce"),
        "authority_evidence_digest": material.get("authority", {}).get(
            "authority_evidence_digest"
        ) if isinstance(material, Mapping) else None,
        "attestation_hash": feedback.get("attestation", {}).get(
            "attestation_hash"
        ),
        "consensus_hash": feedback.get("attestation_consensus", {}).get(
            "consensus_hash"
        ),
        "truth_material_digest": truth_material.get("truth_material_digest"),
        "truth_identity": truth_material.get("truth_identity"),
        "validation_basis": material.get("validation_basis", {})
        if isinstance(material, Mapping)
        else {},
    }
    truth_anchor_hash = generate_digest(payload)
    signature = sign_payload(payload)
    if not verify_signature(payload, signature):
        failures.append("truth_anchor_signature_invalid")
    result = "PASS" if not failures else "FAIL"
    evidence = {
        "result": result,
        "truth_anchor_hash": truth_anchor_hash,
        "payload": payload,
        "signature": signature,
        "verified": verify_signature(payload, signature),
        "failures": sorted(set(failures)),
    }
    working_state.setdefault("governance_feedback", {})["truth_anchor"] = evidence
    working_state.setdefault("audit_trace", []).append({
        "stage": "truth_anchor",
        "result": result,
        "truth_anchor_hash": truth_anchor_hash,
        "failures": evidence["failures"],
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "truth_anchor",
            "result": result,
            "truth_anchor_hash": truth_anchor_hash,
            "failures": evidence["failures"],
        },
    )
