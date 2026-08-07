from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.pqc import generate_digest, verify_signature
from sbp_lex.shared.hash_chain import append_hash_entry, verify_hash_chain


def run_truth_continuity(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []
    feedback = working_state.get("governance_feedback", {})
    anchor = feedback.get("truth_anchor", {})
    if anchor.get("result") != "PASS":
        failures.append("truth_anchor_not_passed")
    payload = anchor.get("payload", {})
    if not isinstance(payload, Mapping):
        failures.append("truth_anchor_payload_missing")
        payload = {}
    if anchor.get("truth_anchor_hash") != generate_digest(dict(payload)):
        failures.append("truth_anchor_digest_mismatch")
    if not verify_signature(payload, anchor.get("signature", {})):
        failures.append("truth_anchor_signature_invalid")
    context = working_state.get("root_of_trust_context", {})
    if not isinstance(context, Mapping):
        failures.append("root_context_missing")
        context = {}
    context_payload = {
        key: deepcopy(value)
        for key, value in dict(context).items()
        if key != "context_digest"
    }
    if context.get("context_digest") != generate_digest(context_payload):
        failures.append("root_context_digest_mismatch")
    for field, expected in (
        ("request_fingerprint", working_state.get("request_fingerprint")),
        ("eie_digest", working_state.get("eie_hash")),
        (
            "canonical_request_identity",
            working_state.get("request_identity_digest"),
        ),
        ("state_hash_entering_root", context.get("state_hash_entering_root")),
        ("root_context_digest", context.get("context_digest")),
        (
            "collective_signal_digest",
            working_state.get("collective_signals", {}).get("digest"),
        ),
        (
            "collective_attachment_hash",
            working_state.get("collective_attachment", {}).get(
                "attachment_hash"
            ),
        ),
        (
            "root_trust_material_digest",
            working_state.get("collective_attachment", {}).get(
                "root_trust_material_digest"
            ),
        ),
        (
            "pt_evidence_envelope_digest",
            working_state.get("pt_evidence_envelope_digest"),
        ),
        (
            "token_chain_reference",
            context.get("token_chain_reference_entering_root"),
        ),
        (
            "audit_chain_reference",
            context.get("audit_chain_reference_entering_root"),
        ),
        ("authority_identity", context.get("authority_identity")),
        ("jurisdiction", context.get("jurisdiction")),
        (
            "attestation_identities",
            context.get("attestation_identities", []),
        ),
        ("logical_timestamp", context.get("logical_timestamp")),
        ("nonce", context.get("nonce")),
    ):
        if payload.get(field) != expected:
            failures.append(f"truth_continuity_binding_mismatch:{field}")
    material = working_state.get("collective_attachment", {}).get(
        "root_trust_material", {}
    )
    truth = material.get("truth", {}) if isinstance(material, Mapping) else {}
    precedence = working_state.get("collective_signals", {}).get(
        "precedence_signal", {}
    )
    lineage = precedence.get("temporal_rule_lineage", []) if isinstance(
        precedence, Mapping
    ) else []
    if truth.get("continuity_reference") != generate_digest(lineage):
        failures.append("truth_continuity_reference_mismatch")
    if not verify_hash_chain(working_state):
        failures.append("truth_hash_chain_invalid")
    continuity_valid = not failures
    evidence = {
        "result": "PASS" if continuity_valid else "FAIL",
        "continuity_valid": continuity_valid,
        "truth_anchor_hash": anchor.get("truth_anchor_hash"),
        "continuity_reference": truth.get("continuity_reference"),
        "failures": sorted(set(failures)),
    }
    working_state.setdefault("governance_feedback", {})[
        "truth_continuity"
    ] = evidence
    working_state.setdefault("audit_trace", []).append({
        "stage": "truth_continuity",
        **evidence,
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={"substage": "truth_continuity", **evidence},
    )
