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
    anchor_failures: list[str] = []
    if working_state.get("hard_entry_gate", {}).get("accepted") is not True:
        anchor_failures.append("hard_entry_not_accepted")
    if not isinstance(envelope, Mapping) or not envelope:
        anchor_failures.append("pt_evidence_envelope_missing")
        envelope = {}
    elif working_state.get("pt_evidence_envelope_digest") != generate_digest(dict(envelope)):
        anchor_failures.append("pt_evidence_envelope_digest_invalid")
    if envelope.get("request_fingerprint") != working_state.get("request_fingerprint"):
        anchor_failures.append("pt_envelope_request_fingerprint_mismatch")
    if working_state.get("hard_entry_gate", {}).get("request_fingerprint") != working_state.get("request_fingerprint"):
        anchor_failures.append("hard_entry_request_fingerprint_mismatch")
    anchor_payload = {
        "request_fingerprint": working_state.get("request_fingerprint"),
        "skg_digest": envelope.get("skg_digest") if isinstance(envelope, Mapping) else None,
        "dtn_digest": envelope.get("dtn_digest") if isinstance(envelope, Mapping) else None,
        "pre_context_digest": envelope.get("pre_context_digest") if isinstance(envelope, Mapping) else None,
        "pt_evidence_envelope_digest": working_state.get("pt_evidence_envelope_digest"),
    }
    for field, value in anchor_payload.items():
        if not isinstance(value, str) or not value:
            anchor_failures.append(f"root_anchor_missing:{field}")
    anchor_signature = sign_payload(anchor_payload)
    working_state["root_of_trust_evidence_anchor"] = {
        "valid": not anchor_failures and verify_signature(anchor_payload, anchor_signature),
        "anchor_digest": generate_digest(anchor_payload),
        "payload": anchor_payload,
        "signature": anchor_signature,
        "authority": "CANONICAL_RUNTIME_ROOT_OF_TRUST",
        "failures": sorted(set(anchor_failures)),
    }
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
