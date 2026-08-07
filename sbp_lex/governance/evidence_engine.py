from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry
from sbp_lex.governance.procedural_truth_envelope import (
    assess_source_records,
    source_is_qualified,
    validate_pt_evidence_envelope,
)
from sbp_lex.shared.control_chain_validation import (
    validate_root_of_trust_evidence,
)


def evidence_is_corroboration_qualified(item: object) -> bool:
    return source_is_qualified(item)


def qualified_evidence(evidence: object) -> list[dict[str, object]]:
    if not isinstance(evidence, list):
        return []
    return [item for item in evidence if evidence_is_corroboration_qualified(item)]


def run_evidence_validation(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    envelope = working_state.get("pt_evidence_envelope", {})
    evidence = envelope.get("source_records", []) if isinstance(envelope, Mapping) else []

    failures: list[str] = []

    if not isinstance(evidence, list):
        failures.append("evidence_not_list")
        evidence = []

    assessment = (
        envelope.get("source_assessment", {})
        if isinstance(envelope, Mapping)
        else {}
    )
    assessment = assessment if isinstance(assessment, Mapping) else {}
    valid_evidence_count = int(
        assessment.get("source_count_qualifying", 0)
    )
    envelope_valid, envelope_failures = validate_pt_evidence_envelope(working_state)
    failures.extend(envelope_failures)
    root_valid, root_failures = validate_root_of_trust_evidence(
        working_state, require_pass=True
    )
    if not root_valid:
        failures.extend(f"root_preflight:{reason}" for reason in root_failures)

    if valid_evidence_count == 0:
        failures.append("no_valid_evidence")
    if not envelope_valid and not envelope_failures:
        failures.append("pt_evidence_envelope_invalid")
    if assessment.get("evidence_completeness_result") != "PASS":
        failures.append("evidence_completeness_not_met")
    if assessment.get("evidentiary_sufficiency_result") != "SUFFICIENT":
        failures.append("evidentiary_sufficiency_not_met")

    failures = sorted(set(failures))

    result = "PASS" if len(failures) == 0 else "FAIL"

    working_state.setdefault("governance_feedback", {})["evidence_validation"] = {
        "result": result,
        "evidence_count": valid_evidence_count,
        "qualifying_source_count": valid_evidence_count,
        "raw_evidence_count": len(evidence),
        "source_count_rejected": assessment.get("source_count_rejected", 0),
        "source_count_duplicates": assessment.get("source_count_duplicates", 0),
        "source_identity_summary": deepcopy(
            assessment.get("source_identity_summary", [])
        ),
        "verification_result": assessment.get("verification_result"),
        "attestation_result": assessment.get("attestation_result"),
        "freshness_result": assessment.get("freshness_result"),
        "provenance_result": assessment.get("provenance_result"),
        "consistency_result": assessment.get("consistency_result"),
        "relevance_result": assessment.get("relevance_result"),
        "evidence_completeness_result": assessment.get(
            "evidence_completeness_result"
        ),
        "evidentiary_sufficiency_result": assessment.get(
            "evidentiary_sufficiency_result"
        ),
        "source_assessment_digest": assessment.get(
            "source_assessment_digest"
        ),
        "qualification_requirements": [
            "verified",
            "attested",
            "freshness_valid",
            "consistency_valid",
            "provenance_valid",
            "integrity_valid",
            "relevance_valid",
            "request_bound",
            "eie_bound",
            "collective_signal_bound",
            "independent_source_identity",
        ],
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "evidence_validation",
            "result": result,
            "evidence_count": valid_evidence_count,
            "source_assessment_digest": assessment.get(
                "source_assessment_digest"
            ),
        }
    )

    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "evidence_validation",
            "result": result,
            "evidence_count": valid_evidence_count,
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
