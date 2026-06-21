from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry
from sbp_lex.governance.procedural_truth_envelope import (
    qualified_sources,
    source_is_qualified,
    validate_pt_evidence_envelope,
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

    valid_evidence = qualified_sources(evidence)
    envelope_valid, envelope_failures = validate_pt_evidence_envelope(working_state)
    failures.extend(envelope_failures)

    if len(valid_evidence) == 0:
        failures.append("no_valid_evidence")
    if not envelope_valid and not envelope_failures:
        failures.append("pt_evidence_envelope_invalid")

    result = "PASS" if len(failures) == 0 else "FAIL"

    working_state.setdefault("governance_feedback", {})["evidence_validation"] = {
        "result": result,
        "evidence_count": len(valid_evidence),
        "raw_evidence_count": len(evidence),
        "qualification_requirements": [
            "verified",
            "attested",
            "freshness_valid",
            "consistency_valid",
        ],
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "evidence_validation",
            "result": result,
            "evidence_count": len(valid_evidence),
        }
    )

    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "evidence_validation",
            "result": result,
            "evidence_count": len(valid_evidence),
        },
    )
