from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


def evidence_is_corroboration_qualified(item: object) -> bool:
    return (
        isinstance(item, dict)
        and bool(item.get("source"))
        and bool(item.get("content"))
        and item.get("verified") is True
        and item.get("attested") is True
        and item.get("freshness_valid") is True
        and item.get("consistency_valid") is True
    )


def qualified_evidence(evidence: object) -> list[dict[str, object]]:
    if not isinstance(evidence, list):
        return []
    return [item for item in evidence if evidence_is_corroboration_qualified(item)]


def run_evidence_validation(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    context = working_state.get("context", {})
    evidence = context.get("evidence", [])

    failures: list[str] = []

    if not isinstance(evidence, list):
        failures.append("evidence_not_list")
        evidence = []

    valid_evidence = qualified_evidence(evidence)

    if len(valid_evidence) == 0:
        failures.append("no_valid_evidence")

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
