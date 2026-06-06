from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


def run_evidence_validation(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    context = working_state.get("context", {})
    evidence = context.get("evidence", [])

    failures: list[str] = []

    if not isinstance(evidence, list):
        failures.append("evidence_not_list")
        evidence = []

    valid_evidence = []

    for item in evidence:
        if not isinstance(item, dict):
            continue

        if not item.get("source"):
            continue

        if not item.get("content"):
            continue

        valid_evidence.append(item)

    if len(valid_evidence) == 0:
        failures.append("no_valid_evidence")

    result = "PASS" if len(failures) == 0 else "FAIL"

    working_state.setdefault("governance_feedback", {})["evidence_validation"] = {
        "result": result,
        "evidence_count": len(valid_evidence),
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
