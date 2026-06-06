from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry, verify_hash_chain


def run_truth_continuity(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    continuity_valid = verify_hash_chain(working_state)

    working_state.setdefault("governance_feedback", {})["truth_continuity"] = {
        "result": "PASS" if continuity_valid else "FAIL",
        "continuity_valid": continuity_valid,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "truth_continuity",
            "continuity_valid": continuity_valid,
        }
    )

    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "truth_continuity",
            "continuity_valid": continuity_valid,
        },
    )
