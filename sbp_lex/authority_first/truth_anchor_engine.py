from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.hash_chain import append_hash_entry


def run_truth_anchor(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    payload = {
        "request_fingerprint": working_state.get("request_fingerprint"),
        "collective_digest": working_state.get("collective_signals", {}).get("digest"),
        "state_hash": working_state.get("state_hash"),
    }

    truth_anchor_hash = generate_digest(payload)

    working_state.setdefault("governance_feedback", {})["truth_anchor"] = {
        "result": "PASS",
        "truth_anchor_hash": truth_anchor_hash,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "truth_anchor",
            "truth_anchor_hash": truth_anchor_hash,
        }
    )

    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "truth_anchor",
            "truth_anchor_hash": truth_anchor_hash,
        },
    )
