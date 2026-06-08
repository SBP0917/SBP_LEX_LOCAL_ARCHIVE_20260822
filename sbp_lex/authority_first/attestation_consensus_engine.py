from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.hash_chain import append_hash_entry


MIN_CONSENSUS_SCORE = 0.75


def run_attestation_consensus(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    governance_feedback = working_state.get("governance_feedback", {})
    attestation = governance_feedback.get("attestation", {})

    failures: list[str] = []

    if attestation.get("result") != "PASS":
        failures.append("attestation_not_passed")

    consensus_score = 1.0 if not failures else 0.0

    consensus_payload = {
        "consensus_score": consensus_score,
        "request_fingerprint": working_state.get("request_fingerprint"),
    }

    consensus_hash = generate_digest(consensus_payload)

    passed = consensus_score >= MIN_CONSENSUS_SCORE

    governance_feedback["attestation_consensus"] = {
        "result": "PASS" if passed else "FAIL",
        "consensus_score": consensus_score,
        "consensus_hash": consensus_hash,
        "failures": failures,
    }

    working_state["governance_feedback"] = governance_feedback

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "attestation_consensus",
            "consensus_score": consensus_score,
            "result": "PASS" if passed else "FAIL",
        }
    )

    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "attestation_consensus",
            "consensus_hash": consensus_hash,
            "result": "PASS" if passed else "FAIL",
        },
  )
