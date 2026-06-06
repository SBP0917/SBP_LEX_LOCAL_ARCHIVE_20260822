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
        },
    )

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "root_of_trust_runner",
            "event": "ROOT_OF_TRUST_COMPLETE",
        }
    )

    return working_state
