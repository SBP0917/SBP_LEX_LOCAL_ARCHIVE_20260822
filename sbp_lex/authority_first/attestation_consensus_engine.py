from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.hash_chain import append_hash_entry


CONSENSUS_MODE = "EXACT_ALL_APPLICABLE_ATTESTATIONS_V1"


def run_attestation_consensus(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []
    feedback = working_state.get("governance_feedback", {})
    if feedback.get("attestation", {}).get("result") != "PASS":
        failures.append("attestation_not_passed")
    material = working_state.get("collective_attachment", {}).get(
        "root_trust_material", {}
    )
    attestations = material.get("attestations", []) if isinstance(
        material, Mapping
    ) else []
    statements = [
        item.get("consensus_statement_digest")
        for item in attestations
        if isinstance(item, Mapping)
    ]
    expected_statement = working_state.get("collective_signals", {}).get(
        "digest"
    )
    statements_are_digests = all(
        isinstance(statement, str) and bool(statement)
        for statement in statements
    )
    exact_agreement = (
        bool(statements)
        and len(statements) == len(attestations)
        and statements_are_digests
        and len(set(statements)) == 1
        and statements[0] == expected_statement
    )
    if not exact_agreement:
        failures.append("attestation_consensus_inconsistent")
    consensus_payload = {
        "mode": CONSENSUS_MODE,
        "exact_agreement": exact_agreement,
        "statement_digests": statements,
        "attestation_count": len(attestations),
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "state_hash_entering_root": working_state.get(
            "root_of_trust_context", {}
        ).get("state_hash_entering_root"),
    }
    consensus_hash = generate_digest(consensus_payload)
    result = "PASS" if not failures else "FAIL"
    evidence = {
        "result": result,
        "consensus_mode": CONSENSUS_MODE,
        "exact_agreement": exact_agreement,
        "attestation_count": len(attestations),
        "consensus_hash": consensus_hash,
        "failures": sorted(set(failures)),
    }
    working_state.setdefault("governance_feedback", {})[
        "attestation_consensus"
    ] = evidence
    working_state.setdefault("audit_trace", []).append({
        "stage": "attestation_consensus",
        **evidence,
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={"substage": "attestation_consensus", **evidence},
    )
