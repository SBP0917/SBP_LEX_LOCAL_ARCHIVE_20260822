from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.hash_chain import append_hash_entry


def run_attestation(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    collective_signals = working_state.get("collective_signals", {})
    digest = collective_signals.get("digest")
    signature = collective_signals.get("signature")

    failures: list[str] = []

    if not digest:
        failures.append("missing_collective_digest")

    if not signature:
        failures.append("missing_collective_signature")

    expected_binding = generate_digest(
        {
            "request_fingerprint": working_state.get("request_fingerprint"),
            "state_hash": working_state.get("state_hash"),
        }
    )

    attestation_payload = {
        "binding": expected_binding,
        "collective_digest": digest,
    }

    attestation_hash = generate_digest(attestation_payload)

    passed = len(failures) == 0

    working_state.setdefault("governance_feedback", {})["attestation"] = {
        "result": "PASS" if passed else "FAIL",
        "attestation_hash": attestation_hash,
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "attestation",
            "result": "PASS" if passed else "FAIL",
            "attestation_hash": attestation_hash,
        }
    )

    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "attestation",
            "result": "PASS" if passed else "FAIL",
            "attestation_hash": attestation_hash,
        },
  )
