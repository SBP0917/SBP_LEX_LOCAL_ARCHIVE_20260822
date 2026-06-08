from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


REVOKED_AUTHORITIES = set()
REVOKED_FINGERPRINTS = set()


def run_truth_revocation(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    authority = str(working_state.get("resolved_authority", "")).strip()
    fingerprint = str(working_state.get("request_fingerprint", "")).strip()

    failures: list[str] = []

    if authority in REVOKED_AUTHORITIES:
        failures.append("authority_revoked")

    if fingerprint in REVOKED_FINGERPRINTS:
        failures.append("request_fingerprint_revoked")

    passed = len(failures) == 0

    working_state.setdefault("governance_feedback", {})["truth_revocation"] = {
        "result": "PASS" if passed else "FAIL",
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "truth_revocation",
            "result": "PASS" if passed else "FAIL",
            "failures": failures,
        }
    )

    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "truth_revocation",
            "result": "PASS" if passed else "FAIL",
            "failures": failures,
        },
    )
