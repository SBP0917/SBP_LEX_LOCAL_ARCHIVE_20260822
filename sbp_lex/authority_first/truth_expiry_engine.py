from __future__ import annotations

import time
from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


MAX_SIGNAL_AGE_SECONDS = 300


def run_truth_expiry(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    signals = working_state.get("collective_signals", {})
    timestamp = signals.get("timestamp")

    failures: list[str] = []

    if not isinstance(timestamp, int):
        failures.append("missing_signal_timestamp")
    else:
        age = int(time.time()) - timestamp
        if age > MAX_SIGNAL_AGE_SECONDS:
            failures.append("truth_expired")

    passed = len(failures) == 0

    working_state.setdefault("governance_feedback", {})["truth_expiry"] = {
        "result": "PASS" if passed else "FAIL",
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "truth_expiry",
            "result": "PASS" if passed else "FAIL",
            "failures": failures,
        }
    )

    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "truth_expiry",
            "result": "PASS" if passed else "FAIL",
            "failures": failures,
        },
  )
