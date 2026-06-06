from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.hash_chain import append_hash_entry

CANONICAL_SIGNAL_AUTHORITY = "CANONICAL_RUNTIME"


def _canonical_signal_timestamp(request_fingerprint: str) -> int:
    return int(str(request_fingerprint)[:12], 16)


def _canonical_signal_nonce(request_fingerprint: str, timestamp: int) -> str:
    return generate_digest(
        {
            "request_fingerprint": request_fingerprint,
            "timestamp": timestamp,
            "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
        }
    )[:32]


def run_truth_expiry(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    signals = working_state.get("collective_signals", {})
    timestamp = signals.get("timestamp")
    fingerprint = str(working_state.get("request_fingerprint", ""))
    failures: list[str] = []

    if not isinstance(timestamp, int):
        failures.append("missing_signal_timestamp")
    elif timestamp != _canonical_signal_timestamp(fingerprint):
        failures.append("truth_timestamp_not_canonical")
    if signals.get("timestamp_authority") != CANONICAL_SIGNAL_AUTHORITY:
        failures.append("truth_timestamp_authority_invalid")
    if isinstance(timestamp, int) and signals.get("nonce") != _canonical_signal_nonce(fingerprint, timestamp):
        failures.append("truth_nonce_not_canonical")

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
