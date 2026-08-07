from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


CANONICAL_SIGNAL_AUTHORITY = "CANONICAL_RUNTIME"


def _interval_valid(value: Mapping[str, Any], logical_time: Any) -> bool:
    issued_at = value.get("issued_at")
    valid_until = value.get("valid_until")
    return (
        isinstance(logical_time, int)
        and not isinstance(logical_time, bool)
        and isinstance(issued_at, int)
        and not isinstance(issued_at, bool)
        and isinstance(valid_until, int)
        and not isinstance(valid_until, bool)
        and issued_at <= logical_time <= valid_until
    )


def run_truth_expiry(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []
    if working_state.get("governance_feedback", {}).get(
        "truth_continuity", {}
    ).get("result") != "PASS":
        failures.append("truth_continuity_not_passed")
    signals = working_state.get("collective_signals", {})
    logical_time = working_state.get("root_of_trust_context", {}).get(
        "logical_timestamp"
    )
    if signals.get("timestamp_authority") != CANONICAL_SIGNAL_AUTHORITY:
        failures.append("truth_timestamp_authority_invalid")
    if signals.get("timestamp") != logical_time:
        failures.append("truth_timestamp_not_canonical")
    signal_timestamp = signals.get("timestamp")
    freshness_window = signals.get("freshness_window_seconds")
    collective_valid_until = (
        signal_timestamp + freshness_window
        if isinstance(signal_timestamp, int)
        and not isinstance(signal_timestamp, bool)
        and isinstance(freshness_window, int)
        and not isinstance(freshness_window, bool)
        and freshness_window >= 0
        else None
    )
    if not (
        isinstance(logical_time, int)
        and not isinstance(logical_time, bool)
        and isinstance(signal_timestamp, int)
        and not isinstance(signal_timestamp, bool)
        and isinstance(collective_valid_until, int)
        and signal_timestamp <= logical_time <= collective_valid_until
    ):
        failures.append("collective_signal_expired")
    material = working_state.get("collective_attachment", {}).get(
        "root_trust_material", {}
    )
    authority = material.get("authority", {}) if isinstance(
        material, Mapping
    ) else {}
    if not isinstance(authority, Mapping) or not _interval_valid(
        authority, logical_time
    ):
        failures.append("authority_expired")
    elif authority.get("authority_status") == "EXPIRED":
        failures.append("authority_expired")
    attestations = material.get("attestations", []) if isinstance(
        material, Mapping
    ) else []
    for index, attestation in enumerate(attestations):
        if not isinstance(attestation, Mapping) or not _interval_valid(
            attestation, logical_time
        ):
            failures.append(f"attestation_expired:{index}")
        elif attestation.get("status") == "EXPIRED":
            failures.append(f"attestation_expired:{index}")
    truth = material.get("truth", {}) if isinstance(material, Mapping) else {}
    if not isinstance(truth, Mapping) or not _interval_valid(truth, logical_time):
        failures.append("truth_expired")
    elif truth.get("status") == "EXPIRED":
        failures.append("truth_expired")
    result = "PASS" if not failures else "FAIL"
    evidence = {
        "result": result,
        "logical_timestamp": logical_time,
        "collective_valid_until": collective_valid_until,
        "authority_valid_until": authority.get("valid_until")
        if isinstance(authority, Mapping)
        else None,
        "attestation_valid_until": [
            item.get("valid_until") for item in attestations
            if isinstance(item, Mapping)
        ],
        "truth_valid_until": truth.get("valid_until")
        if isinstance(truth, Mapping)
        else None,
        "failures": sorted(set(failures)),
    }
    working_state.setdefault("governance_feedback", {})["truth_expiry"] = evidence
    working_state.setdefault("audit_trace", []).append({
        "stage": "truth_expiry",
        **evidence,
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={"substage": "truth_expiry", **evidence},
    )
