from __future__ import annotations

import json
from typing import Any


def parse_json_stdout(stdout: str) -> tuple[dict[str, Any], str]:
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        return {}, "WARNING"
    if not isinstance(parsed, dict):
        return {}, "WARNING"
    observations: dict[str, Any] = {}
    for key in (
        "governance_result",
        "execution_result",
        "decision",
        "convergence_matched",
        "token_failures",
        "matched",
        "replay_count",
        "mismatches",
    ):
        if key in parsed:
            observations[key] = parsed[key]
    return observations, "OK" if observations else "WARNING"


def compare_observations(observed: dict[str, Any], expected: dict[str, Any]) -> str:
    if not expected:
        return "OBSERVATION_NOT_CHECKED"
    matched = sum(1 for key, value in expected.items() if observed.get(key) == value)
    if matched == len(expected):
        return "OBSERVATION_MATCH"
    if matched:
        return "OBSERVATION_PARTIAL"
    return "OBSERVATION_MISSING"
