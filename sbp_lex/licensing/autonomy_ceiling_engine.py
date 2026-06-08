from __future__ import annotations

from typing import Any, Dict, Mapping


def validate_autonomy_ceiling(state: Mapping[str, Any]) -> Dict[str, Any]:
    classification = state.get("classification", {})

    autonomy_level = classification.get("autonomy_level")
    autonomy_ceiling = classification.get("autonomy_ceiling")

    failures: list[str] = []

    if autonomy_level is None:
        failures.append("autonomy_level_missing")

    if autonomy_ceiling is None:
        failures.append("autonomy_ceiling_missing")

    if autonomy_level is not None and autonomy_ceiling is not None:
        try:
            if float(autonomy_level) > float(autonomy_ceiling):
                failures.append("autonomy_ceiling_exceeded")
        except (TypeError, ValueError):
            failures.append("autonomy_values_invalid")

    return {
        "result": "ALLOW" if len(failures) == 0 else "DENY",
        "failures": failures,
        "autonomy_level": autonomy_level,
        "autonomy_ceiling": autonomy_ceiling,
  }
