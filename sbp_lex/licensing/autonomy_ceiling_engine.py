from __future__ import annotations

from typing import Any, Dict, Mapping


def validate_autonomy_ceiling(state: Mapping[str, Any]) -> Dict[str, Any]:
    classification = state.get("classification", {})

    autonomy_level = classification.get("autonomy_level")
    autonomy_ceiling = classification.get("autonomy_ceiling")

    failures: list[str] = []

    if (
        isinstance(autonomy_level, bool)
        or not isinstance(autonomy_level, int)
        or autonomy_level < 0
        or autonomy_level > 100
    ):
        failures.append("autonomy_level_invalid")

    if (
        isinstance(autonomy_ceiling, bool)
        or not isinstance(autonomy_ceiling, int)
        or autonomy_ceiling < 0
        or autonomy_ceiling > 100
    ):
        failures.append("autonomy_ceiling_invalid")

    if not failures and autonomy_level > autonomy_ceiling:
        failures.append("autonomy_ceiling_exceeded")

    profile = classification.get("class_profile", {}) or {}
    profile_ceiling = profile.get("default_autonomy_ceiling")
    if (
        isinstance(autonomy_ceiling, int)
        and not isinstance(autonomy_ceiling, bool)
        and isinstance(profile_ceiling, int)
        and autonomy_ceiling > profile_ceiling
    ):
        failures.append("autonomy_ceiling_exceeds_class_profile")

    return {
        "result": "ALLOW" if len(failures) == 0 else "DENY",
        "failures": failures,
        "autonomy_level": autonomy_level,
        "autonomy_ceiling": autonomy_ceiling,
  }
