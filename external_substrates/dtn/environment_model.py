from __future__ import annotations

from typing import Any, Mapping


def model_environment(context: Mapping[str, Any]) -> dict[str, Any]:
    environment = dict(context.get("environment", {}) or {})
    return {
        "environment_type": str(environment.get("type") or "declared"),
        "controlled": environment.get("controlled") is True,
        "human_proximity": str(environment.get("human_proximity") or "unknown"),
        "conditions": sorted(str(item) for item in environment.get("conditions", [])),
    }

