from __future__ import annotations

from typing import Any, Mapping


def evaluate_risk_potential(context: Mapping[str, Any], cascading: Mapping[str, Any]) -> dict[str, Any]:
    declared = max(0, min(10, int(context.get("declared_risk", 0))))
    score = min(10, declared + min(5, int(cascading.get("score", 0))))
    level = "LOW" if score <= 3 else "MEDIUM" if score <= 6 else "TOP"
    return {"score": score, "level": level, "advisory_only": True}

