from __future__ import annotations

from typing import Any, Mapping


def evaluate_cascading_impact(context: Mapping[str, Any]) -> dict[str, Any]:
    impact = dict(context.get("cascading_impact", {}) or {})
    affected = max(0, int(impact.get("affected_dependencies", 0)))
    propagation = max(0, min(3, int(impact.get("propagation_level", 0))))
    score = affected + propagation * 2
    return {"score": score, "bounded": impact.get("bounded") is True, "affected_dependencies": affected}

