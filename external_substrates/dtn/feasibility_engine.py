from __future__ import annotations

from typing import Any, Mapping


def evaluate_feasibility(
    dependency_signal: Mapping[str, Any],
    capability_signal: Mapping[str, Any],
    pathway_signal: Mapping[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []
    if dependency_signal.get("satisfied") is not True:
        reasons.append("dependencies_unsatisfied")
    if capability_signal.get("available") is not True:
        reasons.append("capabilities_unavailable")
    if pathway_signal.get("constraint_valid") is not True:
        reasons.append("skg_constraints_not_satisfied")
    return {"feasible": not reasons, "reasons": reasons}

