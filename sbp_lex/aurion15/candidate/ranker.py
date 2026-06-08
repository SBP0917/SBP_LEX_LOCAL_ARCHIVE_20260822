from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping


def rank_candidates(state: Mapping[str, Any], candidates: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    ranked = []
    safety = state.get("safety_profile", {}) or {}
    computed_tier = safety.get("computed_tier")

    for candidate in candidates:
        item = deepcopy(candidate)
        score = 100

        pathway = item.get("pathway", {})

        if pathway.get("preserve_constraints"):
            score += 20

        if pathway.get("requires_monitoring"):
            score += 10

        if pathway.get("mode") == "safe_state_or_hold":
            score += 5
            if computed_tier == "TOP":
                score += 30

        if pathway.get("execute_original_action") is False and computed_tier != "TOP":
            score -= 10

        item["rank_score"] = score
        ranked.append(item)

    return sorted(ranked, key=lambda x: x.get("rank_score", 0), reverse=True)
