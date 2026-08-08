from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest


def candidate_rank_score(
    state: Mapping[str, Any], candidate: Mapping[str, Any]
) -> int:
    """Return the deterministic score that a ranker is allowed to add."""
    safety = state.get("safety_profile", {}) or {}
    computed_tier = safety.get("computed_tier")
    score = 100

    pathway = candidate.get("pathway", {})
    pathway = pathway if isinstance(pathway, Mapping) else {}

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

    return score


def rank_candidates(
    state: Mapping[str, Any], candidates: list[Dict[str, Any]]
) -> list[Dict[str, Any]]:
    ranked = []

    for candidate in candidates:
        item = deepcopy(candidate)
        score = candidate_rank_score(state, item)

        item["rank_score"] = score
        ranked.append(item)

    return sorted(
        ranked,
        key=lambda item: (
            -int(item.get("rank_score", 0)),
            str(item.get("candidate_id", "")),
            generate_digest(item),
        ),
    )
