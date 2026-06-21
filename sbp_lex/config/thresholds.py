from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

LOW = "LOW"
MEDIUM = "MEDIUM"
TOP = "TOP"

CORROBORATION_REQUIREMENTS = {LOW: 2, MEDIUM: 3, TOP: 5}
FINANCIAL_THRESHOLDS = {
    "low_max": 499.99,
    "medium_max": 49_999.99,
    "currency": "AUD",
}
TIER_RANK = {LOW: 1, MEDIUM: 2, TOP: 3}


def _safe_factor(value: Any) -> int:
    try:
        factor = int(value)
    except (TypeError, ValueError):
        return 0
    return factor if factor >= 0 else 0


def calculate_consequentiality_tier(
    *,
    human_safety: Any,
    irreversibility: Any,
    cascading_impact: Any,
    financial_operational: Any,
) -> str:
    tier_value = max(
        _safe_factor(human_safety),
        _safe_factor(irreversibility),
        _safe_factor(cascading_impact),
        _safe_factor(financial_operational),
    )
    if tier_value >= 3:
        return TOP
    if tier_value == 2:
        return MEDIUM
    return LOW


def calculate_financial_factor(amount: int | float | None) -> int:
    try:
        amount_value = float(amount) if amount is not None else 0.0
    except (TypeError, ValueError):
        amount_value = 0.0
    if amount_value <= FINANCIAL_THRESHOLDS["low_max"]:
        return 1
    if amount_value <= FINANCIAL_THRESHOLDS["medium_max"]:
        return 2
    return 3


def calculate_financial_tier(amount: int | float | None) -> str:
    return {1: LOW, 2: MEDIUM, 3: TOP}[calculate_financial_factor(amount)]


def required_corroboration_for_tier(tier: str) -> int:
    return CORROBORATION_REQUIREMENTS.get(tier, CORROBORATION_REQUIREMENTS[TOP])


def apply_thresholds(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    safety_profile = working_state.setdefault("safety_profile", {})
    context = working_state.setdefault("context", {})

    human_safety = _safe_factor(safety_profile.get("human_safety"))
    irreversibility = _safe_factor(safety_profile.get("irreversibility"))
    cascading_impact = _safe_factor(safety_profile.get("cascading_impact"))
    financial_amount = context.get("financial_amount", 0)
    financial_factor = calculate_financial_factor(financial_amount)
    financial_operational = max(
        _safe_factor(safety_profile.get("financial_operational")),
        financial_factor,
    )
    computed_tier = calculate_consequentiality_tier(
        human_safety=human_safety,
        irreversibility=irreversibility,
        cascading_impact=cascading_impact,
        financial_operational=financial_operational,
    )
    financial_tier = calculate_financial_tier(financial_amount)
    existing_tier = safety_profile.get("computed_tier")
    if TIER_RANK.get(str(existing_tier), 0) > TIER_RANK[computed_tier]:
        computed_tier = str(existing_tier)
    existing_financial_tier = safety_profile.get("financial_tier")
    if TIER_RANK.get(str(existing_financial_tier), 0) > TIER_RANK[financial_tier]:
        financial_tier = str(existing_financial_tier)
    corroboration_required = required_corroboration_for_tier(computed_tier)

    safety_profile["human_safety"] = human_safety
    safety_profile["irreversibility"] = irreversibility
    safety_profile["cascading_impact"] = cascading_impact
    safety_profile["financial_operational"] = financial_operational
    safety_profile["computed_tier"] = computed_tier
    safety_profile["financial_tier"] = financial_tier
    working_state["corroboration_required"] = corroboration_required
    working_state["corroboration_met"] = False

    threshold_snapshot = {
        "human_safety": human_safety,
        "irreversibility": irreversibility,
        "cascading_impact": cascading_impact,
        "financial_operational": financial_operational,
        "computed_tier": computed_tier,
        "financial_amount": financial_amount,
        "financial_factor": financial_factor,
        "financial_tier": financial_tier,
        "corroboration_required": corroboration_required,
        "corroboration_met": False,
        "qualified_evidence_count": 0,
    }
    working_state.setdefault("governance_feedback", {})["threshold_snapshot"] = threshold_snapshot
    return working_state
