from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

LOW = "LOW"
MEDIUM = "MEDIUM"
TOP = "TOP"

CORROBORATION_REQUIREMENTS = {LOW: 2, MEDIUM: 3, TOP: 5}
FINANCIAL_TIERS = {LOW: {"min": 0, "max": 10_000}, MEDIUM: {"min": 10_001, "max": 1_000_000}, TOP: {"min": 1_000_001, "max": None}}


def calculate_consequentiality_tier(*, human_safety: int, irreversibility: int, cascading_impact: int, financial_operational: int) -> str:
    tier_value = max(int(human_safety), int(irreversibility), int(cascading_impact), int(financial_operational))
    if tier_value <= 1:
        return LOW
    if tier_value <= 3:
        return MEDIUM
    return TOP


def calculate_financial_tier(amount: int | float | None) -> str:
    amount_value = float(amount or 0)
    if amount_value <= FINANCIAL_TIERS[LOW]["max"]:
        return LOW
    if amount_value <= FINANCIAL_TIERS[MEDIUM]["max"]:
        return MEDIUM
    return TOP


def required_corroboration_for_tier(tier: str) -> int:
    return CORROBORATION_REQUIREMENTS.get(tier, CORROBORATION_REQUIREMENTS[TOP])


def apply_thresholds(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    safety_profile = working_state.setdefault("safety_profile", {})
    context = working_state.setdefault("context", {})

    human_safety = int(safety_profile.get("human_safety", 0))
    irreversibility = int(safety_profile.get("irreversibility", 0))
    cascading_impact = int(safety_profile.get("cascading_impact", 0))
    financial_operational = int(safety_profile.get("financial_operational", 0))
    computed_tier = calculate_consequentiality_tier(
        human_safety=human_safety,
        irreversibility=irreversibility,
        cascading_impact=cascading_impact,
        financial_operational=financial_operational,
    )
    financial_amount = context.get("financial_amount", 0)
    financial_tier = calculate_financial_tier(financial_amount)
    corroboration_required = required_corroboration_for_tier(computed_tier)
    evidence = context.get("evidence", [])
    evidence_count = len(evidence) if isinstance(evidence, list) else 0

    safety_profile["computed_tier"] = computed_tier
    safety_profile["financial_tier"] = financial_tier
    working_state["corroboration_required"] = corroboration_required
    working_state["corroboration_met"] = evidence_count >= corroboration_required

    threshold_snapshot = {
        "human_safety": human_safety,
        "irreversibility": irreversibility,
        "cascading_impact": cascading_impact,
        "financial_operational": financial_operational,
        "computed_tier": computed_tier,
        "financial_amount": financial_amount,
        "financial_tier": financial_tier,
        "corroboration_required": corroboration_required,
        "corroboration_met": working_state["corroboration_met"],
        "evidence_count": evidence_count,
    }
    working_state.setdefault("governance_feedback", {})["threshold_snapshot"] = threshold_snapshot
    return working_state
