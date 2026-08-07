from __future__ import annotations

from copy import deepcopy
import math
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest

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
CONSEQUENCE_FACTOR_MIN = 0
CONSEQUENCE_FACTOR_MAX = 3


def _safe_factor(value: Any) -> int:
    try:
        factor = int(value)
    except (TypeError, ValueError):
        return 0
    return factor if factor >= 0 else 0


def _validated_factor(value: Any, *, name: str) -> tuple[int, list[str]]:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0, [f"{name}_must_be_integer"]
    if value < CONSEQUENCE_FACTOR_MIN or value > CONSEQUENCE_FACTOR_MAX:
        return 0, [f"{name}_out_of_range"]
    return value, []


def _validated_financial_amount(
    value: Any, *, supplied: bool
) -> tuple[float, str, list[str]]:
    # Desktop V1's existing missing-input policy is an explicit zero-value
    # default.  Malformed, boolean, non-finite, and negative values are never
    # silently converted into a LOW-risk input.
    if not supplied or value is None:
        return 0.0, "MISSING_DEFAULTED_ZERO", []
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0, "INVALID", ["financial_amount_must_be_finite_number"]
    try:
        amount = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0, "INVALID", ["financial_amount_must_be_finite_number"]
    if not math.isfinite(amount):
        return 0.0, "INVALID", ["financial_amount_must_be_finite_number"]
    if amount < 0:
        return 0.0, "INVALID", ["financial_amount_must_be_non_negative"]
    return amount, "VALID", []


def _valid_tier(value: Any) -> str | None:
    tier = str(value or "").upper()
    return tier if tier in TIER_RANK else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _root_evidence_digest(state: Mapping[str, Any]) -> Any:
    root = _mapping(
        state.get("root_of_trust_evidence")
        or state.get("root_of_trust_evidence_anchor")
    )
    return root.get("root_evidence_digest") or root.get("anchor_digest")


def _threshold_bindings(state: Mapping[str, Any]) -> Dict[str, Any]:
    envelope = _mapping(state.get("pt_evidence_envelope"))
    assessment = _mapping(envelope.get("source_assessment"))
    collective = _mapping(state.get("collective_signal_evidence"))
    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": collective.get("signal_digest"),
        "root_evidence_digest": _root_evidence_digest(state),
        "source_assessment_digest": assessment.get(
            "source_assessment_digest"
        ),
        "pre_root_threshold_state_digest": envelope.get(
            "threshold_state_digest"
        ),
    }


def validate_threshold_conditioning_state(
    state: Mapping[str, Any], *, require_complete: bool = True,
    require_observation: bool = True,
) -> tuple[bool, list[str]]:
    """Validate the sealed threshold state and its complete PT lineage."""

    failures: list[str] = []
    threshold_state = _mapping(state.get("threshold_conditioning_state"))
    payload = _mapping(threshold_state.get("payload"))
    if not threshold_state:
        return False, ["threshold_conditioning_state_missing"]
    if payload.get("schema_version") != "desktop-v1.threshold-conditioning.v1":
        failures.append("threshold_conditioning_schema_invalid")
    if threshold_state.get("threshold_state_digest") != generate_digest(
        dict(payload)
    ):
        failures.append("threshold_state_digest_mismatch")

    expected_bindings = _threshold_bindings(state)
    actual_bindings = {
        field: payload.get(field) for field in expected_bindings
    }
    if payload.get("threshold_binding_digest") != generate_digest(
        actual_bindings
    ):
        failures.append("threshold_binding_digest_mismatch")
    for field, expected_value in expected_bindings.items():
        if payload.get(field) != expected_value:
            failures.append(f"threshold_binding_mismatch:{field}")
        if require_complete and expected_value in (None, "", []):
            failures.append(f"threshold_binding_missing:{field}")

    safety = _mapping(state.get("safety_profile"))
    for field in (
        "human_safety",
        "irreversibility",
        "cascading_impact",
        "financial_operational",
        "computed_tier",
        "financial_tier",
    ):
        if payload.get(field) != safety.get(field):
            failures.append(f"threshold_active_state_mismatch:{field}")
    if payload.get("corroboration_required") != state.get(
        "corroboration_required"
    ):
        failures.append("threshold_active_state_mismatch:corroboration_required")
    if payload.get("corroboration_met") is not state.get("corroboration_met"):
        failures.append("threshold_active_state_mismatch:corroboration_met")
    if require_observation:
        assessment = _mapping(
            _mapping(state.get("pt_evidence_envelope")).get(
                "source_assessment"
            )
        )
        if payload.get("qualified_evidence_count") != assessment.get(
            "source_count_qualifying"
        ):
            failures.append(
                "threshold_active_state_mismatch:qualified_evidence_count"
            )
    return not failures, sorted(set(failures))


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
    except (TypeError, ValueError, OverflowError):
        amount_value = math.inf
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

    # Canonical traversals always derive the threshold basis from the immutable
    # request snapshot.  This prevents a mutable working-state field from
    # lowering the tier between attachment, Root, and PT.
    request_snapshot = working_state.get("request_identity_snapshot")
    if isinstance(request_snapshot, Mapping):
        canonical_safety = request_snapshot.get("safety_profile", {})
        canonical_context = request_snapshot.get("context", {})
        if isinstance(canonical_safety, Mapping):
            factor_basis = canonical_safety
        else:
            factor_basis = safety_profile
        if isinstance(canonical_context, Mapping):
            financial_context = canonical_context
        else:
            financial_context = context
        threshold_basis = "IMMUTABLE_REQUEST_SNAPSHOT"
    else:
        factor_basis = safety_profile
        financial_context = context
        threshold_basis = "DIRECT_THRESHOLD_INPUT"

    failures: list[str] = []
    human_safety, factor_failures = _validated_factor(
        factor_basis.get("human_safety"), name="human_safety"
    )
    failures.extend(factor_failures)
    irreversibility, factor_failures = _validated_factor(
        factor_basis.get("irreversibility"), name="irreversibility"
    )
    failures.extend(factor_failures)
    cascading_impact, factor_failures = _validated_factor(
        factor_basis.get("cascading_impact"), name="cascading_impact"
    )
    failures.extend(factor_failures)
    declared_financial_operational, factor_failures = _validated_factor(
        factor_basis.get("financial_operational"),
        name="financial_operational",
    )
    failures.extend(factor_failures)
    financial_amount, financial_input_status, financial_failures = (
        _validated_financial_amount(
            financial_context.get("financial_amount"),
            supplied="financial_amount" in financial_context,
        )
    )
    failures.extend(financial_failures)
    financial_factor = calculate_financial_factor(financial_amount)
    financial_operational = max(
        declared_financial_operational,
        financial_factor,
    )
    evaluated_tier = calculate_consequentiality_tier(
        human_safety=human_safety,
        irreversibility=irreversibility,
        cascading_impact=cascading_impact,
        financial_operational=financial_operational,
    )
    financial_tier = calculate_financial_tier(financial_amount)

    prior_conditioning = working_state.get("threshold_conditioning_state", {})
    prior_conditioning = (
        prior_conditioning if isinstance(prior_conditioning, Mapping) else {}
    )
    prior_payload = prior_conditioning.get("payload", {})
    prior_payload = prior_payload if isinstance(prior_payload, Mapping) else {}
    prior_digest = prior_conditioning.get("threshold_state_digest")
    if prior_conditioning and prior_digest != generate_digest(dict(prior_payload)):
        failures.append("threshold_state_digest_mismatch")

    existing_tier = _valid_tier(safety_profile.get("computed_tier"))
    prior_high_water = _valid_tier(prior_payload.get("high_water_tier"))
    previous_tier = max(
        (tier for tier in (existing_tier, prior_high_water, LOW) if tier),
        key=lambda tier: TIER_RANK[tier],
    )
    downgrade_attempted = TIER_RANK[evaluated_tier] < TIER_RANK[previous_tier]
    computed_tier = max(
        (previous_tier, evaluated_tier), key=lambda tier: TIER_RANK[tier]
    )
    transition = f"{previous_tier}_TO_{computed_tier}"
    if downgrade_attempted:
        failures.append(
            f"tier_downgrade_attempt:{previous_tier}_TO_{evaluated_tier}"
        )

    existing_financial_tier = _valid_tier(safety_profile.get("financial_tier"))
    if existing_financial_tier and (
        TIER_RANK[existing_financial_tier] > TIER_RANK[financial_tier]
    ):
        financial_tier = existing_financial_tier
    corroboration_required = required_corroboration_for_tier(computed_tier)

    safety_profile["human_safety"] = human_safety
    safety_profile["irreversibility"] = irreversibility
    safety_profile["cascading_impact"] = cascading_impact
    safety_profile["financial_operational"] = financial_operational
    safety_profile["computed_tier"] = computed_tier
    safety_profile["financial_tier"] = financial_tier
    working_state["corroboration_required"] = corroboration_required
    working_state["corroboration_met"] = False

    threshold_bindings = _threshold_bindings(working_state)
    if _root_evidence_digest(working_state):
        for field, value in threshold_bindings.items():
            if value in (None, "", []):
                failures.append(f"threshold_binding_missing:{field}")

    threshold_payload = {
        "schema_version": "desktop-v1.threshold-conditioning.v1",
        "threshold_basis": threshold_basis,
        "human_safety": human_safety,
        "irreversibility": irreversibility,
        "cascading_impact": cascading_impact,
        "financial_operational": financial_operational,
        "evaluated_tier": evaluated_tier,
        "previous_tier": previous_tier,
        "current_tier": computed_tier,
        "high_water_tier": computed_tier,
        "tier_transition": transition,
        "tier_downgrade_attempted": downgrade_attempted,
        "tier_monotonic": not downgrade_attempted,
        "computed_tier": computed_tier,
        "financial_amount": financial_amount,
        "financial_currency": FINANCIAL_THRESHOLDS["currency"],
        "financial_input_status": financial_input_status,
        "financial_factor": financial_factor,
        "financial_tier": financial_tier,
        "corroboration_required": corroboration_required,
        "corroboration_met": False,
        "qualified_evidence_count": 0,
        **threshold_bindings,
        "threshold_binding_digest": generate_digest(threshold_bindings),
        "validation_failures": sorted(set(failures)),
    }
    threshold_state_digest = generate_digest(threshold_payload)
    working_state["threshold_conditioning_state"] = {
        "payload": deepcopy(threshold_payload),
        "threshold_state_digest": threshold_state_digest,
    }
    threshold_snapshot = {
        **threshold_payload,
        "threshold_state_digest": threshold_state_digest,
    }
    working_state.setdefault("governance_feedback", {})["threshold_snapshot"] = threshold_snapshot
    return working_state
