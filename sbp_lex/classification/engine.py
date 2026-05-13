from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.classification.ap_acf import (
    derive_pipeline_mode_from_class,
    derive_subclass,
    get_class_profile,
    normalize_ap_acf_class,
)
from sbp_lex.classification.environment_modifiers import (
    environment_requires_escalation,
    normalize_environment_modifiers,
    public_exposure_is_high,
)
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry


def run_classification(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []
    warnings: list[str] = []

    context = working_state.get("context", {})
    collective = working_state.get("collective_signals", {})
    declaration = (
        working_state.get("payload", {}).get("classification")
        or working_state.get("payload", {}).get("ap_acf")
        or working_state.get("classification")
        or collective.get("ap_acf_declaration")
        or context.get("classification")
        or {}
    )

    if not isinstance(declaration, Mapping):
        declaration = {}
        failures.append("classification_declaration_invalid")

    declared_class = declaration.get("ap_acf_class") or declaration.get("class") or declaration.get("risk_class")
    ap_acf_class = normalize_ap_acf_class(declared_class)

    if ap_acf_class is None:
        failures.append("ap_acf_class_missing_or_invalid")

    profile = get_class_profile(ap_acf_class)
    subclass = derive_subclass(ap_acf_class)

    modifiers = normalize_environment_modifiers({**context, **declaration})

    declared_autonomy_ceiling = declaration.get("autonomy_ceiling")
    default_autonomy_ceiling = profile.get("default_autonomy_ceiling") if profile else None
    autonomy_ceiling = declared_autonomy_ceiling if declared_autonomy_ceiling is not None else default_autonomy_ceiling

    try:
        autonomy_ceiling = float(autonomy_ceiling) if autonomy_ceiling is not None else None
    except (TypeError, ValueError):
        failures.append("autonomy_ceiling_invalid")
        autonomy_ceiling = None

    autonomy_level = declaration.get("autonomy_level", context.get("autonomy_level", 0))
    try:
        autonomy_level = float(autonomy_level)
    except (TypeError, ValueError):
        failures.append("autonomy_level_invalid")
        autonomy_level = 0.0

    if autonomy_ceiling is not None and autonomy_level > autonomy_ceiling:
        failures.append("autonomy_level_exceeds_classification_ceiling")

    if public_exposure_is_high(modifiers) and profile and profile["risk_level"] < 3:
        warnings.append("public_exposure_high_for_low_class")

    escalation_required = environment_requires_escalation(modifiers)

    threshold_tier = working_state.get("safety_profile", {}).get("computed_tier")
    pipeline_mode = derive_pipeline_mode_from_class(ap_acf_class, threshold_tier)

    classification_state = {
        "ap_acf_class": ap_acf_class,
        "subclass": subclass,
        "class_profile": profile,
        "autonomy_level": autonomy_level,
        "autonomy_ceiling": autonomy_ceiling,
        "environment_modifiers": modifiers,
        "public_exposure": modifiers.get("public_exposure"),
        "operational_scope": modifiers.get("operational_scope"),
        "deployment_restrictions": declaration.get("deployment_restrictions", []),
        "manufacturer_declaration": working_state.get("payload", {}).get("manufacturer_declaration", {}),
        "escalation_required": escalation_required,
        "warnings": warnings,
    }

    classification_result = "ALLOW" if len(failures) == 0 else "DENY"
    classification_reason = "classification_valid" if classification_result == "ALLOW" else ",".join(failures)

    working_state["classification"] = classification_state
    working_state["classification_result"] = classification_result
    working_state["classification_reason"] = classification_reason
    working_state["pipeline_mode"] = pipeline_mode

    working_state.setdefault("governance_feedback", {})["classification"] = {
        "result": classification_result,
        "reason": classification_reason,
        "classification_state": classification_state,
        "failures": failures,
        "warnings": warnings,
  )
        if classification_result == "ALLOW":
        working_state = issue_token(
            working_state,
            name="classification",
            issued_at_stage="classification",
            payload={
                "ap_acf_class": ap_acf_class,
                "subclass": subclass,
                "autonomy_level": autonomy_level,
                "autonomy_ceiling": autonomy_ceiling,
                "public_exposure": modifiers.get("public_exposure"),
                "operational_scope": modifiers.get("operational_scope"),
                "pipeline_mode": pipeline_mode,
            },
        )
    else:
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "classification",
            "result": classification_result,
            "reason": classification_reason,
            "pipeline_mode": pipeline_mode,
        }
    )

    return append_hash_entry(
        working_state,
        stage="classification",
        payload={
            "classification_result": classification_result,
            "classification_reason": classification_reason,
            "classification_state": classification_state,
        },
    )
