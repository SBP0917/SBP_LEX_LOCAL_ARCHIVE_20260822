from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.classification.ap_acf import derive_pipeline_mode_from_class, derive_subclass, get_class_profile, normalize_ap_acf_class
from sbp_lex.classification.environment_modifiers import environment_requires_escalation, normalize_environment_modifiers, public_exposure_is_high
from sbp_lex.security.token_stack import issue_token
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.authority_boundary import validate_canonical_upstream
from sbp_lex.security.governed_stage_evidence import (
    append_stage_finalisation,
    build_stage_evidence,
    invalidate_from_stage,
    live_state_hash_valid,
    stage_already_completed,
    stage_token_payload,
)
from sbp_lex.shared.hash_chain import rebuild_state_hash


def run_classification(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    state_hash_entering_stage = working_state.get("state_hash")
    failures: list[str] = []
    warnings: list[str] = []
    already_completed = stage_already_completed(working_state, "classification")
    if not live_state_hash_valid(working_state):
        failures.append("classification_entry_state_hash_invalid")
    working_state = invalidate_from_stage(working_state, "classification")
    if already_completed:
        failures.append("classification_reentry_requires_full_retraversal")
    upstream_valid, upstream_failures = validate_canonical_upstream(
        working_state, required_tokens=("authority", "procedural_truth")
    )
    if not upstream_valid:
        failures.extend(upstream_failures)

    context = working_state.get("context", {}) or {}
    collective = working_state.get("collective_signals", {}) or {}
    payload = working_state.get("payload", {}) or {}
    declaration = working_state.get("ap_acf_declaration") or payload.get("classification") or payload.get("ap_acf") or working_state.get("classification") or collective.get("ap_acf_declaration") or context.get("classification") or {}

    if not isinstance(declaration, Mapping):
        declaration = {}
        failures.append("classification_declaration_invalid")
    if working_state.get("ap_acf_precheck_result") != "PASS":
        failures.append("ap_acf_precheck_not_pass")
    if working_state.get("ap_acf_declaration_hash") != generate_digest(declaration):
        failures.append("ap_acf_declaration_changed_after_precheck")

    ap_acf_class = normalize_ap_acf_class(declaration.get("ap_acf_class") or declaration.get("class") or declaration.get("risk_class"))
    if ap_acf_class is None:
        failures.append("ap_acf_class_missing_or_invalid")

    profile = get_class_profile(ap_acf_class)
    subclass = derive_subclass(ap_acf_class)
    nested_modifiers = declaration.get("environment_modifiers", {})
    if not isinstance(nested_modifiers, Mapping):
        nested_modifiers = {}
        failures.append("environment_modifiers_invalid")
    modifier_source = {**context, **nested_modifiers}
    for field in (
        "environment",
        "human_proximity",
        "geographic_isolation",
        "operational_containment",
        "public_exposure",
        "operational_scope",
    ):
        if field in declaration:
            if (
                field in nested_modifiers
                and nested_modifiers.get(field) != declaration.get(field)
            ):
                failures.append(f"environment_modifier_conflict:{field}")
            modifier_source[field] = declaration.get(field)
    modifiers = normalize_environment_modifiers(modifier_source)

    default_autonomy_ceiling = profile.get("default_autonomy_ceiling") if profile else None
    autonomy_ceiling = declaration.get("autonomy_ceiling", default_autonomy_ceiling)
    if (
        isinstance(autonomy_ceiling, bool)
        or not isinstance(autonomy_ceiling, int)
        or autonomy_ceiling < 0
        or autonomy_ceiling > 100
    ):
        failures.append("autonomy_ceiling_invalid")

    autonomy_level = declaration.get("autonomy_level", context.get("autonomy_level", 0))
    if (
        isinstance(autonomy_level, bool)
        or not isinstance(autonomy_level, int)
        or autonomy_level < 0
        or autonomy_level > 100
    ):
        failures.append("autonomy_level_invalid")

    if (
        isinstance(autonomy_ceiling, int)
        and not isinstance(autonomy_ceiling, bool)
        and isinstance(default_autonomy_ceiling, int)
        and autonomy_ceiling > default_autonomy_ceiling
    ):
        failures.append("autonomy_ceiling_exceeds_class_profile")

    if (
        isinstance(autonomy_ceiling, int)
        and not isinstance(autonomy_ceiling, bool)
        and isinstance(autonomy_level, int)
        and not isinstance(autonomy_level, bool)
        and autonomy_level > autonomy_ceiling
    ):
        failures.append("autonomy_level_exceeds_classification_ceiling")
    if public_exposure_is_high(modifiers) and profile and profile["risk_level"] < 3:
        warnings.append("public_exposure_high_for_low_class")

    escalation_required = environment_requires_escalation(modifiers)
    threshold_tier = working_state.get("safety_profile", {}).get("computed_tier")
    pipeline_mode = derive_pipeline_mode_from_class(ap_acf_class, threshold_tier)

    restrictions = declaration.get("deployment_restrictions", [])
    if not isinstance(restrictions, list) or any(
        not isinstance(item, str) or not item.strip() for item in restrictions
    ):
        failures.append("deployment_restrictions_invalid")
        restrictions = []

    failures = sorted(set(failures))
    warnings = sorted(set(warnings))
    payload_manufacturer = payload.get("manufacturer_declaration", {})
    declared_manufacturer = declaration.get("manufacturer_declaration", {})
    if payload_manufacturer and declared_manufacturer and (
        payload_manufacturer != declared_manufacturer
    ):
        failures.append("manufacturer_declaration_conflict")
    manufacturer_declaration = declared_manufacturer or payload_manufacturer or {}
    if not isinstance(manufacturer_declaration, Mapping):
        failures.append("manufacturer_declaration_invalid")
        manufacturer_declaration = {}

    failures = sorted(set(failures))
    classification_state = {
        "ap_acf_class": ap_acf_class,
        "subclass": subclass,
        "class_profile": profile,
        "autonomy_level": autonomy_level,
        "autonomy_ceiling": autonomy_ceiling,
        "environment_modifiers": modifiers,
        "public_exposure": modifiers.get("public_exposure"),
        "operational_scope": modifiers.get("operational_scope"),
        "deployment_restrictions": restrictions,
        "manufacturer_declaration": deepcopy(dict(manufacturer_declaration)),
        "escalation_required": escalation_required,
        "warnings": warnings,
    }
    classification_result = "ALLOW" if not failures else "DENY"
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
    }

    if classification_result != "ALLOW":
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"

    working_state.setdefault("audit_trace", []).append({"stage": "classification", "result": classification_result, "reason": classification_reason, "pipeline_mode": pipeline_mode})
    working_state["state_hash"] = rebuild_state_hash(working_state)
    working_state["classification_evidence"] = build_stage_evidence(
        working_state,
        stage="classification",
        state_hash_entering_stage=state_hash_entering_stage,
    )
    if classification_result == "ALLOW":
        working_state = issue_token(
            working_state,
            name="classification",
            issued_at_stage="classification",
            payload=stage_token_payload(working_state, "classification"),
        )
    return append_stage_finalisation(working_state, stage="classification")
