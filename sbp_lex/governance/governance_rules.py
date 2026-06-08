from __future__ import annotations

from typing import Any, Dict, Mapping

GOVERNANCE_ALLOW = "ALLOW"
GOVERNANCE_DENY = "DENY"
GOVERNANCE_ESCALATE = "ESCALATE"

MANDATORY_ALLOW_DEPENDENCIES = {
    "authority_first_result": "PASS",
    "procedural_truth_result": "PASS",
    "classification_result": "ALLOW",
    "licensing_result": "ALLOW",
}

ESCALATION_TIERS = {"TOP"}
ESCALATION_CLASSES = {"CLASS_5", "CLASS_5A", "CLASS_5B"}
ESCALATION_ENVIRONMENTS = {
    "defence",
    "aviation",
    "critical_infrastructure",
    "public_transport",
    "medical",
    "surgical",
    "energy_grid",
    "water_system",
}


def dependency_failures(state: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for key, expected in MANDATORY_ALLOW_DEPENDENCIES.items():
        if state.get(key) != expected:
            failures.append(f"{key}_not_{expected}")
    return failures


def escalation_required(state: Mapping[str, Any]) -> bool:
    classification = state.get("classification", {}) or {}
    safety_profile = state.get("safety_profile", {}) or {}
    context = state.get("context", {}) or {}

    computed_tier = safety_profile.get("computed_tier")
    ap_acf_class = classification.get("ap_acf_class")
    class_escalation = bool(classification.get("escalation_required", False))

    environment = str(
        classification.get("environment_modifiers", {}).get(
            "environment",
            context.get("environment", ""),
        )
    ).lower()

    if computed_tier in ESCALATION_TIERS:
        return True

    if ap_acf_class in ESCALATION_CLASSES:
        return True

    if class_escalation:
        return True

    if environment in ESCALATION_ENVIRONMENTS:
        return True

    if bool(context.get("manual_escalation_required", False)):
        return True

    return False


def repeat_denial_violation(state: Mapping[str, Any]) -> bool:
    fingerprint = state.get("request_fingerprint")
    last_denied = state.get("last_denied_fingerprint")
    return bool(fingerprint and last_denied and fingerprint == last_denied)


def determine_governance_result(state: Mapping[str, Any]) -> Dict[str, Any]:
    failures = dependency_failures(state)

    if repeat_denial_violation(state):
        failures.append("identical_denied_request_reentry")

    if failures:
        return {
            "result": GOVERNANCE_DENY,
            "reason": ",".join(failures),
            "failures": failures,
            "escalation_required": False,
        }

    must_escalate = escalation_required(state)
    if must_escalate:
        return {
            "result": GOVERNANCE_ESCALATE,
            "reason": "escalation_required_by_threshold_class_or_environment",
            "failures": [],
            "escalation_required": True,
        }

    return {
        "result": GOVERNANCE_ALLOW,
        "reason": "governance_admissibility_satisfied",
        "failures": [],
        "escalation_required": False,
  }
