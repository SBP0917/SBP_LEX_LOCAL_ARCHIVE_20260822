from __future__ import annotations

from typing import Any, Dict, Mapping


def validate_candidate_constraints(state: Mapping[str, Any], candidate: Mapping[str, Any]) -> Dict[str, Any]:
    failures: list[str] = []
    classification = state.get("classification", {}) or {}
    candidate_constraints = candidate.get("constraints", {}) or {}
    pathway = candidate.get("pathway", {}) or {}

    if state.get("governance_result") != "ALLOW":
        failures.append("governance_not_allowed")

    if state.get("domain_result") != "pass":
        failures.append("domain_not_passed")

    if state.get("classification_result") != "ALLOW":
        failures.append("classification_not_allowed")

    if state.get("licensing_result") != "ALLOW":
        failures.append("licensing_not_allowed")

    expected_class = classification.get("ap_acf_class")
    candidate_class = candidate_constraints.get("classification")
    if expected_class and candidate_class and expected_class != candidate_class:
        failures.append("candidate_classification_mismatch")

    expected_scope = classification.get("operational_scope")
    candidate_scope = candidate_constraints.get("operational_scope")
    if expected_scope and candidate_scope and expected_scope != candidate_scope:
        failures.append("candidate_operational_scope_mismatch")

    autonomy_ceiling = classification.get("autonomy_ceiling")
    candidate_autonomy = pathway.get("autonomy_required", classification.get("autonomy_level", 0))
    if autonomy_ceiling is not None:
        try:
            if float(candidate_autonomy or 0) > float(autonomy_ceiling):
                failures.append("candidate_autonomy_exceeds_ceiling")
        except (TypeError, ValueError):
            failures.append("candidate_autonomy_invalid")

    if pathway.get("requires_monitoring") is False and classification.get("class_profile", {}).get("requires_monitoring") is True:
        failures.append("candidate_missing_required_monitoring")

    return {
        "valid": len(failures) == 0,
        "failures": failures,
        "candidate_id": candidate.get("candidate_id"),
  }
