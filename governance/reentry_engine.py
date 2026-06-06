from __future__ import annotations

from typing import Any, Dict, Mapping


def evaluate_reentry(state: Mapping[str, Any]) -> Dict[str, Any]:
    governance_result = state.get("governance_result")
    fingerprint = state.get("request_fingerprint")
    last_denied = state.get("last_denied_fingerprint")
    context = state.get("context", {}) or {}

    material_change_declared = bool(context.get("material_change_declared", False))
    escalation_path_available = bool(context.get("escalation_path_available", False))

    if governance_result == "ALLOW":
        return {
            "reentry_permitted": False,
            "retry_eligible": False,
            "reason": "governance_allowed_no_reentry_required",
            "required_action": "continue_pipeline",
        }

    if fingerprint and last_denied and fingerprint == last_denied and not material_change_declared:
        return {
            "reentry_permitted": False,
            "retry_eligible": False,
            "reason": "identical_denied_request_no_material_change",
            "required_action": "deny_again_immediately",
        }

    if governance_result == "ESCALATE":
        return {
            "reentry_permitted": escalation_path_available,
            "retry_eligible": False,
            "reason": "escalation_required",
            "required_action": "human_or_authority_review",
        }

    if governance_result == "DENY" and material_change_declared:
        return {
            "reentry_permitted": True,
            "retry_eligible": True,
            "reason": "material_change_declared_full_revalidation_required",
            "required_action": "full_pipeline_revalidation",
        }

    return {
        "reentry_permitted": False,
        "retry_eligible": False,
        "reason": "governance_denied",
        "required_action": "remain_inoperative",
  }
