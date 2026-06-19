from __future__ import annotations

from typing import Any, Dict, Mapping


def evaluate_reentry(state: Mapping[str, Any]) -> Dict[str, Any]:
    governance_result = state.get("governance_result")
    fingerprint = state.get("request_fingerprint")
    context = state.get("context", {}) or {}
    last_denied = state.get("last_denied_fingerprint") or context.get(
        "prior_denied_fingerprint"
    )

    material_change_declared = bool(context.get("material_change_declared", False))
    material_change_reason = context.get("material_change_reason")
    escalation_path_available = bool(context.get("escalation_path_available", False))

    if governance_result == "ALLOW" and not last_denied:
        return {
            "reentry_permitted": False,
            "retry_eligible": False,
            "reason": "governance_allowed_no_reentry_required",
            "required_action": "continue_pipeline",
        }

    if governance_result == "ALLOW" and last_denied:
        if fingerprint == last_denied:
            return {
                "reentry_permitted": False,
                "retry_eligible": False,
                "reason": "identical_denied_request_cannot_reenter",
                "required_action": "remain_inoperative",
                "prior_denied_fingerprint": last_denied,
            }
        if not material_change_declared or not material_change_reason:
            return {
                "reentry_permitted": False,
                "retry_eligible": False,
                "reason": "governed_reentry_requires_material_change_evidence",
                "required_action": "remain_inoperative",
                "prior_denied_fingerprint": last_denied,
            }
        return {
            "reentry_permitted": True,
            "retry_eligible": True,
            "reason": "materially_corrected_request_full_revalidation_complete",
            "required_action": "complete_controlled_return",
            "prior_denied_fingerprint": last_denied,
            "current_request_fingerprint": fingerprint,
            "material_change_reason": material_change_reason,
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

    return {
        "reentry_permitted": False,
        "retry_eligible": False,
        "reason": "governance_denied",
        "required_action": "remain_inoperative",
  }
