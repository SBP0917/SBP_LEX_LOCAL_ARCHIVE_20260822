from __future__ import annotations

from typing import Any, Dict, Mapping


def generate_candidates(state: Mapping[str, Any]) -> list[Dict[str, Any]]:
    action = state.get("action", "")
    payload = state.get("payload", {}) or {}
    context = state.get("context", {}) or {}
    classification = state.get("classification", {}) or {}

    requested_pathway = payload.get("requested_pathway") or context.get("requested_pathway")

    candidates: list[Dict[str, Any]] = []

    if requested_pathway:
        candidates.append(
            {
                "candidate_id": "candidate_requested_001",
                "source": "requested_pathway",
                "action": action,
                "pathway": requested_pathway,
                "constraints": {
                    "classification": classification.get("ap_acf_class"),
                    "autonomy_ceiling": classification.get("autonomy_ceiling"),
                    "operational_scope": classification.get("operational_scope"),
                },
                "rank_score": 0,
                "rejection_reasons": [],
            }
        )

    candidates.append(
        {
            "candidate_id": "candidate_minimal_admissible_001",
            "source": "aurion_minimal_admissible",
            "action": action,
            "pathway": {
                "mode": "minimal_admissible_execution",
                "requires_monitoring": True,
                "preserve_constraints": True,
            },
            "constraints": {
                "classification": classification.get("ap_acf_class"),
                "autonomy_ceiling": classification.get("autonomy_ceiling"),
                "operational_scope": classification.get("operational_scope"),
            },
            "rank_score": 0,
            "rejection_reasons": [],
        }
    )

    candidates.append(
        {
            "candidate_id": "candidate_safe_state_001",
            "source": "aurion_safe_state",
            "action": action,
            "pathway": {
                "mode": "safe_state_or_hold",
                "requires_monitoring": True,
                "execute_original_action": False,
            },
            "constraints": {
                "classification": classification.get("ap_acf_class"),
                "autonomy_ceiling": classification.get("autonomy_ceiling"),
                "operational_scope": classification.get("operational_scope"),
            },
            "rank_score": 0,
            "rejection_reasons": [],
        }
    )

    return candidates
