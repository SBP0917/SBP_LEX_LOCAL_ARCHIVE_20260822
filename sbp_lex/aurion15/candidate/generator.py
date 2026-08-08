from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.domain_aurion_evidence import (
    candidate_bindings,
    constraint_snapshot,
)


CANDIDATE_SCHEMA_VERSION = "desktop-v1.aurion-candidate.v1"


def _candidate(
    state: Mapping[str, Any],
    *,
    candidate_id: str,
    source: str,
    pathway: object,
) -> Dict[str, Any]:
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "source": source,
        "action": state.get("action"),
        "pathway": deepcopy(pathway),
        "constraints": constraint_snapshot(state),
        "bindings": candidate_bindings(state),
        "rank_score": 0,
        "rejection_reasons": [],
    }


def generate_candidates(state: Mapping[str, Any]) -> list[Dict[str, Any]]:
    payload = state.get("payload", {}) or {}
    payload = payload if isinstance(payload, Mapping) else {}
    context = state.get("context", {}) or {}
    context = context if isinstance(context, Mapping) else {}

    requested_pathway = payload.get("requested_pathway") or context.get("requested_pathway")

    candidates: list[Dict[str, Any]] = []

    if requested_pathway:
        candidates.append(
            _candidate(
                state,
                candidate_id="candidate_requested_001",
                source="requested_pathway",
                pathway=requested_pathway,
            )
        )

    candidates.append(
        _candidate(
            state,
            candidate_id="candidate_minimal_admissible_001",
            source="aurion_minimal_admissible",
            pathway={
                "mode": "minimal_admissible_execution",
                "requires_monitoring": True,
                "preserve_constraints": True,
            },
        )
    )

    candidates.append(
        _candidate(
            state,
            candidate_id="candidate_safe_state_001",
            source="aurion_safe_state",
            pathway={
                "mode": "safe_state_or_hold",
                "requires_monitoring": True,
                "execute_original_action": False,
            },
        )
    )

    return candidates
