from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.aurion15.candidate.generator import CANDIDATE_SCHEMA_VERSION
from sbp_lex.security.domain_aurion_evidence import (
    candidate_bindings,
    constraint_snapshot,
)
from sbp_lex.security.pqc import generate_digest


CANDIDATE_FIELDS = {
    "schema_version",
    "candidate_id",
    "source",
    "action",
    "pathway",
    "constraints",
    "bindings",
    "rank_score",
    "rejection_reasons",
}
PATHWAY_FIELDS = {
    "mode",
    "requires_monitoring",
    "preserve_constraints",
    "execute_original_action",
    "autonomy_required",
    "operational_scope",
    "licensing_scope",
    "resolved_authority",
    "consequence_tier",
}
VALID_SOURCES = {
    "requested_pathway",
    "aurion_minimal_admissible",
    "aurion_safe_state",
}
VALID_PATHWAY_MODES = {
    "requested_constrained_pathway",
    "minimal_admissible_execution",
    "safe_state_or_hold",
}


def _candidate_digest(candidate: Mapping[str, Any]) -> str:
    try:
        return generate_digest(dict(candidate))
    except (TypeError, ValueError):
        return "INVALID_NON_CANONICAL_CANDIDATE"


def validate_candidate_constraints(
    state: Mapping[str, Any], candidate: Mapping[str, Any]
) -> Dict[str, Any]:
    failures: list[str] = []
    if not isinstance(candidate, Mapping):
        return {
            "valid": False,
            "failures": ["candidate_not_mapping"],
            "candidate_id": None,
            "candidate_digest": generate_digest({}),
        }

    if set(candidate) != CANDIDATE_FIELDS:
        failures.append("candidate_schema_invalid")
    if candidate.get("schema_version") != CANDIDATE_SCHEMA_VERSION:
        failures.append("candidate_schema_version_invalid")
    candidate_id = candidate.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        failures.append("candidate_id_invalid")
    if candidate.get("source") not in VALID_SOURCES:
        failures.append("candidate_source_invalid")
    if candidate.get("action") != state.get("action"):
        failures.append("candidate_action_mismatch")
    if (
        not isinstance(candidate.get("rank_score"), int)
        or isinstance(candidate.get("rank_score"), bool)
    ):
        failures.append("candidate_rank_score_invalid")
    if candidate.get("rejection_reasons") != []:
        failures.append("candidate_prepopulated_rejection_reasons")

    constraints = candidate.get("constraints")
    if not isinstance(constraints, Mapping):
        failures.append("candidate_constraints_missing")
        constraints = {}
    expected_constraints = constraint_snapshot(state)
    if dict(constraints) != expected_constraints:
        failures.append("candidate_constraint_snapshot_mismatch")

    bindings = candidate.get("bindings")
    if not isinstance(bindings, Mapping):
        failures.append("candidate_bindings_missing")
        bindings = {}
    if dict(bindings) != candidate_bindings(state):
        failures.append("candidate_state_binding_mismatch")

    pathway = candidate.get("pathway")
    if not isinstance(pathway, Mapping):
        failures.append("candidate_pathway_invalid")
        pathway = {}
    elif set(pathway) - PATHWAY_FIELDS:
        failures.append("candidate_pathway_schema_invalid")

    mode = pathway.get("mode")
    if mode not in VALID_PATHWAY_MODES:
        failures.append("candidate_pathway_mode_invalid")
    monitoring = pathway.get("requires_monitoring")
    if not isinstance(monitoring, bool):
        failures.append("candidate_monitoring_declaration_missing")
    class_profile = state.get("classification", {})
    class_profile = class_profile if isinstance(class_profile, Mapping) else {}
    profile = class_profile.get("class_profile", {})
    profile = profile if isinstance(profile, Mapping) else {}
    if profile.get("requires_monitoring") is True and monitoring is not True:
        failures.append("candidate_missing_required_monitoring")

    safe_hold = mode == "safe_state_or_hold"
    if safe_hold:
        if pathway.get("execute_original_action") is not False:
            failures.append("candidate_safe_state_not_fail_closed")
    elif pathway.get("preserve_constraints") is not True:
        failures.append("candidate_constraint_preservation_missing")

    autonomy_required = pathway.get(
        "autonomy_required", expected_constraints.get("autonomy_level")
    )
    ceiling = expected_constraints.get("autonomy_ceiling")
    if (
        isinstance(autonomy_required, bool)
        or not isinstance(autonomy_required, int)
        or autonomy_required < 0
    ):
        failures.append("candidate_autonomy_invalid")
    elif (
        isinstance(ceiling, int)
        and not isinstance(ceiling, bool)
        and autonomy_required > ceiling
    ):
        failures.append("candidate_autonomy_exceeds_ceiling")

    optional_exact = {
        "operational_scope": expected_constraints.get(
            "domain_operational_scope"
        ),
        "licensing_scope": expected_constraints.get("licensing_scope"),
        "resolved_authority": expected_constraints.get("resolved_authority"),
        "consequence_tier": expected_constraints.get("computed_tier"),
    }
    for field, expected in optional_exact.items():
        if field in pathway and pathway.get(field) != expected:
            failures.append(f"candidate_{field}_mismatch")

    required_state = {
        "procedural_truth_result": "PASS",
        "procedural_truth_outcome": "PT_PASS",
        "classification_result": "ALLOW",
        "licensing_result": "ALLOW",
        "governance_result": "ALLOW",
        "grc_result": "PASS",
        "domain_result": "pass",
    }
    for field, expected in required_state.items():
        if state.get(field) != expected:
            failures.append(f"candidate_upstream_invalid:{field}")

    return {
        "valid": not failures,
        "failures": sorted(set(failures)),
        "candidate_id": candidate_id,
        "candidate_digest": _candidate_digest(candidate),
    }
