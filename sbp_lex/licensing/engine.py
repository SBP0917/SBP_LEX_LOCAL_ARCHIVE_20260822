from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.licensing.autonomy_ceiling_engine import validate_autonomy_ceiling
from sbp_lex.licensing.scope_engine import validate_deployment_scope
from sbp_lex.security.token_stack import issue_token
from sbp_lex.security.authority_boundary import validate_canonical_upstream
from sbp_lex.security.governed_stage_evidence import (
    append_stage_finalisation,
    build_stage_evidence,
    invalidate_from_stage,
    live_state_hash_valid,
    stage_already_completed,
    stage_token_payload,
    validate_constraint_continuity,
)
from sbp_lex.shared.hash_chain import rebuild_state_hash


ACCEPTED_LICENCE_STATES = {
    "DECLARED_VALID",
    "VALID",
    "GOVERNANCE_MANAGED",
}
STRUCTURED_LICENCE_FIELDS = {
    "state",
    "status",
    "licence_state",
    "license_state",
}


def _normalise_licence_state(
    state: Mapping[str, Any],
) -> tuple[str | None, list[str], list[str]]:
    context = state.get("context", {}) or {}
    payload = state.get("payload", {}) or {}
    candidates: list[tuple[str, object]] = []
    failures: list[str] = []
    for container_name, container in (("context", context), ("payload", payload)):
        if not isinstance(container, Mapping):
            failures.append(f"{container_name}_not_mapping")
            continue
        for field in ("licence_state", "license_state"):
            if field in container:
                candidates.append((f"{container_name}.{field}", container.get(field)))
        for field in ("licence", "license"):
            if field not in container:
                continue
            value = container.get(field)
            if isinstance(value, Mapping):
                unknown = sorted(set(value) - STRUCTURED_LICENCE_FIELDS)
                if unknown:
                    failures.append(
                        f"structured_licence_fields_unsupported:{','.join(unknown)}"
                    )
                nested = [
                    (f"{container_name}.{field}.{name}", value.get(name))
                    for name in STRUCTURED_LICENCE_FIELDS
                    if name in value
                ]
                if not nested:
                    failures.append("structured_licence_state_missing")
                candidates.extend(nested)
            else:
                candidates.append((f"{container_name}.{field}", value))

    normalized: list[tuple[str, str]] = []
    for source, value in candidates:
        if not isinstance(value, str) or not value.strip():
            failures.append(f"licence_state_malformed:{source}")
            continue
        normalized.append((source, value.strip().upper()))
    unique_values = sorted({value for _, value in normalized})
    if not normalized:
        failures.append("licence_state_missing")
        licence_state = None
    elif len(unique_values) != 1:
        failures.append("licence_state_conflict")
        licence_state = None
    else:
        licence_state = unique_values[0]
        if licence_state not in ACCEPTED_LICENCE_STATES:
            failures.append("licence_state_invalid")
    return licence_state, sorted(source for source, _ in normalized), sorted(set(failures))


def run_licensing(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    state_hash_entering_stage = working_state.get("state_hash")
    failures: list[str] = []
    already_completed = stage_already_completed(working_state, "licensing")
    if not live_state_hash_valid(working_state):
        failures.append("licensing_entry_state_hash_invalid")
    working_state = invalidate_from_stage(working_state, "licensing")
    if already_completed:
        failures.append("licensing_reentry_requires_full_retraversal")
    upstream_valid, upstream_failures = validate_canonical_upstream(
        working_state, required_tokens=("classification",)
    )
    if not upstream_valid:
        failures.extend(upstream_failures)

    if working_state.get("classification_result") != "ALLOW":
        failures.append("classification_not_allowed")

    constraints_valid, constraint_failures = validate_constraint_continuity(
        working_state, through_stage="classification"
    )
    if not constraints_valid:
        failures.extend(constraint_failures)

    autonomy_check = validate_autonomy_ceiling(working_state)
    scope_check = validate_deployment_scope(working_state)

    if autonomy_check.get("result") != "ALLOW":
        failures.extend(autonomy_check.get("failures", []))

    if scope_check.get("result") != "ALLOW":
        failures.extend(scope_check.get("failures", []))

    licence_state, licence_sources, licence_failures = _normalise_licence_state(
        working_state
    )
    failures.extend(licence_failures)

    failures = sorted(set(failures))
    licensing_result = "ALLOW" if len(failures) == 0 else "DENY"
    licensing_reason = "licensing_valid" if licensing_result == "ALLOW" else ",".join(failures)

    working_state["licensing_result"] = licensing_result
    working_state["licensing_reason"] = licensing_reason
    working_state["licensing_scope"] = scope_check.get("requested_scope")

    licensing_state = {
        "result": licensing_result,
        "reason": licensing_reason,
        "licence_state": licence_state,
        "licence_sources": licence_sources,
        "autonomy_check": autonomy_check,
        "scope_check": scope_check,
        "operational_scope": working_state.get("licensing_scope"),
        "environment": scope_check.get("environment"),
        "failures": failures,
    }
    working_state["licensing"] = licensing_state

    working_state.setdefault("governance_feedback", {})["licensing"] = {
        "result": licensing_result,
        "reason": licensing_reason,
        "autonomy_check": autonomy_check,
        "scope_check": scope_check,
        "licence_state": licence_state,
        "licence_sources": licence_sources,
        "failures": failures,
    }

    if licensing_result != "ALLOW":
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "licensing",
            "result": licensing_result,
            "reason": licensing_reason,
        }
    )

    working_state["state_hash"] = rebuild_state_hash(working_state)
    working_state["licensing_evidence"] = build_stage_evidence(
        working_state,
        stage="licensing",
        state_hash_entering_stage=state_hash_entering_stage,
    )
    if licensing_result == "ALLOW":
        working_state = issue_token(
            working_state,
            name="licensing",
            issued_at_stage="licensing",
            payload=stage_token_payload(working_state, "licensing"),
        )

    return append_stage_finalisation(working_state, stage="licensing")
