from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.licensing.autonomy_ceiling_engine import validate_autonomy_ceiling
from sbp_lex.licensing.scope_engine import validate_deployment_scope
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry


def run_licensing(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []

    if working_state.get("classification_result") != "ALLOW":
        failures.append("classification_not_allowed")

    autonomy_check = validate_autonomy_ceiling(working_state)
    scope_check = validate_deployment_scope(working_state)

    if autonomy_check.get("result") != "ALLOW":
        failures.extend(autonomy_check.get("failures", []))

    if scope_check.get("result") != "ALLOW":
        failures.extend(scope_check.get("failures", []))

    context = working_state.get("context", {})
    licence_state = context.get("licence_state", working_state.get("payload", {}).get("licence_state", "DECLARED_VALID"))

    if licence_state not in {"DECLARED_VALID", "VALID", "GOVERNANCE_MANAGED"}:
        failures.append("licence_state_invalid")

    licensing_result = "ALLOW" if len(failures) == 0 else "DENY"
    licensing_reason = "licensing_valid" if licensing_result == "ALLOW" else ",".join(failures)

    working_state["licensing_result"] = licensing_result
    working_state["licensing_reason"] = licensing_reason
    working_state["licensing_scope"] = scope_check.get("operational_scope")

    working_state.setdefault("governance_feedback", {})["licensing"] = {
        "result": licensing_result,
        "reason": licensing_reason,
        "autonomy_check": autonomy_check,
        "scope_check": scope_check,
        "licence_state": licence_state,
        "failures": failures,
    }

    if licensing_result == "ALLOW":
        working_state = issue_token(
            working_state,
            name="licensing",
            issued_at_stage="licensing",
            payload={
                "licensing_result": licensing_result,
                "licence_state": licence_state,
                "autonomy_check": autonomy_check,
                "scope_check": scope_check,
            },
        )
    else:
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "licensing",
            "result": licensing_result,
            "reason": licensing_reason,
        }
    )

    return append_hash_entry(
        working_state,
        stage="licensing",
        payload={
            "licensing_result": licensing_result,
            "licensing_reason": licensing_reason,
            "autonomy_check": autonomy_check,
            "scope_check": scope_check,
        },
  )
