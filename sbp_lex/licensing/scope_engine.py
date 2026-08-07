from __future__ import annotations

from typing import Any, Dict, Mapping


def validate_deployment_scope(state: Mapping[str, Any]) -> Dict[str, Any]:
    classification = state.get("classification", {})
    context = state.get("context", {})

    failures: list[str] = []

    operational_scope = classification.get("operational_scope") or context.get("operational_scope")
    requested_scope = context.get("requested_scope", operational_scope)
    permitted_scopes = context.get("permitted_scopes", [])

    if not operational_scope or operational_scope == "UNDECLARED":
        failures.append("operational_scope_missing")

    if context.get("operational_scope") not in (None, operational_scope):
        failures.append("classification_scope_context_mismatch")

    # No canonical hierarchy exists from which a broader/narrower relation can
    # be inferred.  Equality is therefore the only fail-closed continuation.
    if requested_scope != operational_scope:
        failures.append("requested_scope_broadens_classification_scope")

    if permitted_scopes and requested_scope not in permitted_scopes:
        failures.append("requested_scope_not_permitted")

    environment = classification.get("environment_modifiers", {}).get("environment")
    permitted_environments = context.get("permitted_environments", [])

    if context.get("environment") not in (None, environment):
        failures.append("classification_environment_context_mismatch")

    if permitted_environments and environment not in permitted_environments:
        failures.append("environment_not_permitted")

    return {
        "result": "ALLOW" if len(failures) == 0 else "DENY",
        "failures": failures,
        "operational_scope": operational_scope,
        "requested_scope": requested_scope,
        "environment": environment,
    }
