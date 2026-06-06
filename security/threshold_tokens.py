from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import THRESHOLD_COMPONENT_TOKEN_NAMES
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.token_stack import issue_token, verify_token


def _threshold_values_from_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    safety = state.get("safety_profile", {}) or {}
    context = state.get("context", {}) or {}
    classification = state.get("classification", {}) or {}
    return {
        "human_safety_threshold": safety.get("human_safety"),
        "irreversibility_threshold": safety.get("irreversibility"),
        "cascading_impact_threshold": safety.get("cascading_impact"),
        "financial_operational_threshold": safety.get("financial_operational"),
        "consequentiality_tier": safety.get("computed_tier"),
        "corroboration_threshold": state.get("corroboration_required"),
        "autonomy_boundary_threshold": classification.get("autonomy_ceiling"),
        "financial_tier_threshold": safety.get("financial_tier"),
        "escalation_threshold": context.get("escalation_threshold", "NONE"),
        "classification_boundary": classification.get("ap_acf_class"),
        "licensing_scope": state.get("licensing_scope", context.get("licensing_scope")),
        "jurisdiction_threshold": state.get("jurisdiction"),
        "environment_modifier": classification.get("environment_modifiers", context.get("environment_modifiers")),
        "public_exposure": classification.get("public_exposure", context.get("public_exposure")),
        "operational_scope": classification.get("operational_scope", context.get("operational_scope")),
    }


def issue_threshold_component_tokens(state: Mapping[str, Any], *, issued_at_stage: str) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    values = _threshold_values_from_state(working_state)
    for name in THRESHOLD_COMPONENT_TOKEN_NAMES:
        value = values.get(name)
        working_state = issue_token(
            working_state,
            name=name,
            issued_at_stage=issued_at_stage,
            payload={"component": name, "value": value, "component_hash": generate_digest({"component": name, "value": value})},
        )
    return working_state


def issue_threshold_bundle_token(state: Mapping[str, Any], *, issued_at_stage: str = "threshold_bundle") -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    component_hashes = {name: working_state.get("tokens", {}).get(name, {}).get("digest") for name in THRESHOLD_COMPONENT_TOKEN_NAMES}
    component_hashes = {name: digest for name, digest in component_hashes.items() if digest is not None}
    return issue_token(
        working_state,
        name="threshold_bundle",
        issued_at_stage=issued_at_stage,
        payload={
            "component_hashes": component_hashes,
            "bundle_root_hash": generate_digest(component_hashes),
            "component_count": len(component_hashes),
            "required_component_count": len(THRESHOLD_COMPONENT_TOKEN_NAMES),
        },
    )


def verify_threshold_bundle(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    tokens = state.get("tokens", {})
    expected_fingerprint = state.get("request_fingerprint")
    for name in THRESHOLD_COMPONENT_TOKEN_NAMES:
        token = tokens.get(name)
        if token is None:
            failures.append(f"missing_threshold_component:{name}")
        elif not verify_token(token, expected_request_fingerprint=expected_fingerprint):
            failures.append(f"invalid_threshold_component:{name}")
    bundle = tokens.get("threshold_bundle")
    if bundle is None:
        failures.append("missing_threshold_bundle")
    elif not verify_token(bundle, expected_request_fingerprint=expected_fingerprint):
        failures.append("invalid_threshold_bundle")
    return len(failures) == 0, failures
