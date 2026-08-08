from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.classification.environment_modifiers import (
    normalize_environment_modifiers,
)
from sbp_lex.classification.ap_acf import (
    get_class_profile,
    normalize_ap_acf_class,
)
from sbp_lex.config.security_config import (
    CONDITIONAL_THRESHOLD_TOKENS,
    THRESHOLD_COMPONENT_TOKEN_NAMES,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.token_stack import issue_token, verify_token


PASS4_SEMANTIC_THRESHOLD_NAMES = tuple(
    dict.fromkeys(CONDITIONAL_THRESHOLD_TOKENS + THRESHOLD_COMPONENT_TOKEN_NAMES)
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _threshold_values_from_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    safety = _mapping(state.get("safety_profile"))
    context = _mapping(state.get("context"))
    declaration = _mapping(state.get("ap_acf_declaration"))
    nested_modifiers = _mapping(declaration.get("environment_modifiers"))
    modifier_source = {**context, **nested_modifiers}
    for field in (
        "environment",
        "human_proximity",
        "geographic_isolation",
        "operational_containment",
        "public_exposure",
        "operational_scope",
    ):
        if field in declaration:
            modifier_source[field] = declaration.get(field)
    environment_modifiers = normalize_environment_modifiers(modifier_source)
    ap_acf_class = normalize_ap_acf_class(
        declaration.get("ap_acf_class")
        or declaration.get("class")
        or declaration.get("risk_class")
    )
    profile = get_class_profile(ap_acf_class)
    default_autonomy_ceiling = (
        profile.get("default_autonomy_ceiling")
        if isinstance(profile, Mapping)
        else None
    )
    autonomy_ceiling = declaration.get(
        "autonomy_ceiling", default_autonomy_ceiling
    )
    return {
        "consequentiality_threshold": safety.get("computed_tier"),
        "financial_threshold": safety.get("financial_tier"),
        "human_safety_threshold": safety.get("human_safety"),
        "irreversibility_threshold": safety.get("irreversibility"),
        "cascading_impact_threshold": safety.get("cascading_impact"),
        "financial_operational_threshold": safety.get("financial_operational"),
        "consequentiality_tier": safety.get("computed_tier"),
        "corroboration_threshold": state.get("corroboration_required"),
        "autonomy_boundary_threshold": autonomy_ceiling,
        "financial_tier_threshold": safety.get("financial_tier"),
        "escalation_threshold": context.get("escalation_threshold", "NONE"),
        "classification_boundary": ap_acf_class,
        "licensing_scope": environment_modifiers.get("operational_scope"),
        "jurisdiction_threshold": state.get("jurisdiction"),
        "environment_modifier": environment_modifiers,
        "public_exposure": environment_modifiers.get("public_exposure"),
        "operational_scope": environment_modifiers.get("operational_scope"),
    }


def required_threshold_token_names() -> list[str]:
    return list(dict.fromkeys(CONDITIONAL_THRESHOLD_TOKENS + THRESHOLD_COMPONENT_TOKEN_NAMES))


def issue_threshold_component_tokens(state: Mapping[str, Any], *, issued_at_stage: str) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    values = _threshold_values_from_state(working_state)
    for name in required_threshold_token_names():
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
    required_names = required_threshold_token_names()
    component_hashes = {name: working_state.get("tokens", {}).get(name, {}).get("digest") for name in required_names}
    component_hashes = {name: digest for name, digest in component_hashes.items() if digest is not None}
    return issue_token(
        working_state,
        name="threshold_bundle",
        issued_at_stage=issued_at_stage,
        payload={
            "component_hashes": component_hashes,
            "bundle_root_hash": generate_digest(component_hashes),
            "component_count": len(component_hashes),
            "required_component_count": len(required_names),
        },
    )


def _verify_threshold_bundle_unchecked(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    tokens = state.get("tokens", {})
    if not isinstance(tokens, Mapping):
        return False, ["threshold_token_store_invalid"]
    expected_fingerprint = state.get("request_fingerprint")
    required_names = required_threshold_token_names()
    expected_values = _threshold_values_from_state(state)
    expected_tier = _mapping(state.get("safety_profile")).get(
        "computed_tier"
    )
    expected_corroboration = state.get("corroboration_required")
    for name in required_names:
        token = tokens.get(name)
        if token is None:
            failures.append(f"missing_threshold_component:{name}")
        elif not verify_token(
            token,
            expected_request_fingerprint=expected_fingerprint,
            expected_name=name,
            expected_stage="procedural_truth",
            expected_tier=expected_tier,
        ):
            failures.append(f"invalid_threshold_component:{name}")
        else:
            if token.get("corroboration_required") != expected_corroboration:
                failures.append(
                    f"threshold_component_corroboration_mismatch:{name}"
                )
            payload = token.get("payload", {})
            expected_value = expected_values.get(name)
            if not isinstance(payload, Mapping) or set(payload) != {
                "component",
                "value",
                "component_hash",
            }:
                failures.append(f"threshold_component_payload_invalid:{name}")
            else:
                if payload.get("component") != name:
                    failures.append(
                        f"threshold_component_name_mismatch:{name}"
                    )
                if payload.get("value") != expected_value:
                    failures.append(
                        f"threshold_component_value_mismatch:{name}"
                    )
                if payload.get("component_hash") != generate_digest(
                    {"component": name, "value": expected_value}
                ):
                    failures.append(
                        f"threshold_component_hash_mismatch:{name}"
                    )
    bundle = tokens.get("threshold_bundle")
    if bundle is None:
        failures.append("missing_threshold_bundle")
    elif not verify_token(
        bundle,
        expected_request_fingerprint=expected_fingerprint,
        expected_name="threshold_bundle",
        expected_stage="procedural_truth",
        expected_tier=expected_tier,
    ):
        failures.append("invalid_threshold_bundle")
    else:
        if bundle.get("corroboration_required") != expected_corroboration:
            failures.append("threshold_bundle_corroboration_mismatch")
        payload = bundle.get("payload", {})
        expected_hashes = {
            name: (
                tokens.get(name, {}).get("digest")
                if isinstance(tokens.get(name), Mapping)
                else None
            )
            for name in required_names
        }
        if not isinstance(payload, Mapping) or set(payload) != {
            "component_hashes",
            "bundle_root_hash",
            "component_count",
            "required_component_count",
        }:
            failures.append("threshold_bundle_payload_invalid")
        else:
            if payload.get("required_component_count") != len(required_names):
                failures.append("threshold_bundle_requirement_mismatch")
            if payload.get("component_count") != len(expected_hashes):
                failures.append("threshold_bundle_component_count_mismatch")
            if payload.get("component_hashes") != expected_hashes:
                failures.append("threshold_bundle_component_hashes_mismatch")
            if payload.get("bundle_root_hash") != generate_digest(
                expected_hashes
            ):
                failures.append("threshold_bundle_root_hash_mismatch")
    return len(failures) == 0, failures


def verify_threshold_bundle(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Validate arbitrary threshold state without propagating structure errors."""

    if not isinstance(state, Mapping):
        return False, ["threshold_bundle_structure_invalid"]
    try:
        return _verify_threshold_bundle_unchecked(state)
    except Exception:
        return False, ["threshold_bundle_structure_invalid"]
