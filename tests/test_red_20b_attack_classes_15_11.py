from __future__ import annotations

from copy import deepcopy

import pytest

from external_substrates.demo.build_demo_pre_context_package import build_demo_chain
from external_substrates.dtn.signal_builder import validate_dtn_signal_package
from external_substrates.shared.bridge_validator import validate_pre_context_package_for_bridge
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.pre_context_package import validate_pre_context_package
from external_substrates.shared.signing import sign_payload as sign_external_payload
from external_substrates.skg.signal_builder import validate_skg_signal_package
from main import sample_request
from sbp_lex.api.schema_validation import loads_strict_json, validate_runtime_request_schema
from sbp_lex.aurion15.runtime.runner import run_aurion_runtime
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.governance.engine import run_governance
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.security.authority_boundary import validate_canonical_upstream
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.security.token_stack import verify_required_tokens, verify_token


CANONICAL_STAGE_TOKENS = (
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "domain",
    "aurion",
)


def _valid_state(request: dict | None = None) -> dict:
    state = run_pipeline(request or sample_request())
    valid, failures = validate_canonical_upstream(
        state, required_tokens=CANONICAL_STAGE_TOKENS
    )
    assert valid, failures
    return state


def _resign_internal_token(token: dict) -> dict:
    payload = {
        key: value
        for key, value in token.items()
        if key not in {"digest", "signature", "verified"}
    }
    token["digest"] = generate_digest(payload)
    token["signature"] = sign_payload(payload)
    token["verified"] = True
    return token


def _resign_external_package(package: dict) -> dict:
    digest_body = {
        key: deepcopy(value)
        for key, value in package.items()
        if key not in {"digest", "signature"}
    }
    package["digest"] = digest_mapping(digest_body)
    signature_body = {
        key: deepcopy(value) for key, value in package.items() if key != "signature"
    }
    package["signature"] = sign_external_payload(signature_body)
    return package


def test_01_external_package_cannot_induce_governance_authority() -> None:
    _, _, package = build_demo_chain()
    result = run_governance(package)
    assert result["governance_result"] == "DENY"
    assert result["governance_reason"] == "confused_deputy_rejected"
    assert "governance" not in result.get("tokens", {})


def test_02_bridge_package_cannot_invoke_downstream_authority_without_canonical_state() -> None:
    _, _, package = build_demo_chain()
    governance = run_governance(deepcopy(package))
    domain = run_domain_wrap(deepcopy(package))
    aurion = run_aurion_runtime(deepcopy(package))
    execution = run_execution_gate(deepcopy(package))
    assert governance["governance_result"] == "DENY"
    assert domain["domain_result"] == "escalate"
    assert aurion["aurion15_result"] == "fail"
    assert execution["execution_result"] == "HALT"
    assert execution["execution_verified"] is False


def test_03_validated_request_cannot_be_swapped_before_use() -> None:
    state = _valid_state()
    state["action"] = "substituted_after_validation"
    valid, failures = validate_canonical_upstream(
        state, required_tokens=CANONICAL_STAGE_TOKENS
    )
    assert valid is False
    assert "toctou_state_mismatch:action" in failures


def test_04_pt_envelope_cannot_be_swapped_after_validation() -> None:
    state = _valid_state()
    state["pt_evidence_envelope"]["skg_digest"] = "substituted-skg-digest"
    state["pt_evidence_envelope_digest"] = generate_digest(state["pt_evidence_envelope"])
    valid, failures = validate_canonical_upstream(
        state, required_tokens=("procedural_truth",)
    )
    assert valid is False
    assert "validation_state_mismatch:procedural_truth" in failures


@pytest.mark.parametrize(
    ("field", "token_name", "replacement"),
    (
        ("classification_result", "classification", "DENY"),
        ("licensing_result", "licensing", "DENY"),
        ("governance_result", "governance", "DENY"),
    ),
)
def test_05_validated_stage_results_cannot_be_substituted(
    field: str, token_name: str, replacement: str
) -> None:
    state = _valid_state()
    state[field] = replacement
    valid, failures = validate_canonical_upstream(
        state, required_tokens=(token_name,)
    )
    assert valid is False
    assert f"validation_state_mismatch:{token_name}" in failures


def test_06_token_bundle_cannot_be_swapped_between_validation_and_gate() -> None:
    first = _valid_state()
    second_request = sample_request()
    second_request["action"] = "different_governed_action"
    second = _valid_state(second_request)
    first["tokens"]["token_bundle"] = deepcopy(second["tokens"]["token_bundle"])
    valid, failures = verify_required_tokens(first, required=["token_bundle"])
    assert valid is False
    assert failures == ["invalid_token:token_bundle"]
    gated = run_execution_gate(first)
    assert gated["execution_result"] == "HALT"


def test_07_weaker_external_package_versions_are_rejected() -> None:
    skg, dtn, pre_context = build_demo_chain()
    skg["package_version"] = "0.9"
    dtn["package_version"] = "0.9"
    pre_context["package_version"] = "0.9"
    _resign_external_package(skg)
    _resign_external_package(dtn)
    _resign_external_package(pre_context)
    assert validate_skg_signal_package(skg) is False
    assert validate_dtn_signal_package(dtn) is False
    assert validate_pre_context_package(pre_context) is False
    valid, failures = validate_pre_context_package_for_bridge(pre_context)
    assert valid is False
    assert "protocol_downgrade_rejected" in failures


def test_08_weaker_signing_marker_and_algorithm_are_rejected() -> None:
    state = _valid_state()
    token = deepcopy(state["tokens"]["governance"])
    token["signature"]["algorithm"] = "HMAC-SHA1"
    assert verify_token(token, expected_request_fingerprint=state["request_fingerprint"]) is False
    token = deepcopy(state["tokens"]["governance"])
    token["signature"]["signed_at"] = "LEGACY_UNSIGNED_TIME"
    assert verify_token(token, expected_request_fingerprint=state["request_fingerprint"]) is False


def test_09_threshold_and_freshness_downgrades_are_rejected() -> None:
    state = _valid_state()
    state["pt_evidence_envelope"]["threshold_tier"] = "LOW"
    state["pt_evidence_envelope"]["threshold_requirement"] = 2
    state["pt_evidence_envelope_digest"] = generate_digest(state["pt_evidence_envelope"])
    valid, failures = validate_canonical_upstream(
        state, required_tokens=("procedural_truth",)
    )
    assert valid is False
    assert "validation_state_mismatch:procedural_truth" in failures

    _, _, package = build_demo_chain()
    package["freshness_valid"] = False
    _resign_external_package(package)
    bridge_valid, bridge_failures = validate_pre_context_package_for_bridge(package)
    assert bridge_valid is False
    assert "stale_package" in bridge_failures


def test_10_signature_wrapping_with_unsigned_active_field_is_rejected() -> None:
    state = _valid_state()
    token = deepcopy(state["tokens"]["governance"])
    token["active_payload"] = {"governance_result": "ALLOW"}
    assert verify_token(token, expected_request_fingerprint=state["request_fingerprint"]) is False


def test_11_signed_digest_substitution_is_rejected() -> None:
    state = _valid_state()
    token = deepcopy(state["tokens"]["governance"])
    token["digest"] = state["tokens"]["licensing"]["digest"]
    assert verify_token(token, expected_request_fingerprint=state["request_fingerprint"]) is False


def test_12_validly_resigned_authority_context_substitution_is_rejected() -> None:
    state = _valid_state()
    token = deepcopy(state["tokens"]["authority"])
    token["payload"]["evidence_anchor_digest"] = "other-authority-context"
    state["tokens"]["authority"] = _resign_internal_token(token)
    assert verify_token(
        state["tokens"]["authority"],
        expected_request_fingerprint=state["request_fingerprint"],
    ) is True
    valid, failures = validate_canonical_upstream(
        state, required_tokens=("authority",)
    )
    assert valid is False
    assert "validation_state_mismatch:authority" in failures


def test_13_duplicate_json_fails_and_mapping_order_normalizes() -> None:
    with pytest.raises(ValueError, match="duplicate_json_key:a"):
        loads_strict_json('{"a":1,"a":2}')
    assert generate_digest({"a": 1, "b": 2}) == generate_digest({"b": 2, "a": 1})


def test_14_unicode_variants_normalize_and_key_collisions_fail() -> None:
    composed = "caf\u00e9"
    decomposed = "cafe\u0301"
    assert generate_digest({"value": composed}) == generate_digest({"value": decomposed})
    with pytest.raises(ValueError, match="canonical_key_collision_after_unicode_normalization"):
        generate_digest({composed: 1, decomposed: 2})


def test_15_numeric_string_coercion_cannot_change_digest_meaning() -> None:
    assert generate_digest({"value": 2}) != generate_digest({"value": "2"})
    request = sample_request()
    request["safety_profile"]["human_safety"] = "2"
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert "safety_profile_human_safety_must_be_int" in failures
