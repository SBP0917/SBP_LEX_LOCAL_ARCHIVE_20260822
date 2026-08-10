from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from external_substrates.demo.pass8_resilience_scenarios import (
    build_pass8_scenarios,
    build_scenario_fixture_package,
    evaluate_scenario,
    validate_scenario,
)
from sbp_lex.security.crypto_agility import (
    CRYPTO_PROFILE_FIELDS,
    CryptoProfileRequirement,
    build_crypto_boundary_inventory,
    build_current_crypto_profile,
    build_pqc_performance_baseline,
    build_profiled_object,
    validate_crypto_boundary_inventory,
    validate_crypto_profile,
    verify_profiled_object,
)
from sbp_lex.security.pqc_provider import provider_name
from sbp_lex.security.pqc import generate_digest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = "a" * 64


def _profile() -> dict[str, object]:
    return build_current_crypto_profile(
        key_id="PASS8_TEST_KEY",
        public_key_fingerprint=FINGERPRINT,
    )


def test_crypto_inventory_is_complete_versioned_and_does_not_claim_migration() -> None:
    inventory = build_crypto_boundary_inventory(REPOSITORY_ROOT)
    valid, failures = validate_crypto_boundary_inventory(inventory)
    assert valid is True, failures
    assert inventory["boundary_count"] >= 20
    assert inventory["boundary_count"] == len(inventory["boundaries"])
    assert inventory["current_provider_replaced"] is False
    assert inventory["migration_completed"] is False
    assert inventory["quantum_safe_claim"] is False
    assert inventory["missing_repository_files"] == []


def test_crypto_inventory_tamper_and_scope_claim_fail_closed() -> None:
    inventory = build_crypto_boundary_inventory(REPOSITORY_ROOT)
    tampered = deepcopy(inventory)
    tampered["migration_completed"] = True
    valid, failures = validate_crypto_boundary_inventory(tampered)
    assert valid is False
    assert "pqc_inventory_digest_invalid" in failures
    assert "pqc_inventory_scope_violation" in failures


def test_current_profile_is_explicit_and_provider_is_unchanged() -> None:
    profile = _profile()
    assert set(profile) == CRYPTO_PROFILE_FIELDS
    assert profile["provider_id"] == provider_name() == "cryptography.mldsa"
    valid, failures = validate_crypto_profile(
        profile,
        requirement=CryptoProfileRequirement(
            key_id="PASS8_TEST_KEY",
            public_key_fingerprint=FINGERPRINT,
        ),
        provider_is_available=True,
    )
    assert valid is True, failures


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("profile_version", "UNKNOWN", "cryptographic_profile_version_unknown"),
        ("provider_id", "wrong.provider", "cryptographic_provider_substitution"),
        ("provider_version", "", "cryptographic_provider_version_missing"),
        ("algorithm_family", "CLASSICAL", "cryptographic_algorithm_family_unknown"),
        ("algorithm_identifier", "RSA", "cryptographic_algorithm_substitution"),
        ("security_profile", "UNKNOWN", "cryptographic_security_profile_invalid"),
        ("signature_mode", "LEGACY", "cryptographic_signature_mode_mismatch"),
        ("verification_policy_version", "OLD", "cryptographic_policy_cross_version_replay"),
        ("key_id", "", "cryptographic_key_id_missing"),
        ("public_key_fingerprint", "bad", "cryptographic_public_key_fingerprint_malformed"),
        ("revoked", True, "cryptographic_key_revoked"),
        ("created_at", None, "cryptographic_created_at_invalid"),
        ("hybrid_mode", "implicit", "cryptographic_hybrid_mode_invalid"),
        ("legacy_status", "LEGACY", "cryptographic_legacy_downgrade_rejected"),
        ("migration_status", "MIGRATION_CANDIDATE", "cryptographic_migrated_profile_required"),
        ("deprecation_status", "DEPRECATED", "cryptographic_algorithm_deprecated"),
    ],
)
def test_profile_metadata_substitution_and_downgrade_fail_closed(
    field: str, value: object, reason: str,
) -> None:
    profile = _profile()
    profile[field] = value
    valid, failures = validate_crypto_profile(profile, provider_is_available=True)
    assert valid is False
    assert reason in failures


def test_profile_missing_provider_expiry_key_and_fingerprint_requirements_fail_closed() -> None:
    valid, failures = validate_crypto_profile(None, provider_is_available=True)
    assert valid is False
    assert failures == ["cryptographic_profile_missing"]

    profile = _profile()
    profile["expires_at"] = "2026-01-01T00:00:00+00:00"
    valid, failures = validate_crypto_profile(
        profile,
        requirement=CryptoProfileRequirement(
            key_id="OTHER_KEY",
            public_key_fingerprint="b" * 64,
            require_migrated_profile=True,
        ),
        now=datetime(2026, 8, 9, tzinfo=timezone.utc),
        provider_is_available=False,
    )
    assert valid is False
    assert {
        "cryptographic_key_id_mismatch",
            "cryptographic_public_key_fingerprint_mismatch",
            "cryptographic_key_expired",
            "cryptographic_key_lifecycle_order_invalid",
            "cryptographic_provider_unavailable",
    }.issubset(failures)


def test_hybrid_profile_requires_explicit_approval_and_valid_components() -> None:
    profile = _profile()
    profile["hybrid_mode"] = True
    profile["components"] = [{"algorithm_identifier": "ML-DSA", "valid": True}]
    valid, failures = validate_crypto_profile(profile, provider_is_available=True)
    assert valid is False
    assert "cryptographic_hybrid_mode_not_approved" in failures
    assert "cryptographic_hybrid_component_invalid" in failures

    profile["components"] = [
        {"algorithm_identifier": "ML-DSA", "valid": True},
        {"algorithm_identifier": "APPROVED_SECOND_COMPONENT", "valid": True},
    ]
    valid, failures = validate_crypto_profile(
        profile,
        requirement=CryptoProfileRequirement(allow_hybrid=True),
        provider_is_available=True,
    )
    assert valid is True, failures


def test_profiled_object_binds_crypto_metadata_to_signature() -> None:
    value = build_profiled_object({"decision": "DENY"}, profile=_profile())
    valid, failures = verify_profiled_object(value, provider_is_available=True)
    assert valid is True, failures
    value["crypto_profile"]["provider_id"] = "substituted.provider"
    valid, failures = verify_profiled_object(value, provider_is_available=True)
    assert valid is False
    assert "cryptographic_provider_substitution" in failures
    assert "profiled_object_signature_invalid" in failures


def test_profiled_object_verification_timeout_fails_closed() -> None:
    value = build_profiled_object({"decision": "DENY"}, profile=_profile())

    def timeout(*_args):
        raise TimeoutError("synthetic timeout")

    valid, failures = verify_profiled_object(
        value,
        signature_verifier=timeout,
        provider_is_available=True,
    )
    assert valid is False
    assert "cryptographic_verification_timeout" in failures
    assert "profiled_object_signature_invalid" in failures


def test_pqc_performance_baseline_records_success_and_failure_paths() -> None:
    baseline = build_pqc_performance_baseline(samples=5, warmup=1)
    assert baseline["engineering_baseline_only"] is True
    assert baseline["cryptographic_certification"] is False
    assert baseline["provider_id"] == "cryptography.mldsa"
    assert baseline["algorithm_identifier"] == "ML-DSA"
    assert baseline["metrics"]["signature_size_bytes"]["minimum"] > 0
    assert baseline["metrics"]["failure_path_latency_ms"]["maximum"] >= 0
    assert baseline["errors"] == []


def test_all_four_scenarios_are_digest_bound_nonoperational_and_deterministic() -> None:
    scenarios = build_pass8_scenarios()
    assert set(scenarios) == {"scenario_a", "scenario_b", "scenario_c", "scenario_d"}
    results = {}
    for name, scenario in scenarios.items():
        valid, failures = validate_scenario(scenario)
        assert valid is True, failures
        first = evaluate_scenario(scenario)
        second = evaluate_scenario(scenario)
        assert first == second
        assert first["external_effect"] is False
        assert first["authority_manufactured"] is False
        assert first["expected_result_match"] is True
        results[name] = first
    assert results["scenario_a"]["decision"] == "ESCALATE"
    assert results["scenario_a"]["execution_result"] == "HALT"
    assert results["scenario_b"]["decision"] == "DENY"
    assert results["scenario_c"]["rejected_plan"] == "ABSTRACT_PLAN_CHEAPEST_01"
    assert results["scenario_c"]["selected_plan"] == "ABSTRACT_PLAN_SAFE_BOUNDED_02"
    assert results["scenario_c"]["effect_mode"] == "SYNTHETIC_ONLY"
    assert results["scenario_d"]["decision"] == "DENY"
    assert results["scenario_d"]["downgrade_accepted"] is False


def test_scenario_tamper_denies_without_effect_or_authority() -> None:
    scenario = build_pass8_scenarios()["scenario_a"]
    scenario["conditions"].append("TAMPERED")
    result = evaluate_scenario(scenario)
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result["external_effect"] is False
    assert result["authority_manufactured"] is False
    assert "scenario_digest_invalid" in result["failures"]


def test_resource_scenario_escalates_when_no_admissible_plan_exists() -> None:
    scenario = build_pass8_scenarios()["scenario_c"]
    scenario["plans"] = [scenario["plans"][0]]
    payload = {key: value for key, value in scenario.items() if key != "fixture_digest"}
    scenario["fixture_digest"] = generate_digest(payload)
    result = evaluate_scenario(scenario)
    assert result["decision"] == "ESCALATE"
    assert result["execution_result"] == "HALT"
    assert result["selected_plan"] is None
    assert result["expected_result_match"] is False
    assert result["external_effect"] is False


def test_scenario_fixture_package_is_complete_and_digest_bound() -> None:
    package = build_scenario_fixture_package()
    payload = {key: value for key, value in package.items() if key != "package_digest"}
    assert package["package_digest"] == generate_digest(payload)
    assert package["fixture_count"] == 4
    assert package["all_fixtures_valid"] is True
    assert package["external_services_used"] is False
    assert package["live_effects_used"] is False
