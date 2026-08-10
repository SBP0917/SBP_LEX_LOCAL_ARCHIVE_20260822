from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from sbp_lex.recovery.inventory import DEFAULT_ARTIFACT_SPECS
from sbp_lex.security.crypto_agility import (
    PERFORMANCE_VERSION,
    build_pqc_performance_baseline,
)
from sbp_lex.security.pqc_migration_assurance import (
    build_assurance_bundle,
    build_provider_provenance,
    build_public_interoperability_vector,
    build_threat_recovery_matrix,
    validate_provider_provenance,
    validate_public_interoperability_vector,
    validate_threat_recovery_matrix,
)
from sbp_lex.security.pqc_migration_activation import build_activation_preflight


ROOT = Path(__file__).resolve().parents[1]


def test_provider_provenance_binds_exact_lock_and_installed_provider_files() -> None:
    provenance = build_provider_provenance(ROOT)
    valid, failures = validate_provider_provenance(provenance, ROOT)
    assert valid is True, failures
    assert provenance["provider_exactly_pinned"] is True
    assert provenance["installed_versions"]["cryptography"] == "49.0.0"
    assert provenance["all_selected_provider_files_present"] is True
    assert provenance["private_key_material_included"] is False


def test_provider_provenance_rejects_lock_or_provider_file_drift() -> None:
    provenance = build_provider_provenance(ROOT)
    tampered = deepcopy(provenance)
    tampered["exact_lock_sha256"] = "0" * 64
    valid, failures = validate_provider_provenance(tampered, ROOT)
    assert valid is False
    assert "provider_provenance_digest_invalid" in failures
    assert "provider_provenance_exact_lock_sha256_mismatch" in failures


def test_public_interoperability_vector_has_reproducible_inputs_and_is_directly_verifiable() -> None:
    first = build_public_interoperability_vector()
    second = build_public_interoperability_vector()
    for field in (
        "payload", "payload_digest", "crypto_profile",
        "provider_message_base64", "public_key_base64",
    ):
        assert first[field] == second[field]
    valid, failures = validate_public_interoperability_vector(first)
    assert valid is True, failures
    assert first["test_only"] is True
    assert first["deterministic_inputs"] is True
    assert first["signature_randomization_expected"] is True
    assert first["runtime_authority"] is False
    assert first["private_key_or_seed_included"] is False


def test_public_interoperability_vector_tamper_is_rejected() -> None:
    vector = build_public_interoperability_vector()
    tampered = deepcopy(vector)
    signature = tampered["signature_base64"]
    tampered["signature_base64"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    valid, failures = validate_public_interoperability_vector(tampered)
    assert valid is False
    assert "interoperability_vector_digest_invalid" in failures
    assert "interoperability_provider_wrapper_rejected" in failures


def test_threat_recovery_matrix_is_complete_test_bound_and_non_authoritative() -> None:
    matrix = build_threat_recovery_matrix()
    valid, failures = validate_threat_recovery_matrix(matrix, ROOT)
    assert valid is True, failures
    assert matrix["case_count"] >= 16
    assert all(
        item["automatic_authority_on_failure"] is False
        for item in matrix["cases"]
    )
    assert matrix["external_residuals_self_certified"] is False


def test_assurance_bundle_requires_all_component_validations() -> None:
    bundle = build_assurance_bundle(ROOT)
    assert bundle["pass_status"] == "PASS"
    assert all(bundle["validations"].values())
    assert bundle["production_or_certification_claim"] is False


def test_recovery_inventory_preserves_the_exact_pass9_dependency_lock() -> None:
    records = {item.logical_name: item for item in DEFAULT_ARTIFACT_SPECS}
    lock = records["configuration.requirements_lock"]
    assert lock.source_path == "requirements-pass9.lock.txt"
    assert lock.required_status == "REQUIRED"
    assert lock.validation_method == "sha256"


def test_pass9_performance_baseline_uses_real_provider_and_bounded_samples() -> None:
    baseline = build_pqc_performance_baseline(samples=5, warmup=1)
    assert baseline["performance_version"] == PERFORMANCE_VERSION
    assert baseline["provider_id"] == "cryptography.mldsa"
    assert baseline["provider_version"] == "49.0.0"
    assert baseline["sample_count"] == 5
    assert baseline["engineering_baseline_only"] is True
    assert baseline["cryptographic_certification"] is False


def test_isolated_activation_preflight_is_profiled_safe_and_non_authoritative() -> None:
    preflight = build_activation_preflight(
        trust_classification="ISOLATED_TEST_TRUST",
    )
    assert preflight["pass_status"] == "PASS"
    assert all(preflight["assertions"].values())
    assert preflight["private_key_material_recorded"] is False
    assert preflight["runtime_authority_granted"] is False
    assert preflight["owner_authorisation_claim"] is False


def test_activation_preflight_fails_closed_without_migration_approval(
    monkeypatch,
) -> None:
    monkeypatch.delenv("SBP_LEX_PQC_MIGRATION_APPROVAL_REFERENCE")
    preflight = build_activation_preflight(
        trust_classification="ISOLATED_TEST_TRUST",
    )
    assert preflight["pass_status"] == "FAIL"
    assert preflight["assertions"]["migration_profile_ready"] is False
    assert preflight["assertions"]["sign_verify_round_trip"] is False
