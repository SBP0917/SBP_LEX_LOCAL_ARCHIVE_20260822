from __future__ import annotations

import hashlib
import os
from base64 import b64encode
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from external_substrates.shared.migration_profile import (
    EXTERNAL_MIGRATION_STATUS,
    build_external_source_profile,
    validate_external_source_profile,
)
from external_substrates.shared.signing import (
    PLACEHOLDER_MIGRATION_STATUS,
    placeholder_crypto_profile,
)
from external_substrates.shared.source_crypto import (
    generate_source_keypair,
    sign_source_package,
    verify_source_signature,
)
from sbp_lex.config.security_config import SIGNATURE_ALGORITHM, SYSTEM_ISSUER
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.recovery.common import RecoveryError
from sbp_lex.recovery.inventory import ArtifactSpec, build_inventory
from sbp_lex.recovery.manifest import create_manifest, validate_manifest
from sbp_lex.security.crypto_agility import (
    build_crypto_boundary_inventory,
    validate_crypto_boundary_inventory,
)
from sbp_lex.security.migration_profile import (
    APPROVED_MIGRATION_STATUS,
    CRYPTO_PROFILE_VERSION,
    CryptoProfileConfigurationError,
    CryptoProfileRequirement,
    build_active_crypto_profile,
    provider_version,
    validate_crypto_profile,
)
from sbp_lex.security.pqc import (
    LEGACY_PQC_SIGNATURE_VERSION,
    PQC_SIGNATURE_VERSION,
    generate_digest,
    reset_signing_identity_for_tests,
    sign_payload,
    verify_legacy_signature_for_archive,
    verify_signature,
)
from sbp_lex.security.pqc_policy import PQC_POLICY_NAME
from sbp_lex.security.pqc_provider import (
    PQCProviderUnavailable,
    derive_signing_keypair,
    provider_name,
    sign,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _reset_process_signer() -> None:
    reset_signing_identity_for_tests()
    yield
    reset_signing_identity_for_tests()


def _request() -> dict:
    return {
        "action": "pass9_profile_traversal",
        "payload": {
            "classification": {
                "ap_acf_class": "CLASS_4B",
                "autonomy_level": 25,
                "autonomy_ceiling": 50,
                "operational_scope": "controlled_test",
                "public_exposure": "controlled",
            },
            "licence_state": "VALID",
        },
        "resolved_authority": "desktop-test-authority",
        "jurisdiction": "AU-PACIFIC",
        "context": {
            "environment": "controlled_test",
            "operational_scope": "controlled_test",
            "operational_containment": "bounded",
            "evidence": [{
                "source": "pass9-test-source",
                "content": "profile integration",
                "verified": True,
                "attested": True,
                "freshness_valid": True,
                "consistency_valid": True,
            }],
        },
        "safety_profile": {
            "human_safety": 1,
            "irreversibility": 1,
            "cascading_impact": 1,
            "financial_operational": 1,
        },
    }


def _walk_signatures(value: object) -> list[Mapping[str, object]]:
    found: list[Mapping[str, object]] = []
    if isinstance(value, Mapping):
        if value.get("signature_version") == PQC_SIGNATURE_VERSION:
            found.append(value)
        for child in value.values():
            found.extend(_walk_signatures(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_signatures(child))
    return found


def _legacy_signature(payload: Mapping[str, object]) -> dict[str, object]:
    seed = bytes.fromhex(os.environ["SBP_LEX_SIGNING_SECRET"])
    private_key, public_key = derive_signing_keypair(seed, SIGNATURE_ALGORITHM)
    digest = generate_digest(payload)
    return {
        "issuer": SYSTEM_ISSUER,
        "algorithm": SIGNATURE_ALGORITHM,
        "policy": PQC_POLICY_NAME,
        "provider": provider_name(),
        "provider_available": True,
        "signature_version": LEGACY_PQC_SIGNATURE_VERSION,
        "key_fingerprint": hashlib.sha256(public_key).hexdigest(),
        "digest": digest,
        "signature": b64encode(
            sign(digest.encode("utf-8"), private_key, SIGNATURE_ALGORITHM)
        ).decode("ascii"),
        "public_key": b64encode(public_key).decode("ascii"),
    }


def test_canonical_signature_binds_the_complete_pass9_profile() -> None:
    payload = {"decision": "DENY", "reason": "pass9-test"}
    envelope = sign_payload(payload)
    assert envelope["signature_version"] == PQC_SIGNATURE_VERSION
    assert envelope["crypto_profile"]["profile_version"] == CRYPTO_PROFILE_VERSION
    assert envelope["crypto_profile"]["migration_status"] == APPROVED_MIGRATION_STATUS
    assert envelope["crypto_profile"]["provider_version"] == provider_version()
    assert verify_signature(payload, envelope) is True

    tampered = deepcopy(envelope)
    tampered["crypto_profile"]["approval_reference"] = "SUBSTITUTED_APPROVAL_REFERENCE"
    assert verify_signature(payload, tampered) is False


@pytest.mark.parametrize(
    ("environment_name", "value", "reason"),
    [
        ("SBP_LEX_PQC_MIGRATION_STATUS", "MIGRATION_CANDIDATE", "not_approved"),
        ("SBP_LEX_PQC_MIGRATION_APPROVAL_REFERENCE", "", "approval_missing"),
        ("SBP_LEX_SIGNING_KEY_EXPIRES_AT", "2026-01-01T00:00:00+00:00", "key_expired"),
    ],
)
def test_signing_requires_approved_active_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    environment_name: str,
    value: str,
    reason: str,
) -> None:
    monkeypatch.setenv(environment_name, value)
    with pytest.raises(PQCProviderUnavailable, match=reason):
        sign_payload({"case": reason})


def test_authoritative_revocation_registry_blocks_current_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = hashlib.sha256(
        derive_signing_keypair(
            bytes.fromhex(os.environ["SBP_LEX_SIGNING_SECRET"]),
            SIGNATURE_ALGORITHM,
        )[1]
    ).hexdigest()
    monkeypatch.setenv("SBP_LEX_REVOKED_SIGNING_KEY_FINGERPRINTS", fingerprint)
    with pytest.raises(PQCProviderUnavailable, match="revoked_by_registry"):
        sign_payload({"case": "revoked"})


def test_profile_change_requires_process_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sign_payload({"sequence": 1})
    monkeypatch.setenv(
        "SBP_LEX_PQC_MIGRATION_APPROVAL_REFERENCE",
        "TEST_ONLY_EPHEMERAL_PASS9_APPROVAL_ROTATED",
    )
    with pytest.raises(PQCProviderUnavailable, match="profile changed during"):
        sign_payload({"sequence": 2})


def test_pinned_fingerprint_is_required_for_signing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SBP_LEX_EXPECTED_SIGNER_FINGERPRINT", raising=False)
    with pytest.raises(PQCProviderUnavailable, match="does not match"):
        sign_payload({"case": "missing-pinned-fingerprint"})


def test_legacy_signature_is_runtime_rejected_but_explicitly_archive_verifiable() -> None:
    payload = {"archive_record": "pre-pass9"}
    legacy = _legacy_signature(payload)
    assert verify_signature(payload, legacy) is False
    assert verify_legacy_signature_for_archive(
        payload,
        legacy,
        archive_policy_reference="PASS9_ARCHIVE_READ_POLICY_01",
    ) is True
    assert verify_legacy_signature_for_archive(
        payload,
        legacy,
        archive_policy_reference="short",
    ) is False


def test_legacy_archive_verification_requires_registered_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"archive_record": "pre-pass9-unregistered"}
    legacy = _legacy_signature(payload)
    monkeypatch.delenv("SBP_LEX_APPROVED_LEGACY_ARCHIVE_POLICIES")
    assert verify_legacy_signature_for_archive(
        payload,
        legacy,
        archive_policy_reference="PASS9_ARCHIVE_READ_POLICY_01",
    ) is False


def test_external_source_profile_is_independent_bound_and_no_downgrade() -> None:
    private_key, public_key = generate_source_keypair()
    package = {
        "package_type": "SKG_EXTERNAL_SOURCE_PACKAGE",
        "schema_version": "TEST_V1",
        "package_id": "PASS9-SKG-01",
        "digest": "a" * 64,
    }
    signed = sign_source_package(
        package,
        private_key=private_key,
        source_id="PASS9_SOURCE_01",
        key_id="PASS9_SOURCE_KEY_01",
        substrate_type="SKG",
    )
    public_material = b64encode(public_key).decode("ascii")
    assert signed["signature"]["crypto_profile"]["migration_status"] == EXTERNAL_MIGRATION_STATUS
    assert verify_source_signature(
        signed,
        public_verification_material=public_material,
        expected_source_id="PASS9_SOURCE_01",
        expected_key_id="PASS9_SOURCE_KEY_01",
        expected_substrate_type="SKG",
    ) is True
    signed["signature"]["crypto_profile"]["profile_version"] = "LEGACY"
    assert verify_source_signature(
        signed,
        public_verification_material=public_material,
        expected_source_id="PASS9_SOURCE_01",
        expected_key_id="PASS9_SOURCE_KEY_01",
        expected_substrate_type="SKG",
    ) is False


def test_external_profile_enforces_expiry_and_revocation() -> None:
    public_fingerprint = "a" * 64
    profile = build_external_source_profile(
        source_id="PASS9_SOURCE_01",
        key_id="PASS9_SOURCE_KEY_01",
        public_key_fingerprint=public_fingerprint,
    )
    assert validate_external_source_profile(
        profile,
        source_id="PASS9_SOURCE_01",
        key_id="PASS9_SOURCE_KEY_01",
        public_key_fingerprint=public_fingerprint,
        now=datetime(2026, 8, 9, tzinfo=timezone.utc),
    ) is True
    profile["revoked"] = True
    assert validate_external_source_profile(
        profile,
        source_id="PASS9_SOURCE_01",
        key_id="PASS9_SOURCE_KEY_01",
        public_key_fingerprint=public_fingerprint,
    ) is False


def test_placeholder_surface_is_explicitly_excluded_from_live_migration() -> None:
    profile = placeholder_crypto_profile()
    assert profile["migration_status"] == PLACEHOLDER_MIGRATION_STATUS
    assert profile["live_provider_eligible"] is False
    assert profile["runtime_authority"] is False


def test_inventory_corrects_actual_boundary_types_and_symbols() -> None:
    inventory = build_crypto_boundary_inventory(ROOT)
    valid, failures = validate_crypto_boundary_inventory(inventory)
    assert valid is True, failures
    assert inventory["boundary_count"] == 22
    assert inventory["profile_integration_complete"] is True
    assert inventory["migration_completed"] is False
    assert inventory["production_provider_approved"] is False
    assert inventory["missing_repository_symbols"] == []
    counts = Counter(item["enforcement_status"] for item in inventory["boundaries"])
    assert counts == {
        "PASS9_PROFILE_ENFORCED": 16,
        "PQC_EXCLUDED_TEST_ONLY": 2,
        "PQC_NOT_APPLICABLE_DIGEST_ONLY": 2,
        "PASS9_INDIRECT_PROFILE_BOUND": 1,
        "DEFERRED_APP_IDENTITY_BOUNDARY": 1,
    }


def test_complete_runtime_traversal_uses_only_v3_profiled_signatures() -> None:
    state = run_pipeline(_request())
    signatures = _walk_signatures(state)
    assert len(signatures) >= 10
    assert all(
        signature["crypto_profile"]["profile_version"] == CRYPTO_PROFILE_VERSION
        and signature["crypto_profile"]["migration_status"] == APPROVED_MIGRATION_STATUS
        for signature in signatures
    )


def test_active_profile_rejects_unknown_provider_version() -> None:
    fingerprint = hashlib.sha256(
        derive_signing_keypair(
            bytes.fromhex(os.environ["SBP_LEX_SIGNING_SECRET"]),
            SIGNATURE_ALGORITHM,
        )[1]
    ).hexdigest()
    profile = build_active_crypto_profile(public_key_fingerprint=fingerprint)
    profile["provider_version"] = "0.0.0-substituted"
    valid, failures = validate_crypto_profile(
        profile,
        requirement=CryptoProfileRequirement(provider_version=provider_version()),
        provider_is_available=True,
    )
    assert valid is False
    assert "cryptographic_provider_version_substitution" in failures


def test_active_profile_configuration_rejects_bad_revocation_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = hashlib.sha256(
        derive_signing_keypair(
            bytes.fromhex(os.environ["SBP_LEX_SIGNING_SECRET"]),
            SIGNATURE_ALGORITHM,
        )[1]
    ).hexdigest()
    monkeypatch.setenv("SBP_LEX_REVOKED_SIGNING_KEY_FINGERPRINTS", "malformed")
    with pytest.raises(CryptoProfileConfigurationError, match="revocation_registry_invalid"):
        build_active_crypto_profile(public_key_fingerprint=fingerprint)


@pytest.mark.parametrize(
    ("environment_name", "reason"),
    [
        ("SBP_LEX_SIGNING_KEY_ID", "key_id_missing"),
        ("SBP_LEX_REVOKED_SIGNING_KEY_FINGERPRINTS", "revocation_registry_missing"),
    ],
)
def test_active_profile_requires_explicit_lifecycle_registries(
    monkeypatch: pytest.MonkeyPatch,
    environment_name: str,
    reason: str,
) -> None:
    fingerprint = hashlib.sha256(
        derive_signing_keypair(
            bytes.fromhex(os.environ["SBP_LEX_SIGNING_SECRET"]),
            SIGNATURE_ALGORITHM,
        )[1]
    ).hexdigest()
    monkeypatch.delenv(environment_name)
    with pytest.raises(CryptoProfileConfigurationError, match=reason):
        build_active_crypto_profile(public_key_fingerprint=fingerprint)


def test_signing_key_rotation_requires_process_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sign_payload({"rotation_sequence": 1})
    monkeypatch.setenv("SBP_LEX_SIGNING_SECRET", "1" * 64)
    with pytest.raises(PQCProviderUnavailable, match="identity changed during"):
        sign_payload({"rotation_sequence": 2})


def test_backup_manifest_profile_rollback_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"mode":"pass9"}\n', encoding="utf-8")
    inventory = build_inventory(source, (
        ArtifactSpec(
            "configuration.pass9", "configuration", "config.json",
            "configuration/config.json", "REQUIRED", "PUBLIC_EVIDENCE",
            "json", 1, None, 100, "strict_json",
            "repository_release_authority",
        ),
    ))
    manifest = create_manifest(
        inventory,
        repository_commit="a" * 40,
        measured_baseline_identifier="PASS9_RECOVERY_BASELINE_01",
        runtime_identity="b" * 64,
        generation=1,
        creation_timestamp="2026-08-09T00:00:00+00:00",
    )
    assert (
        manifest["integrity_signature"]["signature_version"]
        == PQC_SIGNATURE_VERSION
    )
    tampered = deepcopy(manifest)
    tampered["integrity_signature"]["crypto_profile"]["profile_version"] = "LEGACY"
    with pytest.raises(RecoveryError, match="backup_manifest_signature_invalid"):
        validate_manifest(tampered)
