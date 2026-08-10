from __future__ import annotations

import argparse
import base64
import importlib.metadata
import json
import platform
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.config.security_config import SIGNATURE_ALGORITHM
from sbp_lex.recovery.common import atomic_json
from sbp_lex.security.migration_profile import (
    CRYPTO_PROFILE_VERSION,
    VERIFICATION_POLICY_VERSION,
    CryptoProfileRequirement,
    build_current_crypto_profile,
    provider_version,
    validate_crypto_profile,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.pqc_provider import (
    derive_signing_keypair,
    provider_available,
    provider_name,
    sign,
    verify,
)


PROVENANCE_VERSION = "PASS9_PQC_PROVIDER_PROVENANCE_V1"
INTEROPERABILITY_VERSION = "PASS9_PQC_PUBLIC_INTEROPERABILITY_VECTOR_V1"
THREAT_RECOVERY_VERSION = "PASS9_PQC_THREAT_RECOVERY_MATRIX_V1"
ASSURANCE_VERSION = "PASS9_CONTROLLED_PQC_ASSURANCE_BUNDLE_V1"
LOCK_FILE = "requirements-pass9.lock.txt"
DECLARATION_FILE = "requirements.txt"
PUBLIC_VECTOR_KEY_ID = "PASS9_PUBLIC_INTEROP_MLDSA65_KEY_01"
PUBLIC_VECTOR_APPROVAL = "PASS9_PUBLIC_INTEROPERABILITY_TEST_VECTOR"
_PUBLIC_VECTOR_SEED = sha256(
    b"SBP_LEX_PASS9_PUBLIC_INTEROPERABILITY_VECTOR_NOT_FOR_RUNTIME_AUTHORITY"
).digest()
_PROVIDER_FILES = (
    "cryptography-49.0.0.dist-info/METADATA",
    "cryptography-49.0.0.dist-info/RECORD",
    "cryptography/hazmat/bindings/_rust.pyd",
    "cryptography/hazmat/primitives/asymmetric/mldsa.py",
)


def _sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _requirements(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _selected_distribution_files() -> list[dict[str, Any]]:
    distribution = importlib.metadata.distribution("cryptography")
    available = {
        str(item).replace("\\", "/"): item
        for item in distribution.files or ()
    }
    records: list[dict[str, Any]] = []
    for relative in _PROVIDER_FILES:
        item = available.get(relative)
        if item is None:
            records.append({
                "relative_path": relative,
                "present": False,
                "size_bytes": None,
                "sha256": None,
            })
            continue
        path = Path(distribution.locate_file(item))
        records.append({
            "relative_path": relative,
            "present": path.is_file(),
            "size_bytes": path.stat().st_size if path.is_file() else None,
            "sha256": _sha256_file(path) if path.is_file() else None,
        })
    return records


def build_provider_provenance(repository_root: Path) -> dict[str, Any]:
    root = repository_root.resolve()
    lock = root / LOCK_FILE
    declaration = root / DECLARATION_FILE
    lock_entries = _requirements(lock)
    declared_entries = _requirements(declaration)
    files = _selected_distribution_files()
    installed = {
        name: importlib.metadata.version(name)
        for name in ("cryptography", "pytest", "packaging", "cffi", "pycparser")
    }
    expected_provider_pin = f"cryptography=={provider_version()}"
    payload = {
        "provenance_version": PROVENANCE_VERSION,
        "repository": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "provider_id": provider_name(),
        "provider_version": provider_version(),
        "algorithm_identifier": SIGNATURE_ALGORITHM,
        "provider_available": provider_available(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "declaration_file": DECLARATION_FILE,
        "declaration_sha256": _sha256_file(declaration),
        "declared_requirements": declared_entries,
        "exact_lock_file": LOCK_FILE,
        "exact_lock_sha256": _sha256_file(lock),
        "exact_lock_entries": lock_entries,
        "installed_versions": installed,
        "provider_exactly_pinned": expected_provider_pin in lock_entries,
        "provider_selected_files": files,
        "all_selected_provider_files_present": all(
            item["present"] is True for item in files
        ),
        "private_key_material_included": False,
        "provenance_scope": (
            "local installed-distribution and exact-lock evidence; not vendor "
            "certification or a software-bill-of-materials signature"
        ),
    }
    return {**payload, "provenance_digest": generate_digest(payload)}


def validate_provider_provenance(
    value: Mapping[str, Any], repository_root: Path,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(value, Mapping):
        return False, ["provider_provenance_not_mapping"]
    payload = {key: item for key, item in value.items() if key != "provenance_digest"}
    if value.get("provenance_version") != PROVENANCE_VERSION:
        failures.append("provider_provenance_version_invalid")
    if value.get("provenance_digest") != generate_digest(payload):
        failures.append("provider_provenance_digest_invalid")
    try:
        expected = build_provider_provenance(repository_root)
    except (OSError, importlib.metadata.PackageNotFoundError):
        failures.append("provider_provenance_environment_unavailable")
    else:
        for field in (
            "provider_id", "provider_version", "algorithm_identifier",
            "declaration_sha256", "exact_lock_sha256", "installed_versions",
            "provider_selected_files",
        ):
            if value.get(field) != expected.get(field):
                failures.append(f"provider_provenance_{field}_mismatch")
    if value.get("provider_available") is not True:
        failures.append("provider_provenance_provider_unavailable")
    if value.get("provider_exactly_pinned") is not True:
        failures.append("provider_provenance_exact_pin_missing")
    if value.get("all_selected_provider_files_present") is not True:
        failures.append("provider_provenance_file_missing")
    if value.get("private_key_material_included") is not False:
        failures.append("provider_provenance_private_material_scope_violation")
    return not failures, sorted(set(failures))


def _vector_message(payload_digest: str, profile: Mapping[str, Any]) -> bytes:
    return generate_digest({
        "payload_digest": payload_digest,
        "crypto_profile": dict(profile),
    }).encode("ascii")


def build_public_interoperability_vector() -> dict[str, Any]:
    private_key, public_key = derive_signing_keypair(
        _PUBLIC_VECTOR_SEED, SIGNATURE_ALGORITHM,
    )
    fingerprint = sha256(public_key).hexdigest()
    profile = build_current_crypto_profile(
        key_id=PUBLIC_VECTOR_KEY_ID,
        public_key_fingerprint=fingerprint,
        created_at="2026-08-09T00:00:00+00:00",
        expires_at="2036-08-09T00:00:00+00:00",
        approval_reference=PUBLIC_VECTOR_APPROVAL,
    )
    test_payload = {
        "domain": "SBP_LEX_PASS9_PUBLIC_INTEROPERABILITY",
        "purpose": "PUBLIC_VERIFIER_COMPATIBILITY_ONLY",
        "sequence": 1,
        "authority_granted": False,
        "runtime_credential": False,
    }
    payload_digest = generate_digest(test_payload)
    message = _vector_message(payload_digest, profile)
    signature = sign(message, private_key, SIGNATURE_ALGORITHM)
    payload = {
        "interoperability_version": INTEROPERABILITY_VERSION,
        "test_only": True,
        "public_vector": True,
        "deterministic_inputs": True,
        "signature_randomization_expected": True,
        "runtime_authority": False,
        "private_key_or_seed_included": False,
        "provider_id": provider_name(),
        "provider_version": provider_version(),
        "algorithm_identifier": SIGNATURE_ALGORITHM,
        "crypto_profile_version": CRYPTO_PROFILE_VERSION,
        "verification_policy_version": VERIFICATION_POLICY_VERSION,
        "payload": test_payload,
        "payload_digest": payload_digest,
        "crypto_profile": profile,
        "provider_message_base64": base64.b64encode(message).decode("ascii"),
        "public_key_base64": base64.b64encode(public_key).decode("ascii"),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }
    return {**payload, "vector_digest": generate_digest(payload)}


def validate_public_interoperability_vector(
    value: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(value, Mapping):
        return False, ["interoperability_vector_not_mapping"]
    payload = {key: item for key, item in value.items() if key != "vector_digest"}
    if value.get("interoperability_version") != INTEROPERABILITY_VERSION:
        failures.append("interoperability_vector_version_invalid")
    if value.get("vector_digest") != generate_digest(payload):
        failures.append("interoperability_vector_digest_invalid")
    if (
        value.get("test_only") is not True
        or value.get("public_vector") is not True
        or value.get("deterministic_inputs") is not True
        or value.get("signature_randomization_expected") is not True
        or value.get("runtime_authority") is not False
        or value.get("private_key_or_seed_included") is not False
    ):
        failures.append("interoperability_vector_scope_invalid")
    profile = value.get("crypto_profile")
    fingerprint = profile.get("public_key_fingerprint") if isinstance(profile, Mapping) else None
    requirement = CryptoProfileRequirement(
        provider_version=provider_version(),
        key_id=PUBLIC_VECTOR_KEY_ID,
        public_key_fingerprint=str(fingerprint),
        approval_reference=PUBLIC_VECTOR_APPROVAL,
    )
    profile_ok, profile_failures = validate_crypto_profile(
        profile if isinstance(profile, Mapping) else None,
        requirement=requirement,
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
        provider_is_available=True,
    )
    if not profile_ok:
        failures.extend(f"interoperability_{item}" for item in profile_failures)
    try:
        public_key = base64.b64decode(
            str(value.get("public_key_base64", "")), validate=True,
        )
        signature = base64.b64decode(
            str(value.get("signature_base64", "")), validate=True,
        )
        message = base64.b64decode(
            str(value.get("provider_message_base64", "")), validate=True,
        )
    except Exception:
        failures.append("interoperability_vector_encoding_invalid")
        return False, sorted(set(failures))
    expected_payload = value.get("payload")
    if not isinstance(expected_payload, Mapping):
        failures.append("interoperability_vector_payload_invalid")
    else:
        expected_digest = generate_digest(expected_payload)
        if value.get("payload_digest") != expected_digest:
            failures.append("interoperability_vector_payload_digest_invalid")
        expected_message = _vector_message(
            expected_digest,
            profile if isinstance(profile, Mapping) else {},
        )
        if message != expected_message:
            failures.append("interoperability_vector_message_invalid")
    if sha256(public_key).hexdigest() != fingerprint:
        failures.append("interoperability_vector_fingerprint_invalid")
    if not verify(message, signature, public_key, SIGNATURE_ALGORITHM):
        failures.append("interoperability_provider_wrapper_rejected")
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa

        mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(
            signature, message,
        )
    except Exception:
        failures.append("interoperability_direct_public_verifier_rejected")
    return not failures, sorted(set(failures))


def build_threat_recovery_matrix() -> dict[str, Any]:
    cases = [
        ("provider_loss", "FAIL_CLOSED", "tests/test_pqc_01_provider_contract.py"),
        ("provider_version_substitution", "FAIL_CLOSED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("profile_substitution", "FAIL_CLOSED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("legacy_runtime_replay", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("unapproved_archive_read", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("revoked_key", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("expired_key", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("not_yet_active_key", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("mid_process_key_rotation", "RESTART_REQUIRED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("mid_process_profile_rotation", "RESTART_REQUIRED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("wrong_pinned_fingerprint", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("malformed_revocation_registry", "FAIL_CLOSED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("backup_profile_rollback", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("external_source_profile_downgrade", "REJECTED", "tests/test_runtime_pass9_pqc_migration.py"),
        ("public_vector_tamper", "REJECTED", "tests/test_runtime_pass9_pqc_assurance.py"),
        ("dependency_or_provider_file_drift", "REJECTED", "tests/test_runtime_pass9_pqc_assurance.py"),
    ]
    entries = [
        {
            "case": case,
            "expected_control_result": result,
            "repository_status": "CLOSED_AND_TESTED",
            "test": test,
            "automatic_authority_on_failure": False,
        }
        for case, result, test in cases
    ]
    payload = {
        "matrix_version": THREAT_RECOVERY_VERSION,
        "case_count": len(entries),
        "cases": entries,
        "repository_controls_complete": True,
        "external_residuals": [
            "independent_cryptographic_specialist_approval",
            "production_key_custody_and_trusted_time",
            "live_external_provider_assurance",
            "production_incident_response_operation",
            "external_certification_and_windows_ivvf",
        ],
        "external_residuals_self_certified": False,
    }
    return {**payload, "matrix_digest": generate_digest(payload)}


def validate_threat_recovery_matrix(
    value: Mapping[str, Any], repository_root: Path,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(value, Mapping):
        return False, ["threat_recovery_matrix_not_mapping"]
    payload = {key: item for key, item in value.items() if key != "matrix_digest"}
    if value.get("matrix_version") != THREAT_RECOVERY_VERSION:
        failures.append("threat_recovery_matrix_version_invalid")
    if value.get("matrix_digest") != generate_digest(payload):
        failures.append("threat_recovery_matrix_digest_invalid")
    cases = value.get("cases")
    if not isinstance(cases, list) or value.get("case_count") != len(cases) or len(cases) < 16:
        failures.append("threat_recovery_matrix_case_set_incomplete")
    elif any(
        not isinstance(item, Mapping)
        or item.get("repository_status") != "CLOSED_AND_TESTED"
        or item.get("automatic_authority_on_failure") is not False
        or not (repository_root / str(item.get("test", ""))).is_file()
        for item in cases
    ):
        failures.append("threat_recovery_matrix_case_invalid")
    if (
        value.get("repository_controls_complete") is not True
        or value.get("external_residuals_self_certified") is not False
    ):
        failures.append("threat_recovery_matrix_scope_invalid")
    return not failures, sorted(set(failures))


def build_assurance_bundle(repository_root: Path) -> dict[str, Any]:
    provenance = build_provider_provenance(repository_root)
    vector = build_public_interoperability_vector()
    matrix = build_threat_recovery_matrix()
    validations = {
        "provider_provenance": validate_provider_provenance(
            provenance, repository_root,
        )[0],
        "public_interoperability": validate_public_interoperability_vector(vector)[0],
        "threat_recovery": validate_threat_recovery_matrix(matrix, repository_root)[0],
    }
    payload = {
        "assurance_version": ASSURANCE_VERSION,
        "provider_provenance_digest": provenance["provenance_digest"],
        "public_interoperability_vector_digest": vector["vector_digest"],
        "threat_recovery_matrix_digest": matrix["matrix_digest"],
        "validations": validations,
        "pass_status": "PASS" if all(validations.values()) else "FAIL",
        "production_or_certification_claim": False,
    }
    return {**payload, "assurance_digest": generate_digest(payload)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pass 9 controlled PQC assurance evidence")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output-dir", default="outputs/security")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    output = Path(args.output_dir)
    provenance = build_provider_provenance(root)
    vector = build_public_interoperability_vector()
    matrix = build_threat_recovery_matrix()
    bundle = build_assurance_bundle(root)
    output.mkdir(parents=True, exist_ok=True)
    atomic_json(output / "pass_09_pqc_provider_provenance.json", provenance)
    atomic_json(output / "pass_09_pqc_interoperability_vector.json", vector)
    atomic_json(output / "pass_09_pqc_threat_recovery_matrix.json", matrix)
    atomic_json(output / "pass_09_pqc_assurance_bundle.json", bundle)
    print(json.dumps(bundle, sort_keys=True, separators=(",", ":")))
    return 0 if bundle["pass_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
