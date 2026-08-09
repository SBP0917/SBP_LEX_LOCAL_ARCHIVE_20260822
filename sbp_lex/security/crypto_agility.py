from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import statistics
import sys
import time
import tracemalloc
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sbp_lex.config.security_config import SIGNATURE_ALGORITHM
from sbp_lex.recovery.common import atomic_json
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.pqc_policy import PQC_POLICY_NAME
from sbp_lex.security.pqc_provider import (
    generate_signing_keypair,
    provider_available,
    provider_name,
    sign,
    verify,
)


CRYPTO_PROFILE_VERSION = "PASS8_CRYPTO_AGILITY_PROFILE_V1"
VERIFICATION_POLICY_VERSION = "PASS8_NO_SILENT_DOWNGRADE_POLICY_V1"
INVENTORY_VERSION = "PASS8_PQC_MIGRATION_READINESS_INVENTORY_V1"
PERFORMANCE_VERSION = "PASS8_PQC_PERFORMANCE_BASELINE_V1"

CRYPTO_PROFILE_FIELDS = frozenset({
    "profile_version", "provider_id", "provider_version", "algorithm_family",
    "algorithm_identifier", "security_profile", "signature_mode", "hybrid_mode",
    "components", "key_id", "public_key_fingerprint", "created_at", "expires_at",
    "revoked", "verification_policy_version", "migration_status", "legacy_status",
    "deprecation_status",
})


@dataclass(frozen=True)
class CryptoProfileRequirement:
    provider_id: str = "cryptography.mldsa"
    algorithm_identifier: str = "ML-DSA"
    signature_mode: str = "SINGLE_PROVIDER_SIGNATURE"
    verification_policy_version: str = VERIFICATION_POLICY_VERSION
    key_id: str | None = None
    public_key_fingerprint: str | None = None
    require_migrated_profile: bool = False
    allow_legacy: bool = False
    allow_hybrid: bool = False


def _provider_version() -> str:
    try:
        return importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        return "UNAVAILABLE"


def build_current_crypto_profile(
    *,
    key_id: str,
    public_key_fingerprint: str,
    created_at: str = "2026-08-09T00:00:00+00:00",
    expires_at: str | None = None,
) -> dict[str, Any]:
    return {
        "profile_version": CRYPTO_PROFILE_VERSION,
        "provider_id": provider_name(),
        "provider_version": _provider_version(),
        "algorithm_family": "POST_QUANTUM_DIGITAL_SIGNATURE",
        "algorithm_identifier": SIGNATURE_ALGORITHM,
        "security_profile": PQC_POLICY_NAME,
        "signature_mode": "SINGLE_PROVIDER_SIGNATURE",
        "hybrid_mode": False,
        "components": [],
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint,
        "created_at": created_at,
        "expires_at": expires_at,
        "revoked": False,
        "verification_policy_version": VERIFICATION_POLICY_VERSION,
        "migration_status": "CURRENT_PROVIDER_BASELINE_PASS8_NO_MIGRATION",
        "legacy_status": "CURRENT_NOT_LEGACY",
        "deprecation_status": "NOT_DEPRECATED_BY_PASS8_POLICY",
    }


def profile_from_signature(
    signature: Mapping[str, Any],
    *,
    key_id: str,
    created_at: str = "2026-08-09T00:00:00+00:00",
) -> dict[str, Any]:
    profile = build_current_crypto_profile(
        key_id=key_id,
        public_key_fingerprint=str(signature.get("key_fingerprint", "")),
        created_at=created_at,
    )
    profile["provider_id"] = signature.get("provider")
    profile["algorithm_identifier"] = signature.get("algorithm")
    profile["security_profile"] = signature.get("policy")
    return profile


def validate_crypto_profile(
    profile: Mapping[str, Any] | None,
    *,
    requirement: CryptoProfileRequirement | None = None,
    now: datetime | None = None,
    provider_is_available: bool | None = None,
) -> tuple[bool, list[str]]:
    required = requirement or CryptoProfileRequirement()
    if not isinstance(profile, Mapping):
        return False, ["cryptographic_profile_missing"]
    failures: list[str] = []
    if set(profile) != CRYPTO_PROFILE_FIELDS:
        failures.append("cryptographic_profile_schema_invalid")
    if profile.get("profile_version") != CRYPTO_PROFILE_VERSION:
        failures.append("cryptographic_profile_version_unknown")
    if profile.get("provider_id") != required.provider_id:
        failures.append("cryptographic_provider_substitution")
    if profile.get("provider_version") in {None, "", "UNAVAILABLE"}:
        failures.append("cryptographic_provider_version_missing")
    if profile.get("algorithm_family") != "POST_QUANTUM_DIGITAL_SIGNATURE":
        failures.append("cryptographic_algorithm_family_unknown")
    if profile.get("algorithm_identifier") != required.algorithm_identifier:
        failures.append("cryptographic_algorithm_substitution")
    if profile.get("security_profile") != PQC_POLICY_NAME:
        failures.append("cryptographic_security_profile_invalid")
    if profile.get("signature_mode") != required.signature_mode:
        failures.append("cryptographic_signature_mode_mismatch")
    if profile.get("verification_policy_version") != required.verification_policy_version:
        failures.append("cryptographic_policy_cross_version_replay")
    key_id = profile.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        failures.append("cryptographic_key_id_missing")
    elif required.key_id is not None and key_id != required.key_id:
        failures.append("cryptographic_key_id_mismatch")
    fingerprint = profile.get("public_key_fingerprint")
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        failures.append("cryptographic_public_key_fingerprint_malformed")
    elif required.public_key_fingerprint is not None and fingerprint != required.public_key_fingerprint:
        failures.append("cryptographic_public_key_fingerprint_mismatch")
    if profile.get("revoked") is not False:
        failures.append("cryptographic_key_revoked")
    if not isinstance(profile.get("created_at"), str):
        failures.append("cryptographic_created_at_invalid")
    expiry = profile.get("expires_at")
    if expiry is not None:
        try:
            expiry_time = datetime.fromisoformat(str(expiry))
            current = now or datetime.now(timezone.utc)
            if expiry_time.tzinfo is None or expiry_time <= current:
                failures.append("cryptographic_key_expired")
        except ValueError:
            failures.append("cryptographic_expires_at_invalid")
    hybrid = profile.get("hybrid_mode")
    components = profile.get("components")
    if hybrid is True:
        if not required.allow_hybrid:
            failures.append("cryptographic_hybrid_mode_not_approved")
        if not isinstance(components, list) or len(components) < 2:
            failures.append("cryptographic_hybrid_component_invalid")
        elif any(
            not isinstance(component, Mapping)
            or component.get("valid") is not True
            or not isinstance(component.get("algorithm_identifier"), str)
            for component in components
        ):
            failures.append("cryptographic_hybrid_component_invalid")
    elif hybrid is False:
        if components != []:
            failures.append("cryptographic_nonhybrid_components_present")
    else:
        failures.append("cryptographic_hybrid_mode_invalid")
    legacy = profile.get("legacy_status")
    if not required.allow_legacy and legacy != "CURRENT_NOT_LEGACY":
        failures.append("cryptographic_legacy_downgrade_rejected")
    migration = profile.get("migration_status")
    if required.require_migrated_profile and migration != "MIGRATED_APPROVED":
        failures.append("cryptographic_migrated_profile_required")
    if profile.get("deprecation_status") != "NOT_DEPRECATED_BY_PASS8_POLICY":
        failures.append("cryptographic_algorithm_deprecated")
    available = provider_available() if provider_is_available is None else provider_is_available
    if available is not True:
        failures.append("cryptographic_provider_unavailable")
    return not failures, failures


def build_profiled_object(
    payload: Mapping[str, Any],
    *,
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    signed = {"payload": deepcopy(dict(payload)), "crypto_profile": deepcopy(dict(profile))}
    return {**signed, "integrity_signature": sign_payload(signed)}


def verify_profiled_object(
    value: Mapping[str, Any],
    *,
    requirement: CryptoProfileRequirement | None = None,
    signature_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], bool] = verify_signature,
    provider_is_available: bool | None = None,
) -> tuple[bool, list[str]]:
    if not isinstance(value, Mapping) or set(value) != {
        "payload", "crypto_profile", "integrity_signature"
    }:
        return False, ["profiled_object_schema_invalid"]
    profile_ok, failures = validate_crypto_profile(
        value.get("crypto_profile"),
        requirement=requirement,
        provider_is_available=provider_is_available,
    )
    signed = {
        "payload": deepcopy(value.get("payload")),
        "crypto_profile": deepcopy(value.get("crypto_profile")),
    }
    try:
        signature_ok = signature_verifier(signed, value.get("integrity_signature", {}))
    except TimeoutError:
        signature_ok = False
        failures.append("cryptographic_verification_timeout")
    except Exception:
        signature_ok = False
        failures.append("cryptographic_verification_exception")
    if not signature_ok:
        failures.append("profiled_object_signature_invalid")
    return profile_ok and signature_ok and not failures, failures


def _boundary(
    boundary_id: str,
    file: str,
    function: str,
    purpose: str,
    protected_object: str,
    *,
    algorithm: str = "ML-DSA",
    provider: str = "cryptography.mldsa",
    role: str = "signature",
    key_id: str = "fingerprint-bound or caller-declared",
    failure: str = "protected object rejected; control path fails closed",
    migration: str = "Pass 9 profile/version integration review",
    tests: Sequence[str] = ("tests/test_pqc_01_provider_contract.py",),
) -> dict[str, Any]:
    return {
        "boundary_id": boundary_id,
        "repository_file": file,
        "class_or_function": function,
        "purpose": purpose,
        "object_protected": protected_object,
        "current_algorithm_identifier": algorithm,
        "current_provider_identifier": provider,
        "provider_version": _provider_version() if provider == "cryptography.mldsa" else "stdlib",
        "cryptographic_role": role,
        "key_id_handling": key_id,
        "key_storage_or_custody_assumption": "operator environment or public verification/custody evidence; no private key embedded",
        "key_rotation_support": "restart-bound identity; controlled evidence regeneration required",
        "revocation_support": "explicit in selected credential/source-key domains; gap elsewhere",
        "expiry_support": "object-specific; migration profile scaffolding supports explicit expiry",
        "recovery_support": "backup/restore preserves evidence but restored material requires full verification",
        "algorithm_metadata_present": algorithm not in {"SHA-256", "HMAC-SHA256_PLACEHOLDER_TEST_ONLY"},
        "signature_mode_metadata_present": role == "signature",
        "migration_status_metadata_present": False,
        "legacy_compatibility_requirement": "explicit only; silent legacy acceptance prohibited",
        "expected_lifetime": "runtime to long-term evidence depending on object",
        "failure_consequence": failure,
        "fail_closed_behaviour": True,
        "tests": list(tests),
        "evidence": ["outputs/security/pqc_migration_readiness_inventory.json"],
        "pass9_migration_action": migration,
        "specialist_review_required": True,
    }


def build_crypto_boundary_inventory(repository_root: Path) -> dict[str, Any]:
    boundaries = [
        _boundary("CRYPTO_EIE_01", "sbp_lex/pipeline/hard_ingress.py", "validate_eie_envelope", "EIE authenticity", "EIE envelope"),
        _boundary("CRYPTO_SKG_SOURCE_01", "external_substrates/shared/source_crypto.py", "verify_source_signature", "SKG source authenticity", "SKG package", key_id="explicit source key ID"),
        _boundary("CRYPTO_DTN_SOURCE_01", "external_substrates/shared/source_crypto.py", "verify_source_signature", "DTN source authenticity", "DTN package", key_id="explicit source key ID"),
        _boundary("CRYPTO_SYNTHETIC_PLACEHOLDER_01", "external_substrates/shared/signing.py", "verify_signature", "deterministic synthetic fixture integrity only", "Pass 2 synthetic package", algorithm="HMAC-SHA256_PLACEHOLDER_TEST_ONLY", provider="python.stdlib.hmac", migration="Remain test-only; prohibit live/provider promotion"),
        _boundary("CRYPTO_BRIDGE_01", "external_substrates/shared/bridge_validator.py", "validate_pre_context_package_for_bridge", "bridge package continuity", "bridge result"),
        _boundary("CRYPTO_COLLECTIVE_01", "sbp_lex/collective/context_interface.py", "validate_pre_context_signals", "collective-signal authenticity", "collective signal package"),
        _boundary("CRYPTO_ROOT_01", "sbp_lex/authority_first/root_of_trust_runner.py", "run_root_of_trust", "Root of Trust attestation", "root attestation"),
        _boundary("CRYPTO_TOKEN_01", "sbp_lex/security/token_stack.py", "verify_token", "core token proof", "core and bundle tokens"),
        _boundary("CRYPTO_THRESHOLD_01", "sbp_lex/security/threshold_tokens.py", "verify_threshold_token", "conditional threshold proof", "threshold tokens"),
        _boundary("CRYPTO_EXECUTION_BOUNDARY_01", "sbp_lex/execution/capability.py", "verify_execution_traversal_authority", "execution boundary continuity", "execution traversal authority"),
        _boundary("CRYPTO_EXECUTION_ATTESTATION_01", "sbp_lex/security/execution_attestation.py", "verify_execution_attestation", "execution attestation", "execution attestation"),
        _boundary("CRYPTO_STATE_HASH_01", "sbp_lex/shared/hash_chain.py", "rebuild_state_hash", "canonical state integrity", "state", algorithm="SHA-256", provider="python.hashlib", role="digest", key_id="not applicable"),
        _boundary("CRYPTO_HASH_CHAIN_01", "sbp_lex/shared/hash_chain.py", "validate_hash_chain", "stage continuity", "hash chain", algorithm="SHA-256", provider="python.hashlib", role="digest", key_id="not applicable"),
        _boundary("CRYPTO_AUDIT_01", "sbp_lex/audit/audit_finalisation.py", "verify_final_audit_record", "terminal audit authenticity", "audit record"),
        _boundary("CRYPTO_REPLAY_01", "sbp_lex/pipeline/replay_runner.py", "verify_replay_result", "replay evidence authenticity", "replay result"),
        _boundary("CRYPTO_INTEGRITY_LEDGER_01", "sbp_lex/persistence/integrity_store.py", "verify_integrity_records", "security integrity ledger", "integrity records/checkpoint"),
        _boundary("CRYPTO_LOCAL_TRUST_01", "sbp_lex/local_trust/signing.py", "verify_local_trust_digest", "local-trust manifest authenticity", "local trust artifacts"),
        _boundary("CRYPTO_RELEASE_01", "sbp_lex/supply_chain/common.py", "verify_envelope", "release/evidence manifest authenticity", "release manifest"),
        _boundary("CRYPTO_BACKUP_01", "sbp_lex/recovery/manifest.py", "validate_manifest", "backup manifest integrity", "sealed backup manifest", algorithm="SHA-256", provider="python.hashlib", role="digest", key_id="not applicable", migration="Pass 9 decide signed backup-profile integration"),
        _boundary("CRYPTO_MEASURED_STARTUP_01", "sbp_lex/runtime/measured_startup.py", "verify_startup_attestation", "runtime measurement authenticity", "startup attestation"),
        _boundary("CRYPTO_UPDATE_PACKAGE_01", "sbp_lex/supply_chain/provenance.py", "validate_provenance_manifest", "package/source provenance", "provenance manifest"),
        _boundary("CRYPTO_DELEGATED_AUTHORITY_01", "sbp_lex/api/credential_lifecycle.py", "verify_credential_record", "delegated credential lifecycle", "credential record", algorithm="SHA-256 and ML-DSA envelope", provider="python.hashlib + cryptography.mldsa", migration="Pass 9 specialist review for delegated-authority profile"),
    ]
    missing = [item["repository_file"] for item in boundaries if not (repository_root / item["repository_file"]).is_file()]
    payload = {
        "inventory_version": INVENTORY_VERSION,
        "repository": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "current_provider_replaced": False,
        "migration_completed": False,
        "quantum_safe_claim": False,
        "boundary_count": len(boundaries),
        "boundaries": boundaries,
        "missing_repository_files": sorted(set(missing)),
        "inventory_complete": not missing,
    }
    return {**payload, "inventory_digest": generate_digest(payload)}


def validate_crypto_boundary_inventory(value: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(value, Mapping):
        return False, ["pqc_inventory_not_mapping"]
    payload = {key: item for key, item in value.items() if key != "inventory_digest"}
    if value.get("inventory_version") != INVENTORY_VERSION:
        failures.append("pqc_inventory_version_invalid")
    if value.get("inventory_digest") != generate_digest(payload):
        failures.append("pqc_inventory_digest_invalid")
    if value.get("current_provider_replaced") is not False or value.get("migration_completed") is not False:
        failures.append("pqc_inventory_scope_violation")
    boundaries = value.get("boundaries")
    if not isinstance(boundaries, list) or len(boundaries) < 20:
        failures.append("pqc_inventory_boundary_set_incomplete")
    elif len({item.get("boundary_id") for item in boundaries if isinstance(item, Mapping)}) != len(boundaries):
        failures.append("pqc_inventory_boundary_id_duplicate")
    if value.get("missing_repository_files") != [] or value.get("inventory_complete") is not True:
        failures.append("pqc_inventory_repository_surface_missing")
    return not failures, failures


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def build_pqc_performance_baseline(*, samples: int = 25, warmup: int = 5) -> dict[str, Any]:
    if samples < 5 or warmup < 1:
        raise ValueError("pqc_performance_sample_bound_invalid")
    message = b"SBP_LEX_PASS8_PQC_PERFORMANCE_BASELINE"
    provider_start = time.perf_counter_ns()
    private_key, public_key = generate_signing_keypair(SIGNATURE_ALGORITHM)
    provider_start_ms = (time.perf_counter_ns() - provider_start) / 1_000_000
    for _ in range(warmup):
        signature = sign(message, private_key, SIGNATURE_ALGORITHM)
        if not verify(message, signature, public_key, SIGNATURE_ALGORITHM):
            raise RuntimeError("pqc_performance_warmup_verification_failed")
    sign_ms: list[float] = []
    verify_ms: list[float] = []
    failure_ms: list[float] = []
    signature_sizes: list[int] = []
    tracemalloc.start()
    for _ in range(samples):
        started = time.perf_counter_ns()
        signature = sign(message, private_key, SIGNATURE_ALGORITHM)
        sign_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        signature_sizes.append(len(signature))
        started = time.perf_counter_ns()
        if not verify(message, signature, public_key, SIGNATURE_ALGORITHM):
            raise RuntimeError("pqc_performance_verification_failed")
        verify_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        started = time.perf_counter_ns()
        verify(b"tampered", signature, public_key, SIGNATURE_ALGORITHM)
        failure_ms.append((time.perf_counter_ns() - started) / 1_000_000)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    metrics = {
        "sign_latency_ms": _latency(sign_ms),
        "verify_latency_ms": _latency(verify_ms),
        "failure_path_latency_ms": _latency(failure_ms),
        "signature_size_bytes": {"minimum": min(signature_sizes), "maximum": max(signature_sizes)},
        "private_key_reference_size_bytes": len(private_key),
        "public_key_size_bytes": len(public_key),
        "signed_object_storage_size_bytes": len(message) + len(signature) + len(public_key),
        "peak_traced_memory_bytes": peak,
        "provider_startup_and_key_generation_ms": provider_start_ms,
        "batch_verification_sample_count": samples,
        "key_rotation_simulation_ms": provider_start_ms,
        "archive_resigning_estimate_ms_per_object": statistics.median(sign_ms),
    }
    payload = {
        "performance_version": PERFORMANCE_VERSION,
        "engineering_baseline_only": True,
        "cryptographic_certification": False,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "provider_id": provider_name(),
        "provider_version": _provider_version(),
        "algorithm_identifier": SIGNATURE_ALGORITHM,
        "sample_count": samples,
        "warmup_count": warmup,
        "warmup_method": "provider sign/verify round trips",
        "metrics": metrics,
        "errors": [],
    }
    return {**payload, "baseline_digest": generate_digest(payload)}


def _latency(values: list[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "median": statistics.median(values),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
        "maximum": max(values),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pass 8 PQC migration readiness evidence")
    sub = parser.add_subparsers(dest="command", required=True)
    inventory = sub.add_parser("inventory")
    inventory.add_argument("--root", default=".")
    inventory.add_argument("--output")
    performance = sub.add_parser("performance")
    performance.add_argument("--samples", type=int, default=25)
    performance.add_argument("--warmup", type=int, default=5)
    performance.add_argument("--output")
    args = parser.parse_args(argv)
    successful = True
    if args.command == "inventory":
        result = build_crypto_boundary_inventory(Path(args.root).resolve())
        valid, failures = validate_crypto_boundary_inventory(result)
        successful = valid
        payload = {key: item for key, item in result.items() if key != "inventory_digest"}
        payload["validation_status"] = "PASS" if valid else "FAIL"
        payload["validation_failures"] = failures
        result = {**payload, "inventory_digest": generate_digest(payload)}
    else:
        result = build_pqc_performance_baseline(samples=args.samples, warmup=args.warmup)
    if args.output:
        atomic_json(Path(args.output), result)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
