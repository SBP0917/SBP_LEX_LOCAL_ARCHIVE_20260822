from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
import tracemalloc
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sbp_lex.config.security_config import SIGNATURE_ALGORITHM
from sbp_lex.recovery.common import atomic_json
from sbp_lex.security.migration_profile import (
    CRYPTO_PROFILE_FIELDS,
    CRYPTO_PROFILE_VERSION,
    VERIFICATION_POLICY_VERSION,
    CryptoProfileRequirement,
    build_current_crypto_profile,
    profile_from_signature,
    provider_version,
    validate_crypto_profile,
)
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.pqc_provider import (
    generate_signing_keypair,
    provider_name,
    sign,
    verify,
)


INVENTORY_VERSION = "PASS9_PQC_MIGRATION_INVENTORY_V2"
PERFORMANCE_VERSION = "PASS9_PQC_PERFORMANCE_BASELINE_V2"


def _provider_version() -> str:
    return provider_version()


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
    enforcement_status: str = "PASS9_PROFILE_ENFORCED",
    migration: str = "Repository-side Pass 9 profile integration complete",
    profile_enforced: bool = True,
    migration_metadata: bool = True,
    specialist_review: str = "PENDING_EXTERNAL",
    custody: str = "operator environment plus pinned public verification identity; no private key embedded",
    lifecycle: str = "activation, expiry and revocation enforced; rotation requires process restart and trust regeneration",
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
        "provider_version": (
            _provider_version()
            if "cryptography.mldsa" in provider
            else "stdlib"
        ),
        "cryptographic_role": role,
        "key_id_handling": key_id,
        "key_storage_or_custody_assumption": custody,
        "key_lifecycle_support": lifecycle,
        "recovery_support": "backup/restore preserves profile evidence; restored material requires full verification",
        "algorithm_metadata_present": True,
        "signature_mode_metadata_present": profile_enforced,
        "migration_status_metadata_present": migration_metadata,
        "runtime_profile_enforced": profile_enforced,
        "enforcement_status": enforcement_status,
        "legacy_compatibility_requirement": "explicit only; silent legacy acceptance prohibited",
        "archive_policy": "legacy verification is separate and cannot admit runtime work",
        "expected_lifetime": "runtime to long-term evidence depending on object",
        "failure_consequence": failure,
        "fail_closed_behaviour": True,
        "tests": list(tests),
        "evidence": ["outputs/security/pass_09_pqc_migration_inventory.json"],
        "pass9_migration_action": migration,
        "specialist_review_status": specialist_review,
    }


def build_crypto_boundary_inventory(repository_root: Path) -> dict[str, Any]:
    boundaries = [
        _boundary(
            "CRYPTO_EIE_01", "sbp_lex/shared/control_chain_validation.py",
            "validate_eie_binding", "EIE authenticity", "EIE envelope",
            algorithm="SHA-256 with downstream ML-DSA Root binding",
            provider="python.hashlib + cryptography.mldsa",
            role="digest_bound_by_signed_root",
            enforcement_status="PASS9_INDIRECT_PROFILE_BOUND",
            migration="EIE digest is bound into the migrated Root attestation profile",
        ),
        _boundary("CRYPTO_SKG_SOURCE_01", "external_substrates/shared/source_crypto.py", "verify_source_signature", "SKG source authenticity", "SKG package", key_id="explicit source key ID"),
        _boundary("CRYPTO_DTN_SOURCE_01", "external_substrates/shared/source_crypto.py", "verify_source_signature", "DTN source authenticity", "DTN package", key_id="explicit source key ID"),
        _boundary(
            "CRYPTO_SYNTHETIC_PLACEHOLDER_01", "external_substrates/shared/signing.py",
            "verify_signature", "deterministic synthetic fixture integrity only",
            "Pass 2 synthetic package", algorithm="HMAC-SHA256_PLACEHOLDER_TEST_ONLY",
            provider="python.stdlib.hmac", role="test_only_integrity",
            key_id="not a production identity", profile_enforced=False,
            migration_metadata=True, enforcement_status="PQC_EXCLUDED_TEST_ONLY",
            migration="Explicitly excluded from live/provider promotion",
            specialist_review="NOT_APPLICABLE_TEST_ONLY",
            custody="fixed deterministic fixture key; prohibited from live use",
            lifecycle="not applicable; test-only surface",
        ),
        _boundary(
            "CRYPTO_BRIDGE_01", "external_substrates/shared/bridge_validator.py",
            "validate_pre_context_package_for_bridge", "bridge package continuity",
            "synthetic pre-context bridge package",
            algorithm="SHA-256 and HMAC-SHA256 placeholder",
            provider="python.hashlib + python.stdlib.hmac", role="test_only_integrity",
            key_id="not a production identity", profile_enforced=False,
            migration_metadata=True, enforcement_status="PQC_EXCLUDED_TEST_ONLY",
            migration="Synthetic bridge stays outside the canonical provider; hard entry revalidates and downstream Root binds its digest",
            specialist_review="NOT_APPLICABLE_TEST_ONLY",
            custody="fixed deterministic fixture key; prohibited from live use",
            lifecycle="not applicable; test-only surface",
        ),
        _boundary("CRYPTO_COLLECTIVE_01", "sbp_lex/collective/context_interface.py", "validate_collective_signal_package", "collective-signal authenticity", "collective signal package"),
        _boundary("CRYPTO_ROOT_01", "sbp_lex/authority_first/root_of_trust_runner.py", "run_root_of_trust", "Root of Trust attestation", "root attestation"),
        _boundary("CRYPTO_TOKEN_01", "sbp_lex/security/token_stack.py", "verify_token", "core token proof", "core and bundle tokens"),
        _boundary("CRYPTO_THRESHOLD_01", "sbp_lex/security/threshold_tokens.py", "verify_threshold_bundle", "conditional threshold proof", "threshold tokens"),
        _boundary("CRYPTO_EXECUTION_BOUNDARY_01", "sbp_lex/execution/capability.py", "verify_execution_traversal_authority", "execution boundary continuity", "execution traversal authority"),
        _boundary("CRYPTO_EXECUTION_ATTESTATION_01", "sbp_lex/security/execution_attestation.py", "verify_execution_attestation", "execution attestation", "execution attestation"),
        _boundary(
            "CRYPTO_STATE_HASH_01", "sbp_lex/shared/hash_chain.py",
            "rebuild_state_hash", "canonical state integrity", "state",
            algorithm="SHA-256", provider="python.hashlib", role="digest",
            key_id="not applicable", profile_enforced=False,
            migration_metadata=False,
            enforcement_status="PQC_NOT_APPLICABLE_DIGEST_ONLY",
            migration="Retain explicit SHA-256 state digest; signed downstream objects bind it",
            specialist_review="NOT_APPLICABLE_DIGEST_ONLY",
            custody="not applicable to unkeyed digest",
            lifecycle="not applicable to unkeyed digest",
        ),
        _boundary(
            "CRYPTO_HASH_CHAIN_01", "sbp_lex/shared/hash_chain.py", "verify_hash_chain",
            "stage continuity", "hash chain", algorithm="SHA-256",
            provider="python.hashlib", role="digest", key_id="not applicable",
            profile_enforced=False, migration_metadata=False,
            enforcement_status="PQC_NOT_APPLICABLE_DIGEST_ONLY",
            migration="Retain explicit SHA-256 continuity digest; terminal state remains signed",
            specialist_review="NOT_APPLICABLE_DIGEST_ONLY",
            custody="not applicable to unkeyed digest",
            lifecycle="not applicable to unkeyed digest",
        ),
        _boundary("CRYPTO_AUDIT_01", "sbp_lex/audit/audit_finalisation.py", "verify_audit_record", "terminal audit authenticity", "audit record"),
        _boundary("CRYPTO_REPLAY_01", "sbp_lex/pipeline/replay_runner.py", "verify_replay_result", "replay evidence authenticity", "replay result"),
        _boundary("CRYPTO_INTEGRITY_LEDGER_01", "sbp_lex/persistence/integrity_store.py", "verify_integrity_records", "security integrity ledger", "integrity records/checkpoint"),
        _boundary("CRYPTO_LOCAL_TRUST_01", "sbp_lex/local_trust/signing.py", "verify_local_trust_digest", "local-trust manifest authenticity", "local trust artifacts"),
        _boundary("CRYPTO_RELEASE_01", "sbp_lex/supply_chain/common.py", "unseal", "release/evidence manifest authenticity", "release manifest"),
        _boundary("CRYPTO_BACKUP_01", "sbp_lex/recovery/manifest.py", "validate_manifest", "backup manifest integrity", "sealed backup manifest", algorithm="SHA-256 plus ML-DSA profile", provider="python.hashlib + cryptography.mldsa", role="digest_and_signature", migration="Canonical recovery bound_payload now carries the enforced V3 profile"),
        _boundary("CRYPTO_MEASURED_STARTUP_01", "sbp_lex/runtime/measured_startup.py", "verify_startup_attestation", "runtime measurement authenticity", "startup attestation"),
        _boundary("CRYPTO_UPDATE_PACKAGE_01", "sbp_lex/supply_chain/provenance.py", "validate_repository_provenance", "package/source provenance", "provenance manifest", algorithm="SHA-256 plus ML-DSA sealed assurance envelope", provider="python.hashlib + cryptography.mldsa", role="digest_and_signature"),
        _boundary(
            "CRYPTO_DELEGATED_AUTHORITY_01", "sbp_lex/api/credential_lifecycle.py",
            "credential_from_record", "delegated credential lifecycle",
            "local API credential record", algorithm="SHA-256 lifecycle event digest",
            provider="python.hashlib", role="credential_lifecycle_digest",
            key_id="credential ID and rotation group", profile_enforced=False,
            migration_metadata=False, enforcement_status="DEFERRED_APP_IDENTITY_BOUNDARY",
            migration="Credential lifecycle remains locally bounded; signed identity/consent profile belongs to owner-approved APP work",
            specialist_review="PENDING_APP_REQUIREMENTS",
            custody="credential secret remains outside public snapshots; APP custody not started",
            lifecycle="activation, rotation, expiry, revocation and retirement enforced locally",
        ),
    ]
    missing = [item["repository_file"] for item in boundaries if not (repository_root / item["repository_file"]).is_file()]
    missing_symbols = []
    for item in boundaries:
        path = repository_root / item["repository_file"]
        if path.is_file() and f"def {item['class_or_function']}" not in path.read_text("utf-8"):
            missing_symbols.append(
                f"{item['repository_file']}::{item['class_or_function']}"
            )
    payload = {
        "inventory_version": INVENTORY_VERSION,
        "repository": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "current_provider_replaced": False,
        "migration_completed": False,
        "profile_integration_complete": True,
        "migration_implementation_status": "REPOSITORY_PROFILE_MIGRATION_IMPLEMENTED_SPECIALIST_REVIEW_PENDING",
        "production_provider_approved": False,
        "quantum_safe_claim": False,
        "boundary_count": len(boundaries),
        "boundaries": boundaries,
        "missing_repository_files": sorted(set(missing)),
        "missing_repository_symbols": sorted(set(missing_symbols)),
        "inventory_complete": not missing and not missing_symbols,
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
    if (
        value.get("current_provider_replaced") is not False
        or value.get("migration_completed") is not False
        or value.get("production_provider_approved") is not False
        or value.get("profile_integration_complete") is not True
    ):
        failures.append("pqc_inventory_scope_violation")
    boundaries = value.get("boundaries")
    if not isinstance(boundaries, list) or len(boundaries) < 20:
        failures.append("pqc_inventory_boundary_set_incomplete")
    elif len({item.get("boundary_id") for item in boundaries if isinstance(item, Mapping)}) != len(boundaries):
        failures.append("pqc_inventory_boundary_id_duplicate")
    if (
        value.get("missing_repository_files") != []
        or value.get("missing_repository_symbols") != []
        or value.get("inventory_complete") is not True
    ):
        failures.append("pqc_inventory_repository_surface_missing")
    if isinstance(boundaries, list):
        allowed = {
            "PASS9_PROFILE_ENFORCED", "PASS9_INDIRECT_PROFILE_BOUND",
            "PQC_NOT_APPLICABLE_DIGEST_ONLY", "PQC_EXCLUDED_TEST_ONLY",
            "DEFERRED_APP_IDENTITY_BOUNDARY",
        }
        if any(
            not isinstance(item, Mapping)
            or item.get("enforcement_status") not in allowed
            for item in boundaries
        ):
            failures.append("pqc_inventory_enforcement_status_invalid")
    return not failures, failures


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def build_pqc_performance_baseline(*, samples: int = 25, warmup: int = 5) -> dict[str, Any]:
    if samples < 5 or warmup < 1:
        raise ValueError("pqc_performance_sample_bound_invalid")
    message = b"SBP_LEX_PASS9_PQC_PERFORMANCE_BASELINE"
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
    parser = argparse.ArgumentParser(description="Pass 9 controlled PQC migration evidence")
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
