from __future__ import annotations

from sbp_lex.security.pqc_policy import (
    FN_DSA_ENABLED,
    PQC_FAIL_CLOSED,
    PQC_KEM_PRIMARY,
    PQC_POLICY_NAME,
    PQC_REAL_PROVIDER_REQUIRED,
    PQC_SIGNATURE_BACKUP,
    PQC_SIGNATURE_PRIMARY,
)
from sbp_lex.security.pqc_provider import provider_available, provider_name, supported_algorithms

DIGEST_ALGORITHM: str = "sha256"
DEFAULT_SIGNATURE_ALGORITHM: str = PQC_SIGNATURE_PRIMARY
DEFAULT_SIGNATURE_ENCODING: str = "RAW_BYTES_OR_PROVIDER_DEFINED"
PQC_PROVIDER_NAME: str = provider_name()
PQC_PROVIDER_AVAILABLE: bool = provider_available()
SIGNATURE_ALGORITHM: str = DEFAULT_SIGNATURE_ALGORITHM
SYSTEM_ISSUER: str = "SBP_LEX_V6_INTERNAL_CONTROL_PLANE"
STATE_VERSION: str = "SBP_LEX_V6_CANONICAL_STATE_1"
TOKEN_VERSION: str = "SBP_LEX_V6_TOKEN_1"
HASH_CHAIN_VERSION: str = "SBP_LEX_V6_HASH_CHAIN_1"
CONVERGENCE_VERSION: str = "SBP_LEX_V6_CONVERGENCE_1"

SECURITY_PROFILE = {
    "require_digest_binding": True,
    "require_signature_binding": True,
    "require_token_verification": True,
    "require_state_hash": True,
    "require_hash_chain": True,
    "require_audit_hash": True,
    "allow_unsigned_collective_signals": False,
    "allow_unverified_tokens": False,
    "allow_missing_execution_tokens": False,
    "allow_mutable_token_payloads": False,
    "allow_uncontrolled_result_strings": False,
    "allow_state_without_request_fingerprint": False,
    "allow_execution_without_convergence": False,
}

REQUIRED_CORE_TOKENS = [
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "domain",
    "aurion",
    "execution_boundary",
    "execution_attestation",
]

REQUIRED_BUNDLE_TOKENS = [
    "threshold_bundle",
    "token_bundle",
]

CONDITIONAL_THRESHOLD_TOKENS = [
    "consequentiality_threshold",
    "corroboration_threshold",
    "financial_threshold",
    "autonomy_boundary_threshold",
    "escalation_threshold",
]

THRESHOLD_COMPONENT_TOKEN_NAMES = [
    "human_safety_threshold",
    "irreversibility_threshold",
    "cascading_impact_threshold",
    "financial_operational_threshold",
    "consequentiality_tier",
    "corroboration_threshold",
    "autonomy_boundary_threshold",
    "financial_tier_threshold",
    "escalation_threshold",
    "classification_boundary",
    "licensing_scope",
    "jurisdiction_threshold",
    "environment_modifier",
    "public_exposure",
    "operational_scope",
]


def build_pqc_config() -> dict[str, object]:
    return {
        "policy_name": PQC_POLICY_NAME,
        "digest_algorithm": DIGEST_ALGORITHM,
        "signature_algorithm": DEFAULT_SIGNATURE_ALGORITHM,
        "signature_backup_algorithm": PQC_SIGNATURE_BACKUP,
        "kem_algorithm": PQC_KEM_PRIMARY,
        "signature_encoding": DEFAULT_SIGNATURE_ENCODING,
        "provider_name": PQC_PROVIDER_NAME,
        "provider_available": PQC_PROVIDER_AVAILABLE,
        "provider_required": PQC_REAL_PROVIDER_REQUIRED,
        "fail_closed": PQC_FAIL_CLOSED,
        "supported_algorithms": list(supported_algorithms()),
        "fn_dsa_enabled": FN_DSA_ENABLED,
        "system_issuer": SYSTEM_ISSUER,
    }


def build_token_requirements() -> dict[str, list[str]]:
    return {
        "core": list(REQUIRED_CORE_TOKENS),
        "bundles": list(REQUIRED_BUNDLE_TOKENS),
        "conditional_thresholds": list(CONDITIONAL_THRESHOLD_TOKENS),
        "expanded_threshold_components": list(THRESHOLD_COMPONENT_TOKEN_NAMES),
    }


def build_collective_signal_security() -> dict[str, bool]:
    return {
        "allow_unsigned_collective_signals": SECURITY_PROFILE["allow_unsigned_collective_signals"],
        "require_digest_binding": SECURITY_PROFILE["require_digest_binding"],
        "require_signature_binding": SECURITY_PROFILE["require_signature_binding"],
    }


def build_execution_gate_security() -> dict[str, bool]:
    return {
        "require_token_verification": SECURITY_PROFILE["require_token_verification"],
        "require_state_hash": SECURITY_PROFILE["require_state_hash"],
        "require_hash_chain": SECURITY_PROFILE["require_hash_chain"],
        "allow_missing_execution_tokens": SECURITY_PROFILE["allow_missing_execution_tokens"],
        "allow_execution_without_convergence": SECURITY_PROFILE["allow_execution_without_convergence"],
    }


def build_audit_security() -> dict[str, object]:
    return {
        "require_audit_hash": SECURITY_PROFILE["require_audit_hash"],
        "hash_chain_version": HASH_CHAIN_VERSION,
        "state_version": STATE_VERSION,
    }


def build_security_config() -> dict[str, object]:
    return {
        "profile": dict(SECURITY_PROFILE),
        "pqc": build_pqc_config(),
        "tokens": build_token_requirements(),
        "collective_signals": build_collective_signal_security(),
        "execution_gate": build_execution_gate_security(),
        "audit": build_audit_security(),
    }
