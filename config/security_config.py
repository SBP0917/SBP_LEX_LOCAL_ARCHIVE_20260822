from __future__ import annotations

DIGEST_ALGORITHM: str = "sha256"
SIGNATURE_ALGORITHM: str = "HMAC-SHA256-PQC-PLACEHOLDER"
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
