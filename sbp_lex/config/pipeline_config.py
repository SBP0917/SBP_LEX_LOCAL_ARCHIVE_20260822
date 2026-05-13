from __future__ import annotations

PIPELINE_ORDER = [
    "state_construction",
    "collective_attach",
    "root_of_trust",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain_wrap",
    "aurion_runtime",
    "execution_gate",
    "audit",
]

HASH_CHAIN_STAGES = [
    "collective_attach",
    "root_of_trust",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "domain_wrap",
    "aurion_runtime",
    "execution_gate",
    "audit",
]

ROOT_OF_TRUST_ORDER = [
    "anchor_validation",
    "attestation",
    "attestation_consensus",
    "truth_anchor",
    "truth_continuity",
    "truth_expiry",
    "truth_revocation",
]

PIPELINE_MODES = {
    "MODE_1_FULL_MIRRORED": "full_mirrored_deterministic_traversal",
    "MODE_2_SPLIT_VALIDATOR": "split_governance_validator_traversal",
    "MODE_3_SINGLE_CONSTRAINED": "single_pipeline_constrained_traversal",
}

NODE_SYNC_REQUIRED_FIELDS = [
    "node_id",
    "request_fingerprint",
    "state_hash",
    "pipeline_mode",
    "threshold_bundle_hash",
    "token_bundle_hash",
    "convergence_hash",
    "decision",
    "audit_hash",
    "node_signature",
]
