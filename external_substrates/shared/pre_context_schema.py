from __future__ import annotations

PRE_CONTEXT_SIGNAL_TYPES = (
    "authority_link_signal",
    "jurisdiction_signal",
    "precedence_signal",
    "policy_conflict_signal",
    "operational_context_signal",
    "dependency_signal",
    "capability_signal",
    "feasibility_signal",
    "risk_potential_signal",
    "cascading_impact_signal",
)

PRE_CONTEXT_REQUIRED_FIELDS = {
    "package_type",
    "request_fingerprint",
    "package_version",
    "skg_package_digest",
    "dtn_package_digest",
    "signals",
    "source_records",
    "source_summary",
    "freshness_valid",
    "consistency_valid",
    "digest",
    "signature",
    "timestamp",
    "nonce",
}

