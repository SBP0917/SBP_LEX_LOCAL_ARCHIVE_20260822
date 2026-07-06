from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CapabilityClass(StrEnum):
    READ_ONLY = "READ_ONLY"
    DIAGNOSTIC = "DIAGNOSTIC"
    REPORTING = "REPORTING"
    MAINTENANCE_PLANNING = "MAINTENANCE_PLANNING"
    OWNER_APPROVED_MAINTENANCE = "OWNER_APPROVED_MAINTENANCE"
    REMOTE_SUPPORT = "REMOTE_SUPPORT"
    BLOCKED_CANONICAL = "BLOCKED_CANONICAL"


@dataclass(frozen=True)
class ODACapability:
    name: str
    capability_class: CapabilityClass
    description: str
    owner_approval_required: bool
    auto_apply_allowed: bool
    runtime_authority: bool = False


ODA_CAPABILITY_INDEX: dict[str, ODACapability] = {
    "repo_health_check": ODACapability(
        name="repo_health_check",
        capability_class=CapabilityClass.DIAGNOSTIC,
        description="Inspect repository path, branch, working tree, and critical file presence.",
        owner_approval_required=False,
        auto_apply_allowed=True,
    ),
    "config_health_check": ODACapability(
        name="config_health_check",
        capability_class=CapabilityClass.DIAGNOSTIC,
        description="Inspect deployment configuration consistency without mutating runtime authority.",
        owner_approval_required=False,
        auto_apply_allowed=True,
    ),
    "audit_evidence_check": ODACapability(
        name="audit_evidence_check",
        capability_class=CapabilityClass.DIAGNOSTIC,
        description="Check audit, report, and evidence presence and hash consistency.",
        owner_approval_required=False,
        auto_apply_allowed=True,
    ),
    "support_bundle_generation": ODACapability(
        name="support_bundle_generation",
        capability_class=CapabilityClass.REPORTING,
        description="Generate a support bundle for remote support triage.",
        owner_approval_required=True,
        auto_apply_allowed=False,
    ),
    "safe_config_tweak": ODACapability(
        name="safe_config_tweak",
        capability_class=CapabilityClass.OWNER_APPROVED_MAINTENANCE,
        description="Apply an approved non-canonical configuration tweak with rollback.",
        owner_approval_required=True,
        auto_apply_allowed=False,
    ),
    "remote_health_sync": ODACapability(
        name="remote_health_sync",
        capability_class=CapabilityClass.REMOTE_SUPPORT,
        description="Send outbound-only health status to support bridge.",
        owner_approval_required=False,
        auto_apply_allowed=True,
    ),
    "runtime_governance_change": ODACapability(
        name="runtime_governance_change",
        capability_class=CapabilityClass.BLOCKED_CANONICAL,
        description="Blocked. ODA cannot change SBP-LEX runtime governance authority.",
        owner_approval_required=False,
        auto_apply_allowed=False,
        runtime_authority=False,
    ),
}


ODA_TOOLKIT_INDEX: dict[str, tuple[str, ...]] = {
    "HEALTH_CHECKS": (
        "repository_root_presence",
        "critical_file_presence",
        "config_file_presence",
        "test_command_availability",
        "runtime_command_availability",
        "ui_control_room_file_presence",
        "audit_report_output_presence",
        "remote_support_bridge_readiness",
    ),
    "DIAGNOSTICS": (
        "repo_missing_file_diagnosis",
        "config_missing_file_diagnosis",
        "dirty_working_tree_diagnosis",
        "missing_report_diagnosis",
        "missing_output_diagnosis",
        "version_drift_diagnosis",
        "broken_support_session_diagnosis",
        "missing_rollback_package_diagnosis",
    ),
    "MAINTENANCE": (
        "report_only_maintenance",
        "non_destructive_metadata_refresh",
        "approved_config_restoration",
        "test_report_regeneration",
        "support_bundle_generation",
        "rollback_package_preparation",
        "codex_work_package_preparation",
        "canon_runtime_sensitive_repair_blocking",
    ),
    "REMOTE_SUPPORT": (
        "outbound_only_session_creation",
        "session_expiry_validation",
        "remote_health_sync",
        "remote_diagnostic_export",
        "signed_package_receipt_placeholder",
        "rollback_verification_placeholder",
        "owner_visible_action_log",
        "physical_attendance_escalation_flag",
    ),
    "DOCUMENT_CONTROL": (
        "document_classification",
        "canonical_index",
        "duplicate_detection",
        "superseded_detection",
        "relationship_mapping",
        "gap_analysis",
        "human_review_flagging",
    ),
    "REPO_CONTROL": (
        "file_manifest",
        "critical_file_hash_capture",
        "branch_status_capture",
        "commit_evidence_capture",
        "local_trust_status_placeholder",
    ),
    "SUPPORT_OUTPUTS": (
        "health_report",
        "diagnostic_report",
        "maintenance_report",
        "support_ticket_summary",
        "support_bundle_manifest",
        "escalation_package",
    ),
}
