from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from sbp_pvpl.status import PVPLStatus


FORBIDDEN_PUBLICATION_ACTIONS = {
    "publish_externally",
    "connect_blockchain",
    "connect_public_ledger",
    "network_publication",
    "cloud_publication",
    "mutate_audit_files",
    "mutate_runtime_traces",
    "rewrite_proof_evidence",
    "create_runtime_authority",
    "issue_runtime_allow",
    "issue_runtime_deny",
    "issue_runtime_escalate",
    "issue_runtime_halt",
    "issue_runtime_execute",
    "activate_phase_25",
    "activate_runtime_traversal",
    "change_pipeline_order",
}

ALLOWED_LOCAL_PROOF_ACTIONS = {
    "summary",
    "build_manifest",
    "build_proof_manifest",
    "build_bundle",
    "build_proof_bundle",
    "validate_local_proof_artifacts",
    "create_local_handoff_record",
    "collect_evidence",
    "verify_bundle",
    "write_report",
    "boundary_check",
}


@dataclass(frozen=True)
class PVPLBoundaryDecision:
    allowed: bool
    status: PVPLStatus
    reason: str
    blocked_actions: list[str] = field(default_factory=list)


def check_pvpl_boundary(action_name: str, requested_actions: Iterable[str]) -> PVPLBoundaryDecision:
    lowered = {action.lower().strip() for action in requested_actions}
    blocked = sorted(action for action in FORBIDDEN_PUBLICATION_ACTIONS if action in lowered)
    unknown = sorted(action for action in lowered if action not in ALLOWED_LOCAL_PROOF_ACTIONS)
    if blocked:
        return PVPLBoundaryDecision(
            allowed=False,
            status=PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY,
            reason="Requested action crosses PVPL runtime-detached proof boundary.",
            blocked_actions=blocked,
        )
    if unknown:
        return PVPLBoundaryDecision(
            allowed=False,
            status=PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY,
            reason="Requested action is not an implemented PVPL-V1 local proof action.",
            blocked_actions=unknown,
        )
    return PVPLBoundaryDecision(
        allowed=True,
        status=PVPLStatus.PROOF_OK,
        reason=f"Action '{action_name}' remains local proof scaffolding.",
        blocked_actions=[],
    )
