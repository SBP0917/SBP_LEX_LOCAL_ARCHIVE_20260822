from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from sbp_oda.status import ODAStatus


FORBIDDEN_ACTION_KEYWORDS = {
    "change_governance_law",
    "change_pipeline_order",
    "alter_execution_gate",
    "rewrite_locked_canon",
    "mutate_token_authority",
    "mutate_audit_authority",
    "mutate_hash_chain_authority",
    "issue_runtime_allow",
    "issue_runtime_deny",
    "issue_runtime_escalate",
    "issue_runtime_halt",
    "execute_runtime_action",
    "open_unrestricted_remote_shell",
}


@dataclass(frozen=True)
class BoundaryDecision:
    status: ODAStatus
    allowed: bool
    reason: str
    blocked_keywords: list[str] = field(default_factory=list)


def check_oda_boundary(action_name: str, requested_operations: Iterable[str]) -> BoundaryDecision:
    lowered = {operation.lower().strip() for operation in requested_operations}
    blocked = sorted(keyword for keyword in FORBIDDEN_ACTION_KEYWORDS if keyword in lowered)

    if blocked:
        return BoundaryDecision(
            status=ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY,
            allowed=False,
            reason="Requested operation crosses ODA support boundary.",
            blocked_keywords=blocked,
        )

    return BoundaryDecision(
        status=ODAStatus.HARNESS_OK,
        allowed=True,
        reason=f"Action '{action_name}' remains inside ODA support boundary.",
        blocked_keywords=[],
    )
