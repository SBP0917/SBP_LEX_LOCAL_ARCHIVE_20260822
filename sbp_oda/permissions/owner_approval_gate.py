from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sbp_oda.status import ODAStatus


@dataclass(frozen=True)
class OwnerApprovalRequest:
    operation_id: str
    operation_name: str
    reason: str
    requested_by: str
    risk_class: str
    created_at: str


@dataclass(frozen=True)
class OwnerApprovalDecision:
    operation_id: str
    approved: bool
    approver: str
    decided_at: str
    reason: str
    status: ODAStatus


def create_owner_approval_request(
    operation_id: str,
    operation_name: str,
    reason: str,
    requested_by: str = "ODA",
    risk_class: str = "MAINTENANCE",
) -> OwnerApprovalRequest:
    return OwnerApprovalRequest(
        operation_id=operation_id,
        operation_name=operation_name,
        reason=reason,
        requested_by=requested_by,
        risk_class=risk_class,
        created_at=datetime.now(UTC).isoformat(),
    )


def approve_request(request: OwnerApprovalRequest, approver: str, reason: str) -> OwnerApprovalDecision:
    return OwnerApprovalDecision(
        operation_id=request.operation_id,
        approved=True,
        approver=approver,
        decided_at=datetime.now(UTC).isoformat(),
        reason=reason,
        status=ODAStatus.HARNESS_OK,
    )


def reject_request(request: OwnerApprovalRequest, approver: str, reason: str) -> OwnerApprovalDecision:
    return OwnerApprovalDecision(
        operation_id=request.operation_id,
        approved=False,
        approver=approver,
        decided_at=datetime.now(UTC).isoformat(),
        reason=reason,
        status=ODAStatus.HARNESS_OWNER_APPROVAL_REQUIRED,
    )
