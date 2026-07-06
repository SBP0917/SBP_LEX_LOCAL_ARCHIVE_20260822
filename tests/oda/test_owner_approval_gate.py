from sbp_oda.permissions.owner_approval_gate import approve_request, create_owner_approval_request, reject_request
from sbp_oda.status import ODAStatus


def test_owner_approval_request_and_decisions() -> None:
    request = create_owner_approval_request("op-1", "support_bundle_generation", "diagnostic export")

    approved = approve_request(request, "owner", "approved")
    rejected = reject_request(request, "owner", "not now")

    assert approved.approved is True
    assert approved.status == ODAStatus.HARNESS_OK
    assert approved.execution_authority == "NONE"
    assert approved.grants_runtime_authority is False
    assert rejected.approved is False
    assert rejected.status == ODAStatus.HARNESS_OWNER_APPROVAL_REQUIRED


def test_owner_approval_does_not_bypass_canonical_boundary() -> None:
    request = create_owner_approval_request("op-2", "runtime_governance_change", "change runtime", risk_class="RUNTIME_AUTHORITY")

    decision = approve_request(request, "owner", "approved")

    assert decision.approved is False
    assert decision.status == ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY
    assert decision.execution_authority == "NONE"
