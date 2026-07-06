from sbp_oda.maintenance.maintenance_policy import RepairClass, evaluate_repair_class
from sbp_oda.status import ODAStatus


def test_report_only_can_auto_apply() -> None:
    decision = evaluate_repair_class(RepairClass.REPORT_ONLY)

    assert decision.allowed_to_auto_apply is True
    assert decision.owner_approval_required is False


def test_canon_sensitive_repair_is_blocked() -> None:
    decision = evaluate_repair_class(RepairClass.CANON_RUNTIME_SENSITIVE)

    assert decision.allowed_to_auto_apply is False
    assert decision.status == ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY
