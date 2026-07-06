from __future__ import annotations

from sbp_oda.maintenance.maintenance_policy import RepairClass, evaluate_repair_class


def plan_maintenance(repair_class: RepairClass) -> dict[str, object]:
    decision = evaluate_repair_class(repair_class)
    return {"status": decision.status.value, "auto_apply": decision.allowed_to_auto_apply, "reason": decision.reason}
