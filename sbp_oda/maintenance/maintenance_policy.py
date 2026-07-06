from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from sbp_oda.status import ODAStatus


class RepairClass(IntEnum):
    REPORT_ONLY = 0
    NON_DESTRUCTIVE_METADATA = 1
    CONFIG_RESTORE_APPROVED_BASELINE = 2
    TEST_REPORT_REGENERATION = 3
    CODEX_WORK_PACKAGE_REPAIR = 4
    CANON_RUNTIME_SENSITIVE = 5


@dataclass(frozen=True)
class MaintenancePolicyDecision:
    repair_class: RepairClass
    allowed_to_auto_apply: bool
    owner_approval_required: bool
    status: ODAStatus
    reason: str


def evaluate_repair_class(repair_class: RepairClass) -> MaintenancePolicyDecision:
    if repair_class == RepairClass.REPORT_ONLY:
        return MaintenancePolicyDecision(
            repair_class=repair_class,
            allowed_to_auto_apply=False,
            owner_approval_required=False,
            status=ODAStatus.HARNESS_OK,
            reason="Report-only action is allowed as evidence generation only; ODA-02 does not auto-apply changes.",
        )

    if repair_class in {
        RepairClass.NON_DESTRUCTIVE_METADATA,
        RepairClass.CONFIG_RESTORE_APPROVED_BASELINE,
        RepairClass.TEST_REPORT_REGENERATION,
    }:
        return MaintenancePolicyDecision(
            repair_class=repair_class,
            allowed_to_auto_apply=False,
            owner_approval_required=True,
            status=ODAStatus.HARNESS_OWNER_APPROVAL_REQUIRED,
            reason="Maintenance action requires owner approval before application.",
        )

    if repair_class == RepairClass.CODEX_WORK_PACKAGE_REPAIR:
        return MaintenancePolicyDecision(
            repair_class=repair_class,
            allowed_to_auto_apply=False,
            owner_approval_required=True,
            status=ODAStatus.HARNESS_REPAIR_RECOMMENDED,
            reason="Prepare Codex work package only. Do not auto-apply.",
        )

    return MaintenancePolicyDecision(
        repair_class=repair_class,
        allowed_to_auto_apply=False,
        owner_approval_required=True,
        status=ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY,
        reason="Canon/runtime-sensitive repair cannot be auto-applied by ODA.",
    )
