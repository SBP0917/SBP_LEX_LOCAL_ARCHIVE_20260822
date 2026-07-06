from __future__ import annotations


def build_escalation_summary(reason: str, physical_attendance_required: bool = False) -> dict[str, object]:
    return {"reason": reason, "physical_attendance_required": physical_attendance_required}
