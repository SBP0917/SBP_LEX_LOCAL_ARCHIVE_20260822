from __future__ import annotations


def build_maintenance_report(action_name: str, status: str) -> dict[str, str]:
    return {"report_type": "ODA_MAINTENANCE_REPORT", "action_name": action_name, "status": status}
