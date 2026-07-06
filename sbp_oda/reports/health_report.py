from __future__ import annotations


def build_health_report(status: str, finding_count: int) -> dict[str, object]:
    return {"report_type": "ODA_HEALTH_REPORT", "status": status, "finding_count": finding_count}
