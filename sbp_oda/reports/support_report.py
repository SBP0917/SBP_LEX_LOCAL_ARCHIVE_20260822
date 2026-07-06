from __future__ import annotations


def build_support_report(deployment_id: str) -> dict[str, str]:
    return {"report_type": "ODA_SUPPORT_REPORT", "deployment_id": deployment_id}
