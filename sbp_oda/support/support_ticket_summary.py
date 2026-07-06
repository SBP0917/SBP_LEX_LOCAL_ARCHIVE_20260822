from __future__ import annotations


def build_support_ticket_summary(deployment_id: str, finding_count: int) -> dict[str, object]:
    return {"deployment_id": deployment_id, "finding_count": finding_count}
