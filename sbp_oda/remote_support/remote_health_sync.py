from __future__ import annotations


def build_remote_health_sync(deployment_id: str, status: str) -> dict[str, str]:
    return {"deployment_id": deployment_id, "status": status, "mode": "OUTBOUND_ONLY"}
