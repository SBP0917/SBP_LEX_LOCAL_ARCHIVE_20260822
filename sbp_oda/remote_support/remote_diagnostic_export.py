from __future__ import annotations


def build_remote_diagnostic_export(deployment_id: str) -> dict[str, str]:
    return {"deployment_id": deployment_id, "export_type": "DIAGNOSTIC_ONLY"}
