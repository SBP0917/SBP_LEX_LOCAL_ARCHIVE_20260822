from __future__ import annotations


def receive_signed_package_placeholder(package_id: str) -> dict[str, str]:
    return {"package_id": package_id, "status": "RECEIVED_PENDING_VERIFICATION", "auto_apply": "false"}
