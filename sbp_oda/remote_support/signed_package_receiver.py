from __future__ import annotations

from sbp_oda.status import ODAStatus


def receive_signed_package(package_id: str) -> dict[str, str]:
    return {
        "package_id": package_id,
        "status": ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY.value,
        "reason": "Signed maintenance package receipt is not implemented in ODA-02 and remains blocked.",
        "auto_apply": "false",
    }
