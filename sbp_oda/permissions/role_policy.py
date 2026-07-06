from __future__ import annotations

ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "owner": ("health", "diagnostics", "support_bundle", "approve_safe_maintenance"),
    "installer": ("health", "diagnostics", "support_bundle"),
    "support": ("health", "diagnostics", "remote_support"),
    "observer": ("health",),
}
