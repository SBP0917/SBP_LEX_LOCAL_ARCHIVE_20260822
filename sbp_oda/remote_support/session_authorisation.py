from __future__ import annotations

from datetime import UTC, datetime

from sbp_oda.remote_support.support_session import SupportSession


def is_session_active(session: SupportSession) -> bool:
    expires_at = datetime.fromisoformat(session.expires_at)
    return datetime.now(UTC) < expires_at


def assert_remote_support_boundary(session: SupportSession) -> None:
    if not session.outbound_only:
        raise PermissionError("Remote support must remain outbound-only.")

    if session.remote_shell_allowed:
        raise PermissionError("Unrestricted remote shell is prohibited for ODA-V1.")

    if not is_session_active(session):
        raise PermissionError("Remote support session has expired.")
