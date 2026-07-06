from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4


@dataclass(frozen=True)
class SupportSession:
    session_id: str
    deployment_id: str
    support_operator: str
    mode: str
    created_at: str
    expires_at: str
    outbound_only: bool = True
    remote_shell_allowed: bool = False


def create_support_session(
    deployment_id: str,
    support_operator: str,
    minutes_valid: int = 60,
) -> SupportSession:
    now = datetime.now(UTC)
    return SupportSession(
        session_id=str(uuid4()),
        deployment_id=deployment_id,
        support_operator=support_operator,
        mode="OUTBOUND_ONLY_SUPPORT",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=minutes_valid)).isoformat(),
        outbound_only=True,
        remote_shell_allowed=False,
    )
