import pytest

from sbp_oda.remote_support.session_authorisation import assert_remote_support_boundary
from sbp_oda.remote_support.support_session import SupportSession, create_support_session


def test_remote_support_is_outbound_only_by_default() -> None:
    session = create_support_session("DEPLOYMENT_TEST", "support_user")

    assert session.outbound_only is True
    assert session.remote_shell_allowed is False
    assert_remote_support_boundary(session)


def test_remote_shell_is_blocked() -> None:
    session = SupportSession(
        session_id="test",
        deployment_id="DEPLOYMENT_TEST",
        support_operator="support_user",
        mode="OUTBOUND_ONLY_SUPPORT",
        created_at="2099-01-01T00:00:00+00:00",
        expires_at="2099-01-01T01:00:00+00:00",
        outbound_only=True,
        remote_shell_allowed=True,
    )

    with pytest.raises(PermissionError):
        assert_remote_support_boundary(session)
