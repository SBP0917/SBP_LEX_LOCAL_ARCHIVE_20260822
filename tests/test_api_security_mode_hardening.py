from __future__ import annotations

import pytest

from sbp_lex.api import access_control
from sbp_lex.api.server import run_server
from sbp_lex.config.environment import environment_security_report


@pytest.mark.parametrize("mode", ["unknown", " local-private ", "", "DISABLED "])
def test_unknown_or_unauthorized_security_modes_fail_closed(monkeypatch, mode: str) -> None:
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", mode)
    monkeypatch.delenv(access_control.INSECURE_TEST_MODE_FLAG, raising=False)

    decision = access_control.decide_access(
        method="GET", path="/health", client_host="127.0.0.1", headers={}
    )

    assert decision.allowed is False
    assert decision.status == 503
    assert decision.mode == "invalid"


def test_unknown_security_mode_prevents_server_socket_binding(monkeypatch) -> None:
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "typo")

    with pytest.raises(access_control.SecurityConfigurationError, match="invalid_api_security_mode"):
        run_server(port=0)


def test_disabled_mode_requires_explicit_test_opt_in(monkeypatch) -> None:
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "disabled")
    monkeypatch.delenv(access_control.INSECURE_TEST_MODE_FLAG, raising=False)

    with pytest.raises(access_control.SecurityConfigurationError, match="outside_test_harness"):
        access_control.security_mode()

    report = environment_security_report()
    assert report["valid"] is False
    assert "api_security_disabled_outside_test_harness" in report["warnings"]


def test_disabled_mode_is_contained_to_opted_in_active_pytest(monkeypatch) -> None:
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "disabled")
    monkeypatch.setenv(access_control.INSECURE_TEST_MODE_FLAG, "1")
    assert access_control.security_mode() == "disabled"

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    with pytest.raises(access_control.SecurityConfigurationError, match="outside_test_harness"):
        access_control.security_mode()


def test_valid_modes_preserve_existing_access_boundaries(monkeypatch) -> None:
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", " LOCAL ")
    assert access_control.security_mode() == "local"
    assert access_control.decide_access(
        method="GET", path="/health", client_host="127.0.0.1", headers={}
    ).allowed
    assert not access_control.decide_access(
        method="GET", path="/health", client_host="203.0.113.8", headers={}
    ).allowed

    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "private")
    monkeypatch.setenv("SBP_LEX_API_TOKEN", "a-secure-private-token-value")
    assert access_control.decide_access(
        method="GET",
        path="/health",
        client_host="203.0.113.8",
        headers={"Authorization": "Bearer a-secure-private-token-value"},
    ).allowed
