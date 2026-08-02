from __future__ import annotations

import hashlib
from base64 import b64encode

import pytest

from sbp_lex.api import access_control
from sbp_lex.api.server import run_server
from sbp_lex.config.environment import environment_security_report
from sbp_lex.security.pqc_provider import derive_signing_keypair


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


def test_environment_report_validates_signing_seed_and_optional_public_key(
    monkeypatch,
) -> None:
    seed = "1" * 64
    _, public_key = derive_signing_keypair(bytes.fromhex(seed), "ML-DSA")
    monkeypatch.setenv("SBP_LEX_SIGNING_SECRET", seed)
    monkeypatch.setenv(
        "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY",
        b64encode(public_key).decode("ascii"),
    )
    monkeypatch.setenv(
        "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT",
        hashlib.sha256(public_key).hexdigest(),
    )
    report = environment_security_report()
    assert report["signing_secret_configured"] is True
    assert report["trusted_signing_public_key_configured"] is True
    assert report["trusted_signing_public_key_valid"] is True
    assert report["expected_signer_fingerprint_valid"] is True
    assert seed not in str(report)

    monkeypatch.setenv(
        "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY", "not-base64!",
    )
    report = environment_security_report()
    assert report["valid"] is False
    assert (
        "trusted_signing_public_key_invalid_or_mismatched"
        in report["warnings"]
    )
