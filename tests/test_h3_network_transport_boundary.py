from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import sbp_lex.api.server as server_module
from sbp_lex.api.access_control import decide_access, is_local_client
from sbp_lex.api.transport_security import (
    LOCAL_PRIVATE,
    PILOT_PRIVATE_MTLS,
    PILOT_PRIVATE_TLS,
    REMOTE_PRODUCTION_DISABLED,
    TransportConfiguration,
    TransportConfigurationError,
    TRANSPORT_SECURITY_EVENTS,
    canonical_ip,
    evaluate_transport,
    is_loopback_address,
    load_transport_configuration,
    normalise_ip,
    transport_identity_grants_api_scope,
    reset_transport_configuration_for_tests,
    validate_bind_policy,
    validate_certificate_identity,
)

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
FINGERPRINT = "a" * 64


def local_config(**changes) -> TransportConfiguration:
    return replace(TransportConfiguration(), **changes)


def proxy_config(**changes) -> TransportConfiguration:
    values = dict(
        profile=PILOT_PRIVATE_TLS,
        allowed_profiles=(PILOT_PRIVATE_TLS,),
        remote_transport_enabled=True,
        tls_enabled=True,
        proxy_enabled=True,
        trusted_proxy_addresses=("10.0.0.2",),
        required_proxy_identity="desktop-proxy-1",
    )
    values.update(changes)
    return local_config(**values)


def tls_config(profile=PILOT_PRIVATE_TLS, **changes) -> TransportConfiguration:
    return local_config(
        profile=profile,
        allowed_profiles=(profile,),
        remote_transport_enabled=True,
        tls_enabled=True,
        required_service_identity="desktop-v1-service" if profile == PILOT_PRIVATE_MTLS else None,
        **changes,
    )


def certificate(**changes):
    value = {
        "fingerprint": FINGERPRINT,
        "not_after": NOW + timedelta(days=1),
        "purpose": "desktop-v1-transport",
        "service_identity": "desktop-v1-service",
        "revoked": False,
    }
    value.update(changes)
    return value


@pytest.mark.parametrize(
    "address,canonical,loopback",
    [
        ("127.0.0.1", "127.0.0.1", True),
        ("::1", "::1", True),
        ("::ffff:127.0.0.1", "127.0.0.1", True),
        ("203.0.113.8", "203.0.113.8", False),
        ("2001:db8::8", "2001:db8::8", False),
    ],
)
def test_address_families_are_parsed_canonically(address, canonical, loopback):
    assert canonical_ip(address) == canonical
    assert is_loopback_address(address) is loopback


@pytest.mark.parametrize("address", ["localhost", "127.0.0.1 ", "fe80::1%3", "bad", "", "1.2.3.999"])
def test_ambiguous_or_malformed_peer_addresses_fail_closed(address):
    with pytest.raises(TransportConfigurationError):
        normalise_ip(address)


def test_access_control_uses_validated_loopback_not_string_prefix(monkeypatch):
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "local")
    assert is_local_client("127.0.0.1")
    assert is_local_client("::ffff:127.0.0.1")
    assert not is_local_client("127.attacker.example")
    assert not decide_access(
        method="GET", path="/health", client_host="203.0.113.8",
        headers={"X-Forwarded-For": "127.0.0.1"},
    ).allowed


@pytest.mark.parametrize("header", ["X-Forwarded-For", "Forwarded", "X-Real-IP", "CF-Connecting-IP"])
def test_untrusted_forwarding_headers_are_ignored_and_evidenced(header):
    value = "for=127.0.0.1" if header == "Forwarded" else "127.0.0.1"
    result = evaluate_transport(
        socket_peer="127.0.0.1", headers=[(header, value)],
        configuration=local_config(),
    )
    assert result.allowed
    assert result.reason == "untrusted_forwarding_header_ignored"
    assert result.asserted_client_identity is None
    assert result.evidence_event == "untrusted_forwarding_header"


def test_remote_peer_cannot_use_forged_forwarding_to_bypass_plaintext_policy():
    result = evaluate_transport(
        socket_peer="203.0.113.8", headers={"X-Forwarded-For": "127.0.0.1"},
        configuration=local_config(),
    )
    assert not result.allowed
    assert result.reason == "plaintext_remote_attempt"


def test_trusted_immediate_proxy_tracks_all_transport_identities():
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[
            ("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"),
            ("X-Forwarded-For", "198.51.100.9"),
        ],
        configuration=proxy_config(),
        secure_transport=True,
    )
    assert result.allowed
    assert result.socket_peer == "10.0.0.2"
    assert result.trusted_proxy_identity == "desktop-proxy-1"
    assert result.asserted_client_identity == "198.51.100.9"
    assert result.forwarding_chain == ("198.51.100.9",)


def test_proxy_asserted_localhost_never_grants_local_access(monkeypatch):
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[
            ("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"),
            ("X-Forwarded-For", "127.0.0.1"),
        ],
        configuration=proxy_config(),
        secure_transport=True,
    )
    assert result.asserted_client_identity == "127.0.0.1"
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "local")
    assert not decide_access(
        method="GET", path="/health", client_host=result.socket_peer, headers={},
    ).allowed


def test_multiple_trusted_forwarding_hops_are_accepted():
    configuration = proxy_config(trusted_proxy_addresses=("10.0.0.2", "10.0.0.3"))
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[
            ("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"),
            ("X-Forwarded-For", "198.51.100.9, 10.0.0.3"),
        ],
        configuration=configuration,
        secure_transport=True,
    )
    assert result.allowed
    assert result.forwarding_chain == ("198.51.100.9", "10.0.0.3")


def test_mixed_trusted_and_untrusted_proxy_chain_is_denied():
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[
            ("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"),
            ("X-Forwarded-For", "198.51.100.9, 10.0.0.99"),
        ],
        configuration=proxy_config(),
        secure_transport=True,
    )
    assert not result.allowed
    assert result.reason == "proxy_trust_failure"


def test_too_many_forwarding_hops_are_denied():
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[
            ("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"),
            ("X-Forwarded-For", "198.51.100.1, 10.0.0.3"),
        ],
        configuration=proxy_config(maximum_forward_hops=1),
        secure_transport=True,
    )
    assert not result.allowed
    assert result.reason == "malformed_forwarding_chain"


@pytest.mark.parametrize(
    "headers",
    [
        [("X-Forwarded-For", "not-an-ip")],
        [("Forwarded", "proto=https")],
        [("Forwarded", "for=unknown")],
        [("X-Forwarded-For", "198.51.100.1,,10.0.0.3")],
    ],
)
def test_malformed_forwarding_chains_are_denied_from_trusted_proxy(headers):
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"), *headers],
        configuration=proxy_config(),
        secure_transport=True,
    )
    assert not result.allowed
    assert result.reason == "malformed_forwarding_chain"


@pytest.mark.parametrize(
    "headers",
    [
        [("X-Forwarded-For", "198.51.100.1"), ("x-forwarded-for", "198.51.100.2")],
        [("Forwarded", "for=198.51.100.1"), ("X-Real-IP", "198.51.100.1")],
    ],
)
def test_duplicate_or_ambiguous_forwarding_headers_are_denied(headers):
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"), *headers],
        configuration=proxy_config(),
        secure_transport=True,
    )
    assert not result.allowed
    assert result.reason == "malformed_forwarding_chain"


def test_forwarded_header_handles_whitespace_case_and_ipv6():
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[
            ("X-SBP-LEX-PROXY-IDENTITY", "desktop-proxy-1"),
            ("FoRwArDeD", ' for="[2001:db8::9]"; proto=https '),
        ],
        configuration=proxy_config(),
        secure_transport=True,
    )
    assert result.allowed
    assert result.asserted_client_identity == "2001:db8::9"


def test_unknown_immediate_proxy_is_not_treated_as_trusted():
    result = evaluate_transport(
        socket_peer="127.0.0.1",
        headers=[
            ("X-SBP-LEX-Proxy-Identity", "desktop-proxy-1"),
            ("X-Forwarded-For", "198.51.100.1"),
        ],
        configuration=proxy_config(),
    )
    assert result.allowed
    assert result.trusted_proxy_identity is None
    assert result.asserted_client_identity is None


def test_trusted_proxy_with_wrong_identity_is_denied():
    result = evaluate_transport(
        socket_peer="10.0.0.2",
        headers=[
            ("X-SBP-LEX-Proxy-Identity", "wrong-proxy"),
            ("X-Forwarded-For", "198.51.100.1"),
        ],
        configuration=proxy_config(),
    )
    assert not result.allowed
    assert result.reason == "proxy_trust_failure"


@pytest.mark.parametrize(
    "environment,reason",
    [
        ({"SBP_LEX_PROXY_MODE": ""}, "blank"),
        ({"SBP_LEX_PROXY_MODE": "trusted"}, "trusted_proxy_set_empty"),
        ({"SBP_LEX_PROXY_MODE": "disabled", "SBP_LEX_TRUSTED_PROXY_ADDRESSES": "127.0.0.1"}, "contradictory"),
        ({"SBP_LEX_PROXY_MODE": "trusted", "SBP_LEX_TRUSTED_PROXY_ADDRESSES": "*", "SBP_LEX_REQUIRED_PROXY_IDENTITY": "p"}, "malformed"),
        ({"SBP_LEX_PROXY_MODE": "trusted", "SBP_LEX_TRUSTED_PROXY_ADDRESSES": "0.0.0.0", "SBP_LEX_REQUIRED_PROXY_IDENTITY": "p"}, "wildcard"),
        ({"SBP_LEX_PROXY_MODE": "trusted", "SBP_LEX_TRUSTED_PROXY_NETWORKS": "0.0.0.0/0", "SBP_LEX_REQUIRED_PROXY_IDENTITY": "p"}, "overbroad"),
        ({"SBP_LEX_PROXY_MODE": "trusted", "SBP_LEX_TRUSTED_PROXY_NETWORKS": "10.0.0.1/24", "SBP_LEX_REQUIRED_PROXY_IDENTITY": "p"}, "invalid_trusted_proxy_cidr"),
    ],
)
def test_invalid_proxy_configuration_fails_closed(environment, reason):
    with pytest.raises(TransportConfigurationError, match=reason):
        load_transport_configuration(environment)


def test_valid_exact_and_bounded_network_proxy_configuration():
    configuration = load_transport_configuration({
        "SBP_LEX_PROXY_MODE": "trusted",
        "SBP_LEX_TRUSTED_PROXY_ADDRESSES": "127.0.0.1,::1",
        "SBP_LEX_TRUSTED_PROXY_NETWORKS": "10.0.0.0/24,fd00::/64",
        "SBP_LEX_REQUIRED_PROXY_IDENTITY": "desktop.proxy",
        "SBP_LEX_MAX_FORWARD_HOPS": "4",
    })
    assert configuration.proxy_enabled
    assert configuration.maximum_forward_hops == 4


@pytest.mark.parametrize("host", ["0.0.0.0", "::"])
def test_local_mode_wildcard_bind_is_denied(host):
    with pytest.raises(TransportConfigurationError, match="wildcard"):
        validate_bind_policy(
            security_mode="local", bind_host=host, configuration=local_config(),
            authentication_configured=True,
        )


def test_local_mode_non_loopback_bind_is_denied():
    with pytest.raises(TransportConfigurationError, match="non_loopback"):
        validate_bind_policy(
            security_mode="local", bind_host="192.0.2.10", configuration=local_config(),
            authentication_configured=True,
        )


def test_local_mode_ipv4_and_ipv6_loopback_bind_are_allowed():
    assert validate_bind_policy(
        security_mode="local", bind_host="127.0.0.1", configuration=local_config(),
        authentication_configured=True,
    ) == "127.0.0.1"
    assert validate_bind_policy(
        security_mode="local", bind_host="::1", configuration=local_config(),
        authentication_configured=True,
    ) == "::1"


def test_hostname_bind_is_denied_as_ambiguous():
    with pytest.raises(TransportConfigurationError, match="ambiguous_hostname"):
        validate_bind_policy(
            security_mode="local", bind_host="localhost", configuration=local_config(),
            authentication_configured=True,
        )


def test_private_mode_requires_configured_authentication():
    configuration = local_config(approved_bind_address="127.0.0.1")
    with pytest.raises(TransportConfigurationError, match="authentication_not_configured"):
        validate_bind_policy(
            security_mode="private", bind_host="127.0.0.1", configuration=configuration,
            authentication_configured=False,
        )


def test_private_mode_requires_exact_approved_bind_address():
    configuration = tls_config(approved_bind_address="192.0.2.10")
    with pytest.raises(TransportConfigurationError, match="mismatch"):
        validate_bind_policy(
            security_mode="private", bind_host="192.0.2.11", configuration=configuration,
            authentication_configured=True,
        )


def test_private_plaintext_remote_bind_is_denied():
    configuration = local_config(approved_bind_address="192.0.2.10")
    with pytest.raises(TransportConfigurationError, match="plaintext_remote"):
        validate_bind_policy(
            security_mode="private", bind_host="192.0.2.10", configuration=configuration,
            authentication_configured=True,
        )


def test_invalid_bind_fails_before_security_store_or_socket_initialization(monkeypatch):
    reset_transport_configuration_for_tests()
    TRANSPORT_SECURITY_EVENTS.clear()
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "local")
    monkeypatch.setattr(server_module, "ensure_measured_startup", lambda: {"status": "MEASURED_STARTUP_APPROVED"})
    reached = []
    monkeypatch.setattr(
        server_module, "initialize_security_state_store",
        lambda **kwargs: reached.append(kwargs),
    )
    with pytest.raises(TransportConfigurationError, match="wildcard_bind"):
        server_module.run_server(host="0.0.0.0", port=0)
    assert reached == []
    assert TRANSPORT_SECURITY_EVENTS.snapshot()[-1]["event_id"] == "bind_policy_failure"


def test_private_missing_authentication_fails_before_bind(monkeypatch):
    reset_transport_configuration_for_tests()
    TRANSPORT_SECURITY_EVENTS.clear()
    monkeypatch.setenv("SBP_LEX_API_SECURITY_MODE", "private")
    monkeypatch.setattr(server_module, "ensure_measured_startup", lambda: {"status": "MEASURED_STARTUP_APPROVED"})
    monkeypatch.setenv("SBP_LEX_BIND_ADDRESS", "127.0.0.1")
    monkeypatch.delenv("SBP_LEX_API_TOKEN", raising=False)
    monkeypatch.delenv("SBP_LEX_API_PRINCIPALS", raising=False)
    reached = []
    monkeypatch.setattr(
        server_module, "initialize_security_state_store",
        lambda **kwargs: reached.append(kwargs),
    )
    with pytest.raises(TransportConfigurationError, match="authentication_not_configured"):
        server_module.run_server(host="127.0.0.1", port=0)
    assert reached == []


def test_local_private_profile_is_default_and_remote_production_is_disabled():
    assert load_transport_configuration({}).profile == LOCAL_PRIVATE
    with pytest.raises(TransportConfigurationError, match="remote_production"):
        load_transport_configuration({
            "SBP_LEX_TRANSPORT_PROFILE": REMOTE_PRODUCTION_DISABLED,
            "SBP_LEX_ALLOWED_TRANSPORT_PROFILES": REMOTE_PRODUCTION_DISABLED,
        })


@pytest.mark.parametrize("profile", [PILOT_PRIVATE_TLS, PILOT_PRIVATE_MTLS])
def test_remote_profiles_require_explicit_activation(profile):
    with pytest.raises(TransportConfigurationError, match="explicitly_enabled"):
        load_transport_configuration({
            "SBP_LEX_TRANSPORT_PROFILE": profile,
            "SBP_LEX_ALLOWED_TRANSPORT_PROFILES": profile,
        })


def test_tls_profile_configuration_is_strict_but_inactive_by_default(tmp_path):
    certificate_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    certificate_path.write_text("test-double", encoding="utf-8")
    key_path.write_text("test-double", encoding="utf-8")
    configuration = load_transport_configuration({
        "SBP_LEX_TRANSPORT_PROFILE": PILOT_PRIVATE_TLS,
        "SBP_LEX_ALLOWED_TRANSPORT_PROFILES": PILOT_PRIVATE_TLS,
        "SBP_LEX_ENABLE_REMOTE_TRANSPORT": "1",
        "SBP_LEX_TLS_ENABLED": "1",
        "SBP_LEX_TLS_CERT_FILE": str(certificate_path),
        "SBP_LEX_TLS_KEY_FILE": str(key_path),
    })
    assert configuration.profile == PILOT_PRIVATE_TLS
    assert configuration.tls_enabled


def test_mtls_profile_requires_ca_and_service_identity(tmp_path):
    certificate_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    certificate_path.write_text("test-double", encoding="utf-8")
    key_path.write_text("test-double", encoding="utf-8")
    with pytest.raises(TransportConfigurationError, match="mtls_identity"):
        load_transport_configuration({
            "SBP_LEX_TRANSPORT_PROFILE": PILOT_PRIVATE_MTLS,
            "SBP_LEX_ALLOWED_TRANSPORT_PROFILES": PILOT_PRIVATE_MTLS,
            "SBP_LEX_ENABLE_REMOTE_TRANSPORT": "1",
            "SBP_LEX_TLS_ENABLED": "1",
            "SBP_LEX_TLS_CERT_FILE": str(certificate_path),
            "SBP_LEX_TLS_KEY_FILE": str(key_path),
        })


def test_plaintext_remote_attempt_is_denied_for_tls_profile():
    result = evaluate_transport(
        socket_peer="203.0.113.8", headers={}, configuration=tls_config(),
        secure_transport=False,
    )
    assert not result.allowed
    assert result.reason == "plaintext_remote_attempt"


def test_secure_remote_tls_transport_is_allowed_but_grants_no_scope():
    result = evaluate_transport(
        socket_peer="203.0.113.8", headers={}, configuration=tls_config(),
        secure_transport=True,
    )
    assert result.allowed
    assert result.transport_device_identity is None
    assert not transport_identity_grants_api_scope(None, "runtime:traverse")


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ({"not_after": NOW - timedelta(seconds=1)}, "certificate_expired"),
        ({"purpose": "operator"}, "certificate_wrong_purpose"),
        ({"service_identity": "other-service"}, "certificate_wrong_service_identity"),
        ({"revoked": True}, "certificate_revoked"),
    ],
)
def test_mtls_certificate_identity_failures(mutation, reason):
    valid, observed, identity = validate_certificate_identity(
        certificate(**mutation), tls_config(PILOT_PRIVATE_MTLS), now=NOW,
    )
    assert not valid
    assert observed == reason
    assert identity is None


def test_valid_mtls_certificate_creates_only_transport_device_identity():
    valid, reason, identity = validate_certificate_identity(
        certificate(), tls_config(PILOT_PRIVATE_MTLS), now=NOW,
    )
    assert valid and reason == "certificate_identity_valid"
    assert identity and identity != FINGERPRINT
    for scope in ("runtime:traverse", "runtime:replay", "connector:submit", "administration"):
        assert not transport_identity_grants_api_scope(identity, scope)


def test_configured_certificate_fingerprint_denylist_is_enforced():
    configuration = tls_config(
        PILOT_PRIVATE_MTLS,
        revoked_certificate_fingerprints=frozenset({FINGERPRINT}),
    )
    valid, reason, identity = validate_certificate_identity(
        certificate(), configuration, now=NOW,
    )
    assert not valid and reason == "certificate_revoked" and identity is None


def test_connector_and_viewer_certificates_cannot_request_operator_or_mutation_scope():
    assert not transport_identity_grants_api_scope("connector-certificate", "runtime:traverse")
    assert not transport_identity_grants_api_scope("viewer-certificate", "connector:submit")


def test_header_cardinality_attack_fails_closed():
    headers = [(f"X-Attacker-{number}", "value") for number in range(129)]
    result = evaluate_transport(
        socket_peer="127.0.0.1", headers=headers, configuration=local_config(),
    )
    assert not result.allowed
    assert result.reason == "transport_header_cardinality_exceeded"


def test_transport_payload_does_not_leak_forwarding_header_or_proxy_secret():
    secret = "raw-secret-that-must-not-leak"
    result = evaluate_transport(
        socket_peer="127.0.0.1",
        headers={"X-Forwarded-For": secret, "Authorization": f"Bearer {secret}"},
        configuration=local_config(),
    )
    assert secret not in str(result.as_payload())


def test_transport_denial_cannot_create_partial_canonical_state():
    result = evaluate_transport(
        socket_peer="203.0.113.8", headers={}, configuration=local_config(),
    )
    canonical_state = []
    if result.allowed:
        canonical_state.append("unexpected")
    assert not result.allowed
    assert canonical_state == []


def test_invalid_peer_never_converts_to_allow():
    result = evaluate_transport(
        socket_peer="attacker.invalid", headers={}, configuration=local_config(),
    )
    assert not result.allowed
    assert result.reason == "unexpected_peer_identity"


def test_transport_security_events_are_bounded_and_secret_free():
    TRANSPORT_SECURITY_EVENTS.clear()
    secret = "raw-reusable-secret"
    for number in range(300):
        TRANSPORT_SECURITY_EVENTS.record(
            "proxy_trust_failure", reason="proxy_trust_failure",
            evidence={"attacker_value": f"{secret}-{number}"},
        )
    events = TRANSPORT_SECURITY_EVENTS.snapshot()
    assert len(events) == 256
    assert secret not in str(events)
    assert events[0]["sequence"] == 45
