from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from sbp_lex.security.pqc import generate_digest

LOCAL_PRIVATE = "LOCAL_PRIVATE"
PILOT_PRIVATE_TLS = "PILOT_PRIVATE_TLS"
PILOT_PRIVATE_MTLS = "PILOT_PRIVATE_MTLS"
REMOTE_PRODUCTION_DISABLED = "REMOTE_PRODUCTION_DISABLED"
TRANSPORT_PROFILES = frozenset({
    LOCAL_PRIVATE, PILOT_PRIVATE_TLS, PILOT_PRIVATE_MTLS,
    REMOTE_PRODUCTION_DISABLED,
})
FORWARDING_HEADERS = frozenset({
    "forwarded", "x-forwarded-for", "x-real-ip", "x-client-ip",
    "cf-connecting-ip", "true-client-ip",
})
PROXY_IDENTITY_HEADER = "x-sbp-lex-proxy-identity"
MAX_HEADER_COUNT = 128
MAX_PROXY_ADDRESSES = 64
MAX_PROXY_NETWORKS = 32
MAX_FORWARD_HOPS = 10
MAX_REVOKED_FINGERPRINTS = 128
MAX_TRANSPORT_SECURITY_EVENTS = 256
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
_HEX_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TRANSPORT_SECURITY_EVENT_IDS = frozenset({
    "untrusted_forwarding_header", "malformed_forwarding_chain",
    "proxy_trust_failure", "bind_policy_failure", "transport_profile_failure",
    "certificate_identity_mismatch", "plaintext_remote_attempt",
    "unexpected_peer_identity",
})


class TransportConfigurationError(RuntimeError):
    pass


class TransportSecurityEventBuffer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_TRANSPORT_SECURITY_EVENTS)
        self._sequence = 0

    def record(self, event_id: str, *, reason: str, evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
        safe_event_id = event_id if event_id in TRANSPORT_SECURITY_EVENT_IDS else "transport_profile_failure"
        safe_evidence = {
            str(key)[:64]: generate_digest({"domain": "H3_TRANSPORT_EVENT", "value": value})
            for key, value in sorted(dict(evidence or {}).items())[:16]
        }
        with self._lock:
            self._sequence += 1
            event = {
                "sequence": self._sequence,
                "event_id": safe_event_id,
                "reason": str(reason)[:128],
                "evidence": safe_evidence,
            }
            self._events.append(event)
            return dict(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._events]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._sequence = 0


TRANSPORT_SECURITY_EVENTS = TransportSecurityEventBuffer()


@dataclass(frozen=True)
class TransportConfiguration:
    profile: str = LOCAL_PRIVATE
    allowed_profiles: tuple[str, ...] = (LOCAL_PRIVATE,)
    proxy_enabled: bool = False
    trusted_proxy_addresses: tuple[str, ...] = ()
    trusted_proxy_networks: tuple[str, ...] = ()
    maximum_forward_hops: int = 3
    required_proxy_identity: str | None = None
    approved_bind_address: str | None = None
    remote_transport_enabled: bool = False
    tls_enabled: bool = False
    tls_certificate_file: Path | None = None
    tls_private_key_file: Path | None = None
    tls_ca_file: Path | None = None
    required_service_identity: str | None = None
    required_certificate_purpose: str = "desktop-v1-transport"
    revoked_certificate_fingerprints: frozenset[str] = frozenset()


@dataclass(frozen=True)
class TransportDecision:
    allowed: bool
    status: int
    reason: str
    socket_peer: str
    trusted_proxy_identity: str | None
    asserted_client_identity: str | None
    forwarding_chain: tuple[str, ...]
    transport_profile: str
    secure_transport: bool
    transport_device_identity: str | None = None
    evidence_event: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "socket_peer": self.socket_peer,
            "trusted_proxy_identity": self.trusted_proxy_identity,
            "asserted_client_identity": self.asserted_client_identity,
            "forwarding_chain": list(self.forwarding_chain),
            "transport_profile": self.transport_profile,
            "secure_transport": self.secure_transport,
            "transport_device_identity": self.transport_device_identity,
        }


def _explicit(source: Mapping[str, str], name: str) -> str | None:
    if name not in source:
        return None
    value = source[name]
    if not isinstance(value, str) or not value.strip():
        raise TransportConfigurationError(f"invalid_transport_configuration:{name}:blank")
    return value.strip()


def _flag(source: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = _explicit(source, name)
    if raw is None:
        return default
    if raw not in {"0", "1"}:
        raise TransportConfigurationError(f"invalid_transport_configuration:{name}:boolean")
    return raw == "1"


def _bounded_int(
    source: Mapping[str, str], name: str, default: int, maximum: int,
) -> int:
    raw = _explicit(source, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise TransportConfigurationError(
            f"invalid_transport_configuration:{name}:non_numeric"
        ) from exc
    if value <= 0 or value > maximum:
        raise TransportConfigurationError(
            f"invalid_transport_configuration:{name}:out_of_range"
        )
    return value


def normalise_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise TransportConfigurationError("malformed_transport_address")
    if "%" in value:
        raise TransportConfigurationError("ambiguous_zone_identifier")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TransportConfigurationError("malformed_transport_address") from exc
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def canonical_ip(value: str) -> str:
    return str(normalise_ip(value))


def is_loopback_address(value: str) -> bool:
    try:
        return normalise_ip(value).is_loopback
    except TransportConfigurationError:
        return False


def _split_csv(raw: str | None, *, maximum: int, name: str) -> list[str]:
    if raw is None:
        return []
    values = [item.strip() for item in raw.split(",")]
    if not values or any(not item for item in values) or len(values) > maximum:
        raise TransportConfigurationError(f"invalid_transport_configuration:{name}:cardinality")
    if len(set(values)) != len(values):
        raise TransportConfigurationError(f"invalid_transport_configuration:{name}:duplicate")
    return values


def _proxy_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if value in {"*", "0.0.0.0/0", "::/0"}:
        raise TransportConfigurationError("overbroad_trusted_proxy_network")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise TransportConfigurationError("invalid_trusted_proxy_cidr") from exc
    minimum = 24 if network.version == 4 else 64
    if network.prefixlen < minimum or network.network_address.is_unspecified or network.network_address.is_multicast:
        raise TransportConfigurationError("overbroad_trusted_proxy_network")
    return network


def _proxy_address(value: str) -> str:
    address = normalise_ip(value)
    if address.is_unspecified or address.is_multicast:
        raise TransportConfigurationError("wildcard_trusted_proxy_address")
    return str(address)


def _path(source: Mapping[str, str], name: str) -> Path | None:
    raw = _explicit(source, name)
    if raw is None:
        return None
    if len(raw) > 260 or "\0" in raw:
        raise TransportConfigurationError(f"invalid_transport_configuration:{name}:path")
    path = Path(raw).expanduser().resolve(strict=False)
    if path.suffix.lower() not in {".pem", ".crt", ".key"}:
        raise TransportConfigurationError(f"invalid_transport_configuration:{name}:extension")
    if not path.is_file():
        raise TransportConfigurationError(f"invalid_transport_configuration:{name}:missing")
    return path


def load_transport_configuration(
    environ: Mapping[str, str] | None = None,
) -> TransportConfiguration:
    source = os.environ if environ is None else environ
    profile = (_explicit(source, "SBP_LEX_TRANSPORT_PROFILE") or LOCAL_PRIVATE).upper()
    if profile not in TRANSPORT_PROFILES:
        raise TransportConfigurationError("invalid_transport_profile")
    allowed_raw = _explicit(source, "SBP_LEX_ALLOWED_TRANSPORT_PROFILES")
    allowed = tuple(item.upper() for item in _split_csv(
        allowed_raw or LOCAL_PRIVATE, maximum=4,
        name="SBP_LEX_ALLOWED_TRANSPORT_PROFILES",
    ))
    if any(item not in TRANSPORT_PROFILES for item in allowed) or profile not in allowed:
        raise TransportConfigurationError("transport_profile_not_allowed")

    proxy_mode = (_explicit(source, "SBP_LEX_PROXY_MODE") or "disabled").lower()
    if proxy_mode not in {"disabled", "trusted"}:
        raise TransportConfigurationError("invalid_proxy_mode")
    proxy_enabled = proxy_mode == "trusted"
    address_raw = _explicit(source, "SBP_LEX_TRUSTED_PROXY_ADDRESSES")
    network_raw = _explicit(source, "SBP_LEX_TRUSTED_PROXY_NETWORKS")
    identity = _explicit(source, "SBP_LEX_REQUIRED_PROXY_IDENTITY")
    max_hops_explicit = "SBP_LEX_MAX_FORWARD_HOPS" in source
    max_hops = _bounded_int(source, "SBP_LEX_MAX_FORWARD_HOPS", 3, MAX_FORWARD_HOPS)
    if not proxy_enabled and any((address_raw, network_raw, identity, max_hops_explicit)):
        raise TransportConfigurationError("contradictory_disabled_proxy_configuration")
    addresses = tuple(sorted({_proxy_address(item) for item in _split_csv(
        address_raw, maximum=MAX_PROXY_ADDRESSES,
        name="SBP_LEX_TRUSTED_PROXY_ADDRESSES",
    )}))
    networks = tuple(sorted(str(_proxy_network(item)) for item in _split_csv(
        network_raw, maximum=MAX_PROXY_NETWORKS,
        name="SBP_LEX_TRUSTED_PROXY_NETWORKS",
    )))
    if proxy_enabled:
        if not addresses and not networks:
            raise TransportConfigurationError("trusted_proxy_set_empty")
        if identity is None or not _IDENTITY_RE.fullmatch(identity):
            raise TransportConfigurationError("required_proxy_identity_invalid")

    remote = _flag(source, "SBP_LEX_ENABLE_REMOTE_TRANSPORT", False)
    tls_enabled = _flag(source, "SBP_LEX_TLS_ENABLED", False)
    bind_address = _explicit(source, "SBP_LEX_BIND_ADDRESS")
    service_identity = _explicit(source, "SBP_LEX_TLS_REQUIRED_SERVICE_IDENTITY")
    purpose = _explicit(source, "SBP_LEX_TLS_REQUIRED_CERTIFICATE_PURPOSE") or "desktop-v1-transport"
    if not _IDENTITY_RE.fullmatch(purpose) or (service_identity and not _IDENTITY_RE.fullmatch(service_identity)):
        raise TransportConfigurationError("certificate_identity_configuration_invalid")
    revoked = frozenset(item.lower() for item in _split_csv(
        _explicit(source, "SBP_LEX_REVOKED_CERTIFICATE_FINGERPRINTS"),
        maximum=MAX_REVOKED_FINGERPRINTS,
        name="SBP_LEX_REVOKED_CERTIFICATE_FINGERPRINTS",
    ))
    if any(not _HEX_DIGEST_RE.fullmatch(item) for item in revoked):
        raise TransportConfigurationError("revoked_certificate_fingerprint_invalid")

    certificate = key = ca = None
    if profile == REMOTE_PRODUCTION_DISABLED:
        raise TransportConfigurationError("remote_production_transport_disabled")
    if profile == LOCAL_PRIVATE:
        tls_names = {
            "SBP_LEX_TLS_CERT_FILE", "SBP_LEX_TLS_KEY_FILE", "SBP_LEX_TLS_CA_FILE",
            "SBP_LEX_TLS_REQUIRED_SERVICE_IDENTITY",
            "SBP_LEX_REVOKED_CERTIFICATE_FINGERPRINTS",
        }
        if remote or tls_enabled or any(name in source for name in tls_names):
            raise TransportConfigurationError("contradictory_local_transport_configuration")
    else:
        if not remote or not tls_enabled:
            raise TransportConfigurationError("remote_tls_profile_not_explicitly_enabled")
        certificate = _path(source, "SBP_LEX_TLS_CERT_FILE")
        key = _path(source, "SBP_LEX_TLS_KEY_FILE")
        if certificate == key:
            raise TransportConfigurationError("tls_certificate_key_path_collision")
        if profile == PILOT_PRIVATE_MTLS:
            ca = _path(source, "SBP_LEX_TLS_CA_FILE")
            if ca is None or service_identity is None:
                raise TransportConfigurationError("mtls_identity_configuration_required")

    return TransportConfiguration(
        profile=profile, allowed_profiles=allowed, proxy_enabled=proxy_enabled,
        trusted_proxy_addresses=addresses, trusted_proxy_networks=networks,
        maximum_forward_hops=max_hops, required_proxy_identity=identity,
        approved_bind_address=bind_address, remote_transport_enabled=remote,
        tls_enabled=tls_enabled, tls_certificate_file=certificate,
        tls_private_key_file=key, tls_ca_file=ca,
        required_service_identity=service_identity,
        required_certificate_purpose=purpose,
        revoked_certificate_fingerprints=revoked,
    )


def _trusted(peer: ipaddress._BaseAddress, config: TransportConfiguration) -> bool:
    if not config.proxy_enabled:
        return False
    if str(peer) in config.trusted_proxy_addresses:
        return True
    return any(peer in ipaddress.ip_network(item) for item in config.trusted_proxy_networks)


def _header_pairs(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
) -> list[tuple[str, str]]:
    items: Iterable[tuple[str, str]] = headers.items() if isinstance(headers, Mapping) else headers
    result: list[tuple[str, str]] = []
    for key, value in items:
        if not isinstance(key, str) or not isinstance(value, str):
            raise TransportConfigurationError("malformed_transport_header")
        result.append((key.strip().lower(), value.strip()))
    return result


def _address_token(value: str) -> str:
    token = value.strip().strip('"')
    if not token or token.lower() == "unknown" or token.startswith("_") or "%" in token:
        raise TransportConfigurationError("malformed_forwarding_chain")
    if token.startswith("["):
        closing = token.find("]")
        if closing < 0 or token[closing + 1:] not in {""} and not token[closing + 1:].startswith(":"):
            raise TransportConfigurationError("malformed_forwarding_chain")
        token = token[1:closing]
    elif token.count(":") == 1 and "." in token:
        address, port = token.rsplit(":", 1)
        if not port.isdigit():
            raise TransportConfigurationError("malformed_forwarding_chain")
        token = address
    return canonical_ip(token)


def _forwarding_chain(name: str, value: str) -> tuple[str, ...]:
    if not value:
        raise TransportConfigurationError("malformed_forwarding_chain")
    if name == "forwarded":
        values: list[str] = []
        for element in value.split(","):
            parameters = [part.strip() for part in element.split(";") if part.strip()]
            candidates = [part.split("=", 1)[1] for part in parameters if part.lower().startswith("for=")]
            if len(candidates) != 1:
                raise TransportConfigurationError("malformed_forwarding_chain")
            values.append(_address_token(candidates[0]))
        return tuple(values)
    return tuple(_address_token(item) for item in value.split(","))


def _deny(
    reason: str, peer: str, config: TransportConfiguration, *, secure: bool,
    event: str, proxy_identity: str | None = None,
) -> TransportDecision:
    return TransportDecision(
        False, 403 if reason not in {"malformed_forwarding_chain", "transport_header_cardinality_exceeded"} else 400,
        reason, peer, proxy_identity, None, (), config.profile, secure,
        evidence_event=event,
    )


def evaluate_transport(
    *, socket_peer: str,
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
    configuration: TransportConfiguration,
    secure_transport: bool = False,
    certificate: Mapping[str, Any] | None = None,
) -> TransportDecision:
    try:
        peer_ip = normalise_ip(socket_peer)
        pairs = _header_pairs(headers)
    except TransportConfigurationError:
        return _deny(
            "unexpected_peer_identity", str(socket_peer), configuration,
            secure=secure_transport, event="unexpected_peer_identity",
        )
    peer = str(peer_ip)
    if peer_ip.is_unspecified or peer_ip.is_multicast:
        return _deny(
            "unexpected_peer_identity", peer, configuration,
            secure=secure_transport, event="unexpected_peer_identity",
        )
    if len(pairs) > MAX_HEADER_COUNT:
        return _deny(
            "transport_header_cardinality_exceeded", peer, configuration,
            secure=secure_transport, event="malformed_forwarding_chain",
        )
    forwarding = [(name, value) for name, value in pairs if name in FORWARDING_HEADERS]
    names = [name for name, _ in forwarding]
    if len(names) != len(set(names)) or len(set(names)) > 1:
        return _deny(
            "malformed_forwarding_chain", peer, configuration,
            secure=secure_transport, event="malformed_forwarding_chain",
        )

    peer_trusted = _trusted(peer_ip, configuration)
    ignored_forwarding = bool(forwarding and not peer_trusted)
    if ignored_forwarding:
        forwarding = []

    proxy_identity = None
    chain: tuple[str, ...] = ()
    asserted = None
    if peer_trusted:
        identity_values = [value for name, value in pairs if name == PROXY_IDENTITY_HEADER]
        if len(identity_values) != 1 or identity_values[0] != configuration.required_proxy_identity:
            return _deny(
                "proxy_trust_failure", peer, configuration, secure=secure_transport,
                event="proxy_trust_failure",
            )
        proxy_identity = identity_values[0]
        if forwarding:
            try:
                chain = _forwarding_chain(*forwarding[0])
            except TransportConfigurationError:
                return _deny(
                    "malformed_forwarding_chain", peer, configuration,
                    secure=secure_transport, event="malformed_forwarding_chain",
                    proxy_identity=proxy_identity,
                )
            if not chain or len(chain) > configuration.maximum_forward_hops:
                return _deny(
                    "malformed_forwarding_chain", peer, configuration,
                    secure=secure_transport, event="malformed_forwarding_chain",
                    proxy_identity=proxy_identity,
                )
            try:
                parsed_chain = [normalise_ip(item) for item in chain]
                if any(item.is_unspecified or item.is_multicast for item in parsed_chain):
                    raise TransportConfigurationError("malformed_forwarding_chain")
                intermediate = parsed_chain[1:]
            except TransportConfigurationError:
                return _deny(
                    "malformed_forwarding_chain", peer, configuration,
                    secure=secure_transport, event="malformed_forwarding_chain",
                    proxy_identity=proxy_identity,
                )
            if any(not _trusted(item, configuration) for item in intermediate):
                return _deny(
                    "proxy_trust_failure", peer, configuration, secure=secure_transport,
                    event="proxy_trust_failure", proxy_identity=proxy_identity,
                )
            asserted = chain[0]

    remote_peer = not peer_ip.is_loopback
    if remote_peer and (configuration.profile == LOCAL_PRIVATE or not secure_transport):
        return _deny(
            "plaintext_remote_attempt", peer, configuration, secure=secure_transport,
            event="plaintext_remote_attempt", proxy_identity=proxy_identity,
        )
    transport_identity = None
    if configuration.profile == PILOT_PRIVATE_MTLS:
        valid, reason, transport_identity = validate_certificate_identity(certificate, configuration)
        if not valid:
            return _deny(
                reason, peer, configuration, secure=secure_transport,
                event="certificate_identity_mismatch", proxy_identity=proxy_identity,
            )
    return TransportDecision(
        True, 200,
        "untrusted_forwarding_header_ignored" if ignored_forwarding else "transport_boundary_allowed",
        peer, proxy_identity, asserted,
        chain, configuration.profile, secure_transport, transport_identity,
        evidence_event="untrusted_forwarding_header" if ignored_forwarding else None,
    )


def validate_bind_policy(
    *, security_mode: str, bind_host: str, configuration: TransportConfiguration,
    authentication_configured: bool,
) -> str:
    if bind_host.lower() == "localhost":
        raise TransportConfigurationError("ambiguous_hostname_bind_denied")
    try:
        address = normalise_ip(bind_host)
    except TransportConfigurationError as exc:
        raise TransportConfigurationError("bind_address_must_be_ip_literal") from exc
    if address.is_unspecified:
        raise TransportConfigurationError("wildcard_bind_denied")
    canonical = str(address)
    if security_mode in {"local", "disabled"}:
        if not address.is_loopback:
            raise TransportConfigurationError("local_mode_non_loopback_bind_denied")
        if configuration.profile != LOCAL_PRIVATE:
            raise TransportConfigurationError("local_mode_transport_profile_invalid")
        return canonical
    if security_mode != "private":
        raise TransportConfigurationError("unknown_bind_security_mode")
    if not authentication_configured:
        raise TransportConfigurationError("private_mode_authentication_not_configured")
    if configuration.approved_bind_address is None:
        raise TransportConfigurationError("private_mode_bind_address_required")
    try:
        approved = canonical_ip(configuration.approved_bind_address)
    except TransportConfigurationError as exc:
        raise TransportConfigurationError("private_mode_bind_address_invalid") from exc
    if canonical != approved:
        raise TransportConfigurationError("private_mode_bind_address_mismatch")
    if not address.is_loopback and configuration.profile == LOCAL_PRIVATE:
        raise TransportConfigurationError("plaintext_remote_bind_denied")
    return canonical


def validate_certificate_identity(
    certificate: Mapping[str, Any] | None,
    configuration: TransportConfiguration,
    *, now: datetime | None = None,
) -> tuple[bool, str, str | None]:
    if not isinstance(certificate, Mapping):
        return False, "certificate_identity_mismatch", None
    fingerprint = certificate.get("fingerprint")
    if not isinstance(fingerprint, str) or not _HEX_DIGEST_RE.fullmatch(fingerprint):
        return False, "certificate_identity_mismatch", None
    fingerprint = fingerprint.lower()
    if certificate.get("revoked") is True or fingerprint in configuration.revoked_certificate_fingerprints:
        return False, "certificate_revoked", None
    expiry = certificate.get("not_after")
    try:
        if isinstance(expiry, str):
            expires = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        elif isinstance(expiry, datetime):
            expires = expiry
        else:
            raise ValueError
        if expires.tzinfo is None:
            raise ValueError
        if (now or datetime.now(timezone.utc)) >= expires.astimezone(timezone.utc):
            return False, "certificate_expired", None
    except (TypeError, ValueError):
        return False, "certificate_identity_mismatch", None
    if certificate.get("purpose") != configuration.required_certificate_purpose:
        return False, "certificate_wrong_purpose", None
    if certificate.get("service_identity") != configuration.required_service_identity:
        return False, "certificate_wrong_service_identity", None
    identity = generate_digest({
        "domain": "SBP_LEX_DESKTOP_V1_TRANSPORT_DEVICE_IDENTITY",
        "fingerprint": fingerprint,
        "service_identity": certificate.get("service_identity"),
    })
    return True, "certificate_identity_valid", identity


def transport_identity_grants_api_scope(
    transport_device_identity: str | None, requested_scope: str,
) -> bool:
    del transport_device_identity, requested_scope
    return False


def build_ssl_context(configuration: TransportConfiguration) -> ssl.SSLContext | None:
    if configuration.profile == LOCAL_PRIVATE:
        return None
    if not configuration.tls_enabled or not configuration.tls_certificate_file or not configuration.tls_private_key_file:
        raise TransportConfigurationError("tls_configuration_incomplete")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=str(configuration.tls_certificate_file),
        keyfile=str(configuration.tls_private_key_file),
    )
    if configuration.profile == PILOT_PRIVATE_MTLS:
        if not configuration.tls_ca_file:
            raise TransportConfigurationError("mtls_ca_required")
        context.load_verify_locations(cafile=str(configuration.tls_ca_file))
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def certificate_record_from_socket(connection: Any) -> Mapping[str, Any] | None:
    if not isinstance(connection, ssl.SSLSocket):
        return None
    der = connection.getpeercert(binary_form=True)
    if not der:
        return None
    record: dict[str, Any] = {"fingerprint": sha256(der).hexdigest(), "revoked": False}
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID

        certificate = x509.load_der_x509_certificate(der)
        record["not_after"] = certificate.not_valid_after_utc
        try:
            usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            record["purpose"] = "desktop-v1-transport" if ExtendedKeyUsageOID.CLIENT_AUTH in usage else "unsupported"
        except x509.ExtensionNotFound:
            record["purpose"] = "unsupported"
        try:
            names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            identities = [*names.get_values_for_type(x509.DNSName), *names.get_values_for_type(x509.UniformResourceIdentifier)]
            record["service_identity"] = identities[0] if len(identities) == 1 else None
        except x509.ExtensionNotFound:
            record["service_identity"] = None
    except Exception:
        return None
    return record


_ACTIVE_CONFIGURATION: TransportConfiguration | None = None


def initialize_transport_configuration() -> TransportConfiguration:
    global _ACTIVE_CONFIGURATION
    _ACTIVE_CONFIGURATION = load_transport_configuration()
    return _ACTIVE_CONFIGURATION


def active_transport_configuration() -> TransportConfiguration:
    global _ACTIVE_CONFIGURATION
    if _ACTIVE_CONFIGURATION is None:
        _ACTIVE_CONFIGURATION = load_transport_configuration()
    return _ACTIVE_CONFIGURATION


def reset_transport_configuration_for_tests() -> None:
    global _ACTIVE_CONFIGURATION
    _ACTIVE_CONFIGURATION = None
