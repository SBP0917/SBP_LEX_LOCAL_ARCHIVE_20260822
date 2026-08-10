from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import unicodedata
from base64 import b64decode, b64encode
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import (
    DIGEST_ALGORITHM,
    SIGNATURE_ALGORITHM,
    SYSTEM_ISSUER,
)
from sbp_lex.security.pqc_policy import (
    PQC_FAIL_CLOSED,
    PQC_POLICY_NAME,
    PQC_SIGNATURE_PRIMARY,
)
from sbp_lex.security.migration_profile import (
    CRYPTO_PROFILE_VERSION,
    VERIFICATION_POLICY_VERSION,
    CryptoProfileConfigurationError,
    active_crypto_profile_requirement,
    build_active_crypto_profile,
    crypto_profile_digest,
    legacy_archive_policy_is_approved,
    provider_version,
    validate_crypto_profile,
)
from sbp_lex.security.pqc_provider import (
    PQCProviderUnavailable,
    derive_signing_keypair,
    generate_signing_keypair,
    provider_available,
    provider_name,
    sign,
    verify,
)

PQC_SIGNATURE_VERSION = "PQC_01_PROVIDER_SIGNATURE_V3"
LEGACY_PQC_SIGNATURE_VERSION = "PQC_01_PROVIDER_SIGNATURE_V2"
SIGNING_SECRET_ENVIRONMENT_NAME = "SBP_LEX_SIGNING_SECRET"
TRUSTED_PUBLIC_KEY_ENVIRONMENT_NAME = "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY"
EXPECTED_SIGNER_FINGERPRINT_ENVIRONMENT_NAME = (
    "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT"
)
_SIGNING_SEED_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PROCESS_PRIVATE_KEY: bytes | None = None
_PROCESS_PUBLIC_KEY: bytes | None = None
_PROCESS_SEED_FINGERPRINT: str | None = None
_PROCESS_PROFILE_DIGEST: str | None = None


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("canonical_mapping_key_must_be_string")
            key = unicodedata.normalize("NFC", raw_key)
            if key in result:
                raise ValueError("canonical_key_collision_after_unicode_normalization")
            if _is_pqc_signature_envelope(value) and key in {"signature", "public_key"}:
                result[key] = f"{key.upper()}_PROVIDER_PROOF_PRESENT"
            else:
                result[key] = _canonicalize(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical_non_finite_number")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"canonical_unsupported_type:{type(value).__name__}")


def _is_pqc_signature_envelope(value: Mapping[str, Any]) -> bool:
    return (
        value.get("signature_version")
        in {PQC_SIGNATURE_VERSION, LEGACY_PQC_SIGNATURE_VERSION}
        and value.get("algorithm") == SIGNATURE_ALGORITHM
        and "signature" in value
        and "public_key" in value
    )


def canonical_json(data: Any) -> str:
    return json.dumps(
        _canonicalize(data),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def generate_digest(data: Any) -> str:
    if DIGEST_ALGORITHM != "sha256":
        raise ValueError("Unsupported digest algorithm")
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def _configured_seed() -> bytes:
    raw = os.environ.get(SIGNING_SECRET_ENVIRONMENT_NAME, "")
    if _SIGNING_SEED_PATTERN.fullmatch(raw) is None:
        raise PQCProviderUnavailable(
            "Trusted ML-DSA signing seed is missing or invalid; "
            "SBP_LEX_SIGNING_SECRET must be exactly 64 lowercase hexadecimal characters."
        )
    return bytes.fromhex(raw)


def _public_key_fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def _process_keypair() -> tuple[bytes, bytes]:
    global _PROCESS_PRIVATE_KEY, _PROCESS_PUBLIC_KEY, _PROCESS_SEED_FINGERPRINT
    if not provider_available():
        raise PQCProviderUnavailable("PQC provider unavailable; signing fails closed.")
    seed = _configured_seed()
    seed_fingerprint = hashlib.sha256(seed).hexdigest()
    if _PROCESS_SEED_FINGERPRINT is not None and not hmac.compare_digest(
        _PROCESS_SEED_FINGERPRINT, seed_fingerprint,
    ):
        raise PQCProviderUnavailable(
            "Trusted signing identity changed during the active process; restart is required."
        )
    if _PROCESS_PRIVATE_KEY is None or _PROCESS_PUBLIC_KEY is None:
        _PROCESS_PRIVATE_KEY, _PROCESS_PUBLIC_KEY = derive_signing_keypair(
            seed, SIGNATURE_ALGORITHM,
        )
        _PROCESS_SEED_FINGERPRINT = seed_fingerprint
    return _PROCESS_PRIVATE_KEY, _PROCESS_PUBLIC_KEY


def _trusted_public_key() -> bytes | None:
    encoded = os.environ.get(TRUSTED_PUBLIC_KEY_ENVIRONMENT_NAME, "")
    if not encoded:
        return None
    try:
        configured_public = _decode(encoded)
    except ValueError:
        return None
    derived_public: bytes | None = None
    if os.environ.get(SIGNING_SECRET_ENVIRONMENT_NAME):
        try:
            _, derived_public = _process_keypair()
        except PQCProviderUnavailable:
            return None
    if (
        derived_public is not None
        and not hmac.compare_digest(configured_public, derived_public)
    ):
        return None
    expected_fingerprint = os.environ.get(
        EXPECTED_SIGNER_FINGERPRINT_ENVIRONMENT_NAME, "",
    )
    if _SIGNING_SEED_PATTERN.fullmatch(expected_fingerprint) is None:
        return None
    if not hmac.compare_digest(
        expected_fingerprint, _public_key_fingerprint(configured_public),
    ):
        return None
    return configured_public


def trusted_signing_key_fingerprint() -> str:
    public_key = _trusted_public_key()
    if public_key is None:
        raise PQCProviderUnavailable("Trusted ML-DSA public verification key is unavailable.")
    return _public_key_fingerprint(public_key)


def trusted_signing_public_key() -> str:
    public_key = _trusted_public_key()
    if public_key is None:
        raise PQCProviderUnavailable("Trusted ML-DSA public verification key is unavailable.")
    return _encode(public_key)


def sign_payload(
    payload: Mapping[str, Any], issuer: str = SYSTEM_ISSUER,
) -> Dict[str, Any]:
    """Sign through the configured ML-DSA identity and bind its trusted key."""
    if issuer != SYSTEM_ISSUER:
        raise PQCProviderUnavailable("Unapproved signing issuer requested.")
    digest = generate_digest(payload)
    message = digest.encode("utf-8")
    private_key, public_key = _process_keypair()
    trusted_public_key = _trusted_public_key()
    if trusted_public_key is None or not hmac.compare_digest(
        public_key, trusted_public_key,
    ):
        raise PQCProviderUnavailable(
            "Configured ML-DSA signing identity does not match the trusted verification key."
        )
    key_fingerprint = _public_key_fingerprint(public_key)
    try:
        crypto_profile = build_active_crypto_profile(
            public_key_fingerprint=key_fingerprint,
        )
    except CryptoProfileConfigurationError as exc:
        raise PQCProviderUnavailable(str(exc)) from exc
    global _PROCESS_PROFILE_DIGEST
    current_profile_digest = crypto_profile_digest(crypto_profile)
    if (
        _PROCESS_PROFILE_DIGEST is not None
        and not hmac.compare_digest(_PROCESS_PROFILE_DIGEST, current_profile_digest)
    ):
        raise PQCProviderUnavailable(
            "Cryptographic migration profile changed during the active process; restart is required."
        )
    _PROCESS_PROFILE_DIGEST = current_profile_digest
    message = _signature_message(digest, crypto_profile)
    signature_value = sign(message, private_key, SIGNATURE_ALGORITHM)
    return {
        "issuer": issuer,
        "algorithm": SIGNATURE_ALGORITHM,
        "policy": PQC_POLICY_NAME,
        "provider": provider_name(),
        "provider_available": True,
        "signature_version": PQC_SIGNATURE_VERSION,
        "key_fingerprint": key_fingerprint,
        "crypto_profile": crypto_profile,
        "digest": digest,
        "signature": _encode(signature_value),
        "public_key": _encode(public_key),
    }


def verify_signature(payload: Mapping[str, Any], signature: Mapping[str, Any]) -> bool:
    if not isinstance(signature, Mapping):
        return False
    if signature.get("issuer") != SYSTEM_ISSUER:
        return False
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        return False
    if signature.get("policy") != PQC_POLICY_NAME:
        return False
    if signature.get("provider") != provider_name():
        return False
    if signature.get("provider_available") is not True:
        return False
    if signature.get("signature_version") != PQC_SIGNATURE_VERSION:
        return False
    if set(signature) != {
        "issuer",
        "algorithm",
        "policy",
        "provider",
        "provider_available",
        "signature_version",
        "key_fingerprint",
        "crypto_profile",
        "digest",
        "signature",
        "public_key",
    }:
        return False
    expected_digest = generate_digest(payload)
    if signature.get("digest") != expected_digest:
        return False
    if not provider_available():
        return False
    try:
        public_key = _decode(str(signature.get("public_key", "")))
        signature_value = _decode(str(signature.get("signature", "")))
    except ValueError:
        return False
    trusted_public_key = _trusted_public_key()
    if trusted_public_key is None or not hmac.compare_digest(
        public_key, trusted_public_key,
    ):
        return False
    if signature.get("key_fingerprint") != _public_key_fingerprint(public_key):
        return False
    try:
        requirement = active_crypto_profile_requirement(
            public_key_fingerprint=_public_key_fingerprint(public_key),
        )
    except CryptoProfileConfigurationError:
        return False
    profile_ok, _ = validate_crypto_profile(
        signature.get("crypto_profile"),
        requirement=requirement,
        provider_is_available=True,
    )
    if not profile_ok:
        return False
    return verify(
        _signature_message(expected_digest, signature["crypto_profile"]),
        signature_value,
        public_key,
        SIGNATURE_ALGORITHM,
    )


def verify_legacy_signature_for_archive(
    payload: Mapping[str, Any],
    signature: Mapping[str, Any],
    *,
    archive_policy_reference: str,
) -> bool:
    """Verify a V2 object for explicit archive reading, never runtime admission."""
    if not legacy_archive_policy_is_approved(archive_policy_reference):
        return False
    if not isinstance(signature, Mapping) or signature.get("signature_version") != LEGACY_PQC_SIGNATURE_VERSION:
        return False
    if set(signature) != {
        "issuer", "algorithm", "policy", "provider", "provider_available",
        "signature_version", "key_fingerprint", "digest", "signature", "public_key",
    }:
        return False
    if (
        signature.get("issuer") != SYSTEM_ISSUER
        or signature.get("algorithm") != SIGNATURE_ALGORITHM
        or signature.get("policy") != PQC_POLICY_NAME
        or signature.get("provider") != provider_name()
        or signature.get("provider_available") is not True
        or not provider_available()
    ):
        return False
    expected_digest = generate_digest(payload)
    if signature.get("digest") != expected_digest:
        return False
    try:
        public_key = _decode(str(signature.get("public_key", "")))
        signature_value = _decode(str(signature.get("signature", "")))
    except ValueError:
        return False
    trusted_public_key = _trusted_public_key()
    if trusted_public_key is None or not hmac.compare_digest(public_key, trusted_public_key):
        return False
    if signature.get("key_fingerprint") != _public_key_fingerprint(public_key):
        return False
    return verify(
        expected_digest.encode("utf-8"), signature_value, public_key,
        SIGNATURE_ALGORITHM,
    )


def pqc_provider_status() -> dict[str, object]:
    trusted_key_available = _trusted_public_key() is not None
    profile_ready = False
    profile_error: str | None = None
    if trusted_key_available:
        try:
            build_active_crypto_profile(
                public_key_fingerprint=trusted_signing_key_fingerprint(),
            )
            profile_ready = True
        except CryptoProfileConfigurationError as exc:
            profile_error = str(exc)
    return {
        "policy": PQC_POLICY_NAME,
        "signature_algorithm": PQC_SIGNATURE_PRIMARY,
        "provider": provider_name(),
        "provider_version": provider_version(),
        "provider_available": provider_available(),
        "trusted_signing_key_available": trusted_key_available,
        "trusted_signing_key_fingerprint": (
            trusted_signing_key_fingerprint() if trusted_key_available else None
        ),
        "crypto_profile_version": CRYPTO_PROFILE_VERSION,
        "verification_policy_version": VERIFICATION_POLICY_VERSION,
        "migration_profile_ready": profile_ready,
        "migration_profile_error": profile_error,
        "fail_closed": PQC_FAIL_CLOSED,
    }


def reset_signing_identity_for_tests() -> None:
    global _PROCESS_PRIVATE_KEY, _PROCESS_PUBLIC_KEY, _PROCESS_SEED_FINGERPRINT
    global _PROCESS_PROFILE_DIGEST
    _PROCESS_PRIVATE_KEY = None
    _PROCESS_PUBLIC_KEY = None
    _PROCESS_SEED_FINGERPRINT = None
    _PROCESS_PROFILE_DIGEST = None


def _signature_message(payload_digest: str, profile: Mapping[str, Any]) -> bytes:
    return generate_digest({
        "payload_digest": payload_digest,
        "crypto_profile": dict(profile),
    }).encode("utf-8")


def _encode(value: bytes) -> str:
    return b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return b64decode(value.encode("ascii"), validate=True)
