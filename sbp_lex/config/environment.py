from __future__ import annotations

import hmac
import hashlib
import os
import re
from base64 import b64decode
from typing import Any, Dict

from sbp_lex.api.access_control import SecurityConfigurationError, security_mode
from sbp_lex.security.pqc_provider import (
    PQCProviderUnavailable,
    derive_signing_keypair,
)
from sbp_lex.security.migration_profile import (
    CryptoProfileConfigurationError,
    build_active_crypto_profile,
    crypto_profile_digest,
)


def environment_security_report() -> Dict[str, Any]:
    raw_mode = os.environ.get("SBP_LEX_API_SECURITY_MODE", "local").strip().lower()
    try:
        mode = security_mode()
        mode_error = None
    except SecurityConfigurationError as exc:
        mode = raw_mode
        mode_error = str(exc)
    token_required = os.environ.get("SBP_LEX_REQUIRE_API_TOKEN", "0") == "1" or mode == "private"
    signing_secret = os.environ.get("SBP_LEX_SIGNING_SECRET")
    trusted_signing_public_key = os.environ.get(
        "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY"
    )
    expected_signer_fingerprint = os.environ.get(
        "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT"
    )
    api_token = os.environ.get("SBP_LEX_API_TOKEN")
    warnings: list[str] = []
    signing_seed_valid = (
        signing_secret is not None
        and re.fullmatch(r"[0-9a-f]{64}", signing_secret) is not None
    )
    trusted_key_valid = False
    trusted_key_fingerprint: str | None = None

    if mode_error and mode not in {"local", "private", "disabled"}:
        warnings.append("invalid_api_security_mode")
    if mode_error == "disabled_api_security_mode_outside_test_harness":
        warnings.append("api_security_disabled_outside_test_harness")
    elif mode == "disabled":
        warnings.append("api_security_disabled")
    if token_required and not api_token:
        warnings.append("api_token_required_but_missing")
    if signing_secret is None:
        warnings.append("trusted_signing_seed_missing")
    elif not signing_seed_valid:
        warnings.append("trusted_signing_seed_invalid")
    if trusted_signing_public_key is None:
        warnings.append("trusted_signing_public_key_missing")
    else:
        try:
            configured_public_key = b64decode(
                trusted_signing_public_key.encode("ascii"),
                validate=True,
            )
            trusted_key_fingerprint = hashlib.sha256(
                configured_public_key
            ).hexdigest()
            if not signing_seed_valid:
                trusted_key_valid = bool(configured_public_key)
            else:
                _, derived_public_key = derive_signing_keypair(
                    bytes.fromhex(signing_secret), "ML-DSA",
                )
                trusted_key_valid = hmac.compare_digest(
                    configured_public_key, derived_public_key,
                )
        except (
            UnicodeEncodeError, ValueError, PQCProviderUnavailable,
        ):
            trusted_key_valid = False
        if not trusted_key_valid:
            warnings.append(
                "trusted_signing_public_key_invalid_or_mismatched"
            )
    expected_fingerprint_valid = (
        expected_signer_fingerprint is not None
        and re.fullmatch(r"[0-9a-f]{64}", expected_signer_fingerprint)
        is not None
        and trusted_key_fingerprint is not None
        and hmac.compare_digest(
            expected_signer_fingerprint,
            trusted_key_fingerprint,
        )
    )
    if expected_signer_fingerprint is None:
        warnings.append("expected_signer_fingerprint_missing")
    elif not expected_fingerprint_valid:
        warnings.append("expected_signer_fingerprint_invalid_or_mismatched")
    migration_profile_ready = False
    migration_profile_error: str | None = None
    migration_profile_fingerprint: str | None = None
    if expected_fingerprint_valid and trusted_key_fingerprint is not None:
        try:
            profile = build_active_crypto_profile(
                public_key_fingerprint=trusted_key_fingerprint,
            )
            migration_profile_ready = True
            migration_profile_fingerprint = crypto_profile_digest(profile)
        except CryptoProfileConfigurationError as exc:
            migration_profile_error = str(exc)
    else:
        migration_profile_error = "cryptographic_trusted_identity_unavailable"
    if not migration_profile_ready:
        warnings.append("pqc_migration_profile_invalid")
    if api_token is not None and len(api_token) < 24:
        warnings.append("api_token_short")

    return {
        "mode": mode,
        "token_required": token_required,
        "signing_secret_configured": (
            signing_seed_valid
        ),
        "trusted_signing_public_key_configured": bool(
            trusted_signing_public_key
        ),
        "trusted_signing_public_key_valid": trusted_key_valid,
        "expected_signer_fingerprint_configured": bool(
            expected_signer_fingerprint
        ),
        "expected_signer_fingerprint_valid": expected_fingerprint_valid,
        "pqc_migration_profile_ready": migration_profile_ready,
        "pqc_migration_profile_digest": migration_profile_fingerprint,
        "pqc_migration_profile_error": migration_profile_error,
        "api_token_configured": api_token is not None,
        "warnings": warnings,
        "valid": not warnings,
    }
