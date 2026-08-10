from __future__ import annotations

import importlib.metadata
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Mapping

from sbp_lex.config.security_config import SIGNATURE_ALGORITHM
from sbp_lex.security.pqc_policy import PQC_POLICY_NAME
from sbp_lex.security.pqc_provider import provider_available, provider_name


CRYPTO_PROFILE_VERSION = "PASS9_CONTROLLED_PQC_PROFILE_V2"
VERIFICATION_POLICY_VERSION = "PASS9_NO_SILENT_DOWNGRADE_POLICY_V2"
APPROVED_MIGRATION_STATUS = "MIGRATED_APPROVED"
SIGNATURE_MODE = "SINGLE_PROVIDER_SIGNATURE"
ALGORITHM_FAMILY = "POST_QUANTUM_DIGITAL_SIGNATURE"
LEGACY_STATUS = "CURRENT_NOT_LEGACY"
DEPRECATION_STATUS = "ACTIVE_NOT_DEPRECATED"

MIGRATION_STATUS_ENVIRONMENT_NAME = "SBP_LEX_PQC_MIGRATION_STATUS"
MIGRATION_APPROVAL_ENVIRONMENT_NAME = "SBP_LEX_PQC_MIGRATION_APPROVAL_REFERENCE"
SIGNING_KEY_ID_ENVIRONMENT_NAME = "SBP_LEX_SIGNING_KEY_ID"
SIGNING_KEY_ACTIVATED_AT_ENVIRONMENT_NAME = "SBP_LEX_SIGNING_KEY_ACTIVATED_AT"
SIGNING_KEY_EXPIRES_AT_ENVIRONMENT_NAME = "SBP_LEX_SIGNING_KEY_EXPIRES_AT"
REVOKED_SIGNING_KEYS_ENVIRONMENT_NAME = "SBP_LEX_REVOKED_SIGNING_KEY_FINGERPRINTS"
EMPTY_REVOCATION_REGISTRY_VALUE = "NONE"
APPROVED_LEGACY_ARCHIVE_POLICIES_ENVIRONMENT_NAME = (
    "SBP_LEX_APPROVED_LEGACY_ARCHIVE_POLICIES"
)

CRYPTO_PROFILE_FIELDS = frozenset({
    "profile_version", "provider_id", "provider_version", "algorithm_family",
    "algorithm_identifier", "security_profile", "signature_mode", "hybrid_mode",
    "components", "key_id", "public_key_fingerprint", "created_at", "expires_at",
    "revoked", "verification_policy_version", "migration_status", "legacy_status",
    "deprecation_status", "approval_reference",
})

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:/-]{8,160}$")


class CryptoProfileConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class CryptoProfileRequirement:
    provider_id: str = "cryptography.mldsa"
    provider_version: str | None = None
    algorithm_identifier: str = "ML-DSA"
    signature_mode: str = SIGNATURE_MODE
    verification_policy_version: str = VERIFICATION_POLICY_VERSION
    key_id: str | None = None
    public_key_fingerprint: str | None = None
    approval_reference: str | None = None
    revoked_key_fingerprints: frozenset[str] = frozenset()
    require_migrated_profile: bool = True
    require_expiry: bool = True
    allow_legacy: bool = False
    allow_hybrid: bool = False


def provider_version() -> str:
    try:
        return importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        return "UNAVAILABLE"


def derived_key_id(public_key_fingerprint: str) -> str:
    if _HEX64.fullmatch(public_key_fingerprint) is None:
        raise CryptoProfileConfigurationError("cryptographic_public_key_fingerprint_malformed")
    return f"MLDSA65_{public_key_fingerprint[:24].upper()}"


def build_current_crypto_profile(
    *,
    key_id: str,
    public_key_fingerprint: str,
    created_at: str = "2026-08-09T00:00:00+00:00",
    expires_at: str | None = "2099-12-31T23:59:59+00:00",
    migration_status: str = APPROVED_MIGRATION_STATUS,
    approval_reference: str = "PASS9_CONTROLLED_LOCAL_MIGRATION_DECISION",
    revoked: bool = False,
) -> dict[str, Any]:
    return {
        "profile_version": CRYPTO_PROFILE_VERSION,
        "provider_id": provider_name(),
        "provider_version": provider_version(),
        "algorithm_family": ALGORITHM_FAMILY,
        "algorithm_identifier": SIGNATURE_ALGORITHM,
        "security_profile": PQC_POLICY_NAME,
        "signature_mode": SIGNATURE_MODE,
        "hybrid_mode": False,
        "components": [],
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint,
        "created_at": created_at,
        "expires_at": expires_at,
        "revoked": revoked,
        "verification_policy_version": VERIFICATION_POLICY_VERSION,
        "migration_status": migration_status,
        "legacy_status": LEGACY_STATUS,
        "deprecation_status": DEPRECATION_STATUS,
        "approval_reference": approval_reference,
    }


def profile_from_signature(
    signature: Mapping[str, Any],
    *,
    key_id: str,
    created_at: str = "2026-08-09T00:00:00+00:00",
) -> dict[str, Any]:
    supplied = signature.get("crypto_profile")
    if isinstance(supplied, Mapping):
        return dict(supplied)
    profile = build_current_crypto_profile(
        key_id=key_id,
        public_key_fingerprint=str(signature.get("key_fingerprint", "")),
        created_at=created_at,
    )
    profile["provider_id"] = signature.get("provider")
    profile["algorithm_identifier"] = signature.get("algorithm")
    profile["security_profile"] = signature.get("policy")
    return profile


def _time(value: object, *, reason: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise CryptoProfileConfigurationError(reason)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CryptoProfileConfigurationError(reason) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise CryptoProfileConfigurationError(reason)
    return parsed


def revoked_key_fingerprints(raw: str | None = None) -> frozenset[str]:
    value = os.environ.get(REVOKED_SIGNING_KEYS_ENVIRONMENT_NAME, "") if raw is None else raw
    normalized = value.strip()
    if not normalized or normalized == EMPTY_REVOCATION_REGISTRY_VALUE:
        return frozenset()
    items = [item.strip() for item in normalized.split(",")]
    if any(_HEX64.fullmatch(item) is None for item in items) or len(items) != len(set(items)):
        raise CryptoProfileConfigurationError("cryptographic_revocation_registry_invalid")
    return frozenset(items)


def approved_legacy_archive_policies(raw: str | None = None) -> frozenset[str]:
    if raw is None:
        if APPROVED_LEGACY_ARCHIVE_POLICIES_ENVIRONMENT_NAME not in os.environ:
            return frozenset()
        raw = os.environ[APPROVED_LEGACY_ARCHIVE_POLICIES_ENVIRONMENT_NAME]
    if not raw.strip():
        return frozenset()
    items = [item.strip() for item in raw.split(",")]
    if (
        any(_IDENTIFIER.fullmatch(item) is None for item in items)
        or len(items) != len(set(items))
    ):
        raise CryptoProfileConfigurationError(
            "cryptographic_archive_policy_registry_invalid"
        )
    return frozenset(items)


def legacy_archive_policy_is_approved(reference: str) -> bool:
    if not isinstance(reference, str) or _IDENTIFIER.fullmatch(reference) is None:
        return False
    try:
        return reference in approved_legacy_archive_policies()
    except CryptoProfileConfigurationError:
        return False


def validate_crypto_profile(
    profile: Mapping[str, Any] | None,
    *,
    requirement: CryptoProfileRequirement | None = None,
    now: datetime | None = None,
    provider_is_available: bool | None = None,
) -> tuple[bool, list[str]]:
    required = requirement or CryptoProfileRequirement()
    if not isinstance(profile, Mapping):
        return False, ["cryptographic_profile_missing"]
    failures: list[str] = []
    if set(profile) != CRYPTO_PROFILE_FIELDS:
        failures.append("cryptographic_profile_schema_invalid")
    if profile.get("profile_version") != CRYPTO_PROFILE_VERSION:
        failures.append("cryptographic_profile_version_unknown")
    if profile.get("provider_id") != required.provider_id:
        failures.append("cryptographic_provider_substitution")
    version = profile.get("provider_version")
    if not isinstance(version, str) or not version or version == "UNAVAILABLE":
        failures.append("cryptographic_provider_version_missing")
    elif required.provider_version is not None and version != required.provider_version:
        failures.append("cryptographic_provider_version_substitution")
    if profile.get("algorithm_family") != ALGORITHM_FAMILY:
        failures.append("cryptographic_algorithm_family_unknown")
    if profile.get("algorithm_identifier") != required.algorithm_identifier:
        failures.append("cryptographic_algorithm_substitution")
    if profile.get("security_profile") != PQC_POLICY_NAME:
        failures.append("cryptographic_security_profile_invalid")
    if profile.get("signature_mode") != required.signature_mode:
        failures.append("cryptographic_signature_mode_mismatch")
    if profile.get("verification_policy_version") != required.verification_policy_version:
        failures.append("cryptographic_policy_cross_version_replay")

    key_id = profile.get("key_id")
    if not isinstance(key_id, str) or _IDENTIFIER.fullmatch(key_id) is None:
        failures.append("cryptographic_key_id_missing")
    elif required.key_id is not None and key_id != required.key_id:
        failures.append("cryptographic_key_id_mismatch")
    fingerprint = profile.get("public_key_fingerprint")
    if not isinstance(fingerprint, str) or _HEX64.fullmatch(fingerprint) is None:
        failures.append("cryptographic_public_key_fingerprint_malformed")
    else:
        if (
            required.public_key_fingerprint is not None
            and fingerprint != required.public_key_fingerprint
        ):
            failures.append("cryptographic_public_key_fingerprint_mismatch")
        if fingerprint in required.revoked_key_fingerprints:
            failures.append("cryptographic_key_revoked_by_registry")
    if profile.get("revoked") is not False:
        failures.append("cryptographic_key_revoked")

    current = now or datetime.now(timezone.utc)
    try:
        activated = _time(profile.get("created_at"), reason="cryptographic_created_at_invalid")
        if activated > current:
            failures.append("cryptographic_key_not_yet_active")
    except CryptoProfileConfigurationError as exc:
        failures.append(str(exc))
        activated = None
    expiry_value = profile.get("expires_at")
    if expiry_value is None:
        if required.require_expiry:
            failures.append("cryptographic_expiry_required")
    else:
        try:
            expiry = _time(expiry_value, reason="cryptographic_expires_at_invalid")
            if expiry <= current:
                failures.append("cryptographic_key_expired")
            if activated is not None and expiry <= activated:
                failures.append("cryptographic_key_lifecycle_order_invalid")
        except CryptoProfileConfigurationError as exc:
            failures.append(str(exc))

    hybrid = profile.get("hybrid_mode")
    components = profile.get("components")
    if hybrid is True:
        if not required.allow_hybrid:
            failures.append("cryptographic_hybrid_mode_not_approved")
        if not isinstance(components, list) or len(components) < 2:
            failures.append("cryptographic_hybrid_component_invalid")
        elif any(
            not isinstance(component, Mapping)
            or component.get("valid") is not True
            or not isinstance(component.get("algorithm_identifier"), str)
            for component in components
        ):
            failures.append("cryptographic_hybrid_component_invalid")
    elif hybrid is False:
        if components != []:
            failures.append("cryptographic_nonhybrid_components_present")
    else:
        failures.append("cryptographic_hybrid_mode_invalid")

    if not required.allow_legacy and profile.get("legacy_status") != LEGACY_STATUS:
        failures.append("cryptographic_legacy_downgrade_rejected")
    if (
        required.require_migrated_profile
        and profile.get("migration_status") != APPROVED_MIGRATION_STATUS
    ):
        failures.append("cryptographic_migrated_profile_required")
    if profile.get("deprecation_status") != DEPRECATION_STATUS:
        failures.append("cryptographic_algorithm_deprecated")
    approval = profile.get("approval_reference")
    if not isinstance(approval, str) or _IDENTIFIER.fullmatch(approval) is None:
        failures.append("cryptographic_migration_approval_missing")
    elif required.approval_reference is not None and approval != required.approval_reference:
        failures.append("cryptographic_migration_approval_mismatch")

    available = provider_available() if provider_is_available is None else provider_is_available
    if available is not True:
        failures.append("cryptographic_provider_unavailable")
    return not failures, sorted(set(failures))


def build_active_crypto_profile(
    *, public_key_fingerprint: str, now: datetime | None = None,
) -> dict[str, Any]:
    status = os.environ.get(MIGRATION_STATUS_ENVIRONMENT_NAME, "")
    approval = os.environ.get(MIGRATION_APPROVAL_ENVIRONMENT_NAME, "")
    activated_at = os.environ.get(SIGNING_KEY_ACTIVATED_AT_ENVIRONMENT_NAME, "")
    expires_at = os.environ.get(SIGNING_KEY_EXPIRES_AT_ENVIRONMENT_NAME, "")
    key_id = os.environ.get(SIGNING_KEY_ID_ENVIRONMENT_NAME, "")
    if status != APPROVED_MIGRATION_STATUS:
        raise CryptoProfileConfigurationError("cryptographic_migrated_profile_not_approved")
    if _IDENTIFIER.fullmatch(key_id) is None:
        raise CryptoProfileConfigurationError("cryptographic_key_id_missing")
    if REVOKED_SIGNING_KEYS_ENVIRONMENT_NAME not in os.environ:
        raise CryptoProfileConfigurationError(
            "cryptographic_revocation_registry_missing"
        )
    profile = build_current_crypto_profile(
        key_id=key_id,
        public_key_fingerprint=public_key_fingerprint,
        created_at=activated_at,
        expires_at=expires_at,
        migration_status=status,
        approval_reference=approval,
    )
    requirement = CryptoProfileRequirement(
        provider_version=provider_version(),
        key_id=key_id,
        public_key_fingerprint=public_key_fingerprint,
        approval_reference=approval,
        revoked_key_fingerprints=revoked_key_fingerprints(),
    )
    valid, failures = validate_crypto_profile(
        profile, requirement=requirement, now=now,
    )
    if not valid:
        raise CryptoProfileConfigurationError(
            "cryptographic_active_profile_invalid:" + ",".join(failures)
        )
    return profile


def active_crypto_profile_requirement(
    *, public_key_fingerprint: str,
) -> CryptoProfileRequirement:
    approval = os.environ.get(MIGRATION_APPROVAL_ENVIRONMENT_NAME, "")
    key_id = os.environ.get(SIGNING_KEY_ID_ENVIRONMENT_NAME, "")
    if os.environ.get(MIGRATION_STATUS_ENVIRONMENT_NAME) != APPROVED_MIGRATION_STATUS:
        raise CryptoProfileConfigurationError("cryptographic_migrated_profile_not_approved")
    if _IDENTIFIER.fullmatch(approval) is None:
        raise CryptoProfileConfigurationError("cryptographic_migration_approval_missing")
    if _IDENTIFIER.fullmatch(key_id) is None:
        raise CryptoProfileConfigurationError("cryptographic_key_id_missing")
    if REVOKED_SIGNING_KEYS_ENVIRONMENT_NAME not in os.environ:
        raise CryptoProfileConfigurationError(
            "cryptographic_revocation_registry_missing"
        )
    return CryptoProfileRequirement(
        provider_version=provider_version(),
        key_id=key_id,
        public_key_fingerprint=public_key_fingerprint,
        approval_reference=approval,
        revoked_key_fingerprints=revoked_key_fingerprints(),
    )


def crypto_profile_digest(profile: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(profile), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return sha256(raw).hexdigest()
