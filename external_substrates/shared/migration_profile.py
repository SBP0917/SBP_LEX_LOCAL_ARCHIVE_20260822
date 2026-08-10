from __future__ import annotations

import importlib.metadata
import re
from datetime import datetime, timezone
from typing import Any, Mapping


EXTERNAL_PROFILE_VERSION = "PASS9_EXTERNAL_SOURCE_PQC_PROFILE_V2"
EXTERNAL_VERIFICATION_POLICY = "PASS9_EXTERNAL_SOURCE_NO_DOWNGRADE_V2"
EXTERNAL_MIGRATION_STATUS = "MIGRATED_APPROVED_LOCAL_SOURCE"
EXTERNAL_APPROVAL_REFERENCE = "PASS9_CONTROLLED_LOCAL_SOURCE_DECISION"
EXTERNAL_PROFILE_FIELDS = frozenset({
    "profile_version", "verification_policy_version", "provider_id",
    "provider_version", "algorithm_family", "algorithm_identifier",
    "signature_mode", "hybrid_mode", "components", "source_id", "key_id",
    "public_key_fingerprint", "created_at", "expires_at", "revoked",
    "migration_status", "legacy_status", "deprecation_status",
    "approval_reference",
})

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def provider_version() -> str:
    try:
        return importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        return "UNAVAILABLE"


def build_external_source_profile(
    *, source_id: str, key_id: str, public_key_fingerprint: str,
) -> dict[str, Any]:
    return {
        "profile_version": EXTERNAL_PROFILE_VERSION,
        "verification_policy_version": EXTERNAL_VERIFICATION_POLICY,
        "provider_id": "cryptography.mldsa",
        "provider_version": provider_version(),
        "algorithm_family": "POST_QUANTUM_DIGITAL_SIGNATURE",
        "algorithm_identifier": "ML-DSA",
        "signature_mode": "SINGLE_PROVIDER_SIGNATURE",
        "hybrid_mode": False,
        "components": [],
        "source_id": source_id,
        "key_id": key_id,
        "public_key_fingerprint": public_key_fingerprint,
        "created_at": "2026-08-09T00:00:00+00:00",
        "expires_at": "2099-12-31T23:59:59+00:00",
        "revoked": False,
        "migration_status": EXTERNAL_MIGRATION_STATUS,
        "legacy_status": "CURRENT_NOT_LEGACY",
        "deprecation_status": "ACTIVE_NOT_DEPRECATED",
        "approval_reference": EXTERNAL_APPROVAL_REFERENCE,
    }


def _time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def validate_external_source_profile(
    profile: object, *, source_id: str, key_id: str,
    public_key_fingerprint: str, now: datetime | None = None,
) -> bool:
    if not isinstance(profile, Mapping) or set(profile) != EXTERNAL_PROFILE_FIELDS:
        return False
    if (
        profile.get("profile_version") != EXTERNAL_PROFILE_VERSION
        or profile.get("verification_policy_version") != EXTERNAL_VERIFICATION_POLICY
        or profile.get("provider_id") != "cryptography.mldsa"
        or profile.get("provider_version") != provider_version()
        or profile.get("algorithm_family") != "POST_QUANTUM_DIGITAL_SIGNATURE"
        or profile.get("algorithm_identifier") != "ML-DSA"
        or profile.get("signature_mode") != "SINGLE_PROVIDER_SIGNATURE"
        or profile.get("hybrid_mode") is not False
        or profile.get("components") != []
        or profile.get("source_id") != source_id
        or profile.get("key_id") != key_id
        or profile.get("public_key_fingerprint") != public_key_fingerprint
        or _HEX64.fullmatch(public_key_fingerprint) is None
        or profile.get("revoked") is not False
        or profile.get("migration_status") != EXTERNAL_MIGRATION_STATUS
        or profile.get("legacy_status") != "CURRENT_NOT_LEGACY"
        or profile.get("deprecation_status") != "ACTIVE_NOT_DEPRECATED"
        or profile.get("approval_reference") != EXTERNAL_APPROVAL_REFERENCE
    ):
        return False
    current = now or datetime.now(timezone.utc)
    activated = _time(profile.get("created_at"))
    expires = _time(profile.get("expires_at"))
    return bool(
        activated is not None
        and expires is not None
        and activated <= current < expires
        and activated < expires
    )
