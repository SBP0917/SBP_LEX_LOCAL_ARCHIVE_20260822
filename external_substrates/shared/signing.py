from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Any

from external_substrates.shared.canonical_json import canonical_bytes

PLACEHOLDER_CRYPTOGRAPHY_NOTICE = "PLACEHOLDER ONLY - NOT PRODUCTION CRYPTOGRAPHY"
PLACEHOLDER_PROFILE_VERSION = "PASS9_SYNTHETIC_HMAC_EXCLUSION_V1"
PLACEHOLDER_MIGRATION_STATUS = "PQC_EXCLUDED_TEST_ONLY"
_DEFAULT_PLACEHOLDER_KEY = b"SBP_LEX_15_6A_EXTERNAL_SUBSTRATE_DETERMINISTIC_PLACEHOLDER"


def placeholder_crypto_profile() -> dict[str, object]:
    return {
        "profile_version": PLACEHOLDER_PROFILE_VERSION,
        "cryptographic_role": "DETERMINISTIC_FIXTURE_INTEGRITY_ONLY",
        "algorithm_identifier": "HMAC-SHA256_PLACEHOLDER_TEST_ONLY",
        "provider_id": "python.stdlib.hmac",
        "migration_status": PLACEHOLDER_MIGRATION_STATUS,
        "live_provider_eligible": False,
        "runtime_authority": False,
        "notice": PLACEHOLDER_CRYPTOGRAPHY_NOTICE,
    }


def _key(value: str | bytes | None) -> bytes:
    if value is None:
        return _DEFAULT_PLACEHOLDER_KEY
    return value if isinstance(value, bytes) else value.encode("utf-8")


def sign_payload(payload: Any, signing_key: str | bytes | None = None) -> str:
    return hmac.new(_key(signing_key), canonical_bytes(payload), sha256).hexdigest()


def verify_signature(
    payload: Any,
    signature: str,
    verification_key: str | bytes | None = None,
) -> bool:
    if not isinstance(signature, str) or not signature:
        return False
    return hmac.compare_digest(sign_payload(payload, verification_key), signature)
