from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from base64 import b64decode, b64encode
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import DIGEST_ALGORITHM, SIGNATURE_ALGORITHM, SYSTEM_ISSUER
from sbp_lex.security.pqc_policy import PQC_FAIL_CLOSED, PQC_POLICY_NAME, PQC_SIGNATURE_PRIMARY
from sbp_lex.security.pqc_provider import (
    PQCProviderUnavailable,
    generate_signing_keypair,
    provider_available,
    provider_name,
    sign,
    verify,
)

PQC_SIGNATURE_VERSION = "PQC_01_PROVIDER_SIGNATURE_V1"
_PROCESS_PRIVATE_KEY: bytes | None = None
_PROCESS_PUBLIC_KEY: bytes | None = None


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
        value.get("signature_version") == PQC_SIGNATURE_VERSION
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


def sign_payload(payload: Mapping[str, Any], issuer: str = SYSTEM_ISSUER) -> Dict[str, Any]:
    """Sign a canonical payload through the configured real PQC provider."""
    digest = generate_digest(payload)
    message = digest.encode("utf-8")
    private_key, public_key = _process_keypair()
    signature_value = sign(message, private_key, SIGNATURE_ALGORITHM)
    return {
        "issuer": issuer,
        "algorithm": SIGNATURE_ALGORITHM,
        "policy": PQC_POLICY_NAME,
        "provider": provider_name(),
        "provider_available": True,
        "signature_version": PQC_SIGNATURE_VERSION,
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
    return verify(expected_digest.encode("utf-8"), signature_value, public_key, SIGNATURE_ALGORITHM)


def pqc_provider_status() -> dict[str, object]:
    return {
        "policy": PQC_POLICY_NAME,
        "signature_algorithm": PQC_SIGNATURE_PRIMARY,
        "provider": provider_name(),
        "provider_available": provider_available(),
        "fail_closed": PQC_FAIL_CLOSED,
    }


def _process_keypair() -> tuple[bytes, bytes]:
    global _PROCESS_PRIVATE_KEY, _PROCESS_PUBLIC_KEY
    if not provider_available():
        raise PQCProviderUnavailable("PQC provider unavailable; signing fails closed.")
    if _PROCESS_PRIVATE_KEY is None or _PROCESS_PUBLIC_KEY is None:
        _PROCESS_PRIVATE_KEY, _PROCESS_PUBLIC_KEY = generate_signing_keypair(SIGNATURE_ALGORITHM)
    return _PROCESS_PRIVATE_KEY, _PROCESS_PUBLIC_KEY


def _encode(value: bytes) -> str:
    return b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return b64decode(value.encode("ascii"), validate=True)
