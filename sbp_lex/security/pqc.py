from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import unicodedata
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import DIGEST_ALGORITHM, SIGNATURE_ALGORITHM, SYSTEM_ISSUER

_SECRET = os.environ.get("SBP_LEX_SIGNING_SECRET", "SBP_LEX_V6_LOCAL_DETERMINISTIC_SECURITY_BINDING").encode("utf-8")
DETERMINISTIC_SIGNATURE_MARKER = "CANONICAL_RUNTIME_DETERMINISTIC_SIGNATURE"


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("canonical_mapping_key_must_be_string")
            key = unicodedata.normalize("NFC", raw_key)
            if key in result:
                raise ValueError("canonical_key_collision_after_unicode_normalization")
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
    """Deterministic V1 signature envelope.

    No wall-clock timestamp is embedded in the signature. This keeps token,
    replay, convergence and audit hashes stable across identical traversals.
    """
    digest = generate_digest(payload)
    signature_value = hmac.new(_SECRET, digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "issuer": issuer,
        "algorithm": SIGNATURE_ALGORITHM,
        "digest": digest,
        "signature": signature_value,
        "signed_at": DETERMINISTIC_SIGNATURE_MARKER,
    }


def verify_signature(payload: Mapping[str, Any], signature: Mapping[str, Any]) -> bool:
    if not isinstance(signature, Mapping):
        return False
    if signature.get("issuer") != SYSTEM_ISSUER:
        return False
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        return False
    if signature.get("signed_at") != DETERMINISTIC_SIGNATURE_MARKER:
        return False
    if set(signature) != {"issuer", "algorithm", "digest", "signature", "signed_at"}:
        return False
    expected_digest = generate_digest(payload)
    if signature.get("digest") != expected_digest:
        return False
    expected_signature = hmac.new(_SECRET, expected_digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(signature.get("signature", "")), expected_signature)
