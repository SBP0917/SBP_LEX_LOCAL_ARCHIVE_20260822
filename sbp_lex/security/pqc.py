from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import DIGEST_ALGORITHM, SIGNATURE_ALGORITHM, SYSTEM_ISSUER

_SECRET = b"SBP_LEX_V6_LOCAL_DETERMINISTIC_SECURITY_BINDING"


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def generate_digest(data: Any) -> str:
    if DIGEST_ALGORITHM != "sha256":
        raise ValueError("Unsupported digest algorithm")
    payload = canonical_json(data).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sign_payload(payload: Mapping[str, Any], issuer: str = SYSTEM_ISSUER) -> Dict[str, Any]:
    digest = generate_digest(payload)
    signature_value = hmac.new(_SECRET, digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "issuer": issuer,
        "algorithm": SIGNATURE_ALGORITHM,
        "digest": digest,
        "signature": signature_value,
        "signed_at": int(time.time()),
    }


def verify_signature(payload: Mapping[str, Any], signature: Mapping[str, Any]) -> bool:
    if not isinstance(signature, Mapping):
        return False
    expected_digest = generate_digest(payload)
    if signature.get("digest") != expected_digest:
        return False
    expected_signature = hmac.new(_SECRET, expected_digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(signature.get("signature", "")), expected_signature)
