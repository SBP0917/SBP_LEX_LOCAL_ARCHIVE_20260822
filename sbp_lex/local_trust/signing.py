from __future__ import annotations

import re
from typing import Any, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


LOCAL_TRUST_SIGNATURE_MODE = "ML_DSA_65_TRUSTED_SIGNATURE_V2"
LOCAL_TRUST_SIGNATURE_BINDING_VERSION = "LOCAL_TRUST_SIGNATURE_BINDING_V2"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sign_local_trust_digest(
    integrity_domain: str,
    payload_digest: str,
) -> dict[str, Any]:
    _validate_binding_input(integrity_domain, payload_digest)
    return sign_payload(_signed_payload(integrity_domain, payload_digest))


def verify_local_trust_digest(
    integrity_domain: str,
    payload_digest: str,
    signature: object,
) -> bool:
    try:
        _validate_binding_input(integrity_domain, payload_digest)
    except (TypeError, ValueError):
        return False
    return isinstance(signature, Mapping) and verify_signature(
        _signed_payload(integrity_domain, payload_digest),
        signature,
    )


def local_trust_binding_digest(
    integrity_domain: str,
    payload_digest: str,
    signature: Mapping[str, Any],
) -> str:
    _validate_binding_input(integrity_domain, payload_digest)
    if not isinstance(signature, Mapping):
        raise TypeError("local_trust_signature_must_be_mapping")
    return generate_digest({
        "binding_version": LOCAL_TRUST_SIGNATURE_BINDING_VERSION,
        "integrity_domain": integrity_domain,
        "payload_digest": payload_digest,
        "integrity_signature": dict(signature),
    })


def _signed_payload(integrity_domain: str, payload_digest: str) -> dict[str, str]:
    return {
        "binding_version": LOCAL_TRUST_SIGNATURE_BINDING_VERSION,
        "integrity_domain": integrity_domain,
        "payload_digest": payload_digest,
    }


def _validate_binding_input(integrity_domain: str, payload_digest: str) -> None:
    if not isinstance(integrity_domain, str) or not integrity_domain.strip():
        raise ValueError("local_trust_integrity_domain_invalid")
    if not isinstance(payload_digest, str) or _HEX64.fullmatch(payload_digest) is None:
        raise ValueError("local_trust_payload_digest_invalid")
