from __future__ import annotations

import base64
from copy import deepcopy
from typing import Any, Mapping

from external_substrates.shared.canonical_json import canonical_bytes

ALGORITHM = "ML-DSA"
PURPOSE = "EXTERNAL_EVIDENCE_PACKAGE_VERIFICATION"
SIGNATURE_VERSION = "H6G_EXTERNAL_SOURCE_SIGNATURE_V1"
DOMAINS = {
    "SKG": b"SBP_LEX_DESKTOP_V1_EXTERNAL_SKG_SOURCE_PACKAGE_V1\x00",
    "DTN": b"SBP_LEX_DESKTOP_V1_EXTERNAL_DTN_SOURCE_PACKAGE_V1\x00",
}


class ExternalSourceCryptoError(ValueError):
    pass


def _module():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except Exception as exc:
        raise ExternalSourceCryptoError("mldsa_provider_unavailable") from exc
    return mldsa


def generate_source_keypair() -> tuple[bytes, bytes]:
    private = _module().MLDSA65PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def encode_public_key(public_key: bytes) -> str:
    return base64.b64encode(public_key).decode("ascii")


def _decode(value: Any, *, error: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ExternalSourceCryptoError(error)
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ExternalSourceCryptoError(error) from exc


def signature_claims(
    *, package: Mapping[str, Any], source_id: str, key_id: str,
    substrate_type: str, algorithm: str = ALGORITHM, purpose: str = PURPOSE,
) -> dict[str, Any]:
    return {
        "signature_version": SIGNATURE_VERSION,
        "source_id": source_id,
        "key_id": key_id,
        "substrate_type": substrate_type,
        "algorithm": algorithm,
        "purpose": purpose,
        "package_type": package.get("package_type"),
        "schema_version": package.get("schema_version"),
        "package_id": package.get("package_id"),
        "package_digest": package.get("digest"),
    }


def _message(claims: Mapping[str, Any]) -> bytes:
    substrate = str(claims.get("substrate_type", ""))
    domain = DOMAINS.get(substrate)
    if domain is None:
        raise ExternalSourceCryptoError("unknown_substrate_domain")
    return domain + canonical_bytes(dict(claims))


def sign_source_package(
    package: Mapping[str, Any], *, private_key: bytes, source_id: str,
    key_id: str, substrate_type: str,
) -> dict[str, Any]:
    claims = signature_claims(
        package=package, source_id=source_id, key_id=key_id,
        substrate_type=substrate_type,
    )
    try:
        signature = _module().MLDSA65PrivateKey.from_seed_bytes(private_key).sign(_message(claims))
    except Exception as exc:
        raise ExternalSourceCryptoError("malformed_private_key") from exc
    result = deepcopy(dict(package))
    result["signature"] = {**claims, "signature": base64.b64encode(signature).decode("ascii")}
    return result


def verify_source_signature(
    package: Mapping[str, Any], *, public_verification_material: str,
    expected_source_id: str, expected_key_id: str, expected_substrate_type: str,
    expected_algorithm: str = ALGORITHM, expected_purpose: str = PURPOSE,
) -> bool:
    signature = package.get("signature")
    if not isinstance(signature, Mapping):
        return False
    expected = signature_claims(
        package=package, source_id=expected_source_id, key_id=expected_key_id,
        substrate_type=expected_substrate_type,
        algorithm=expected_algorithm, purpose=expected_purpose,
    )
    if set(signature) != set(expected) | {"signature"}:
        return False
    if any(signature.get(key) != value for key, value in expected.items()):
        return False
    if expected_algorithm != ALGORITHM or expected_purpose != PURPOSE:
        return False
    try:
        public_key = _decode(public_verification_material, error="malformed_public_key")
        signature_bytes = _decode(signature.get("signature"), error="malformed_signature")
        _module().MLDSA65PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, _message(expected)
        )
    except Exception:
        return False
    return True


def source_signature_shape_valid(package: Mapping[str, Any], *, substrate_type: str) -> bool:
    signature = package.get("signature")
    if not isinstance(signature, Mapping):
        return False
    source_id = signature.get("source_id")
    key_id = signature.get("key_id")
    if not isinstance(source_id, str) or not source_id or not isinstance(key_id, str) or not key_id:
        return False
    expected = signature_claims(
        package=package, source_id=source_id, key_id=key_id,
        substrate_type=substrate_type,
    )
    return set(signature) == set(expected) | {"signature"} and all(
        signature.get(key) == value for key, value in expected.items()
    ) and isinstance(signature.get("signature"), str) and bool(signature.get("signature"))
