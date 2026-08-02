from __future__ import annotations

import hashlib
import inspect
from base64 import b64decode, b64encode

import pytest

from sbp_lex.config.security_config import build_pqc_config
from sbp_lex.security import pqc
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.pqc_policy import (
    FN_DSA_ENABLED,
    PQC_FAIL_CLOSED,
    PQC_KEM_PRIMARY,
    PQC_POLICY_NAME,
    PQC_REAL_PROVIDER_REQUIRED,
    PQC_SIGNATURE_BACKUP,
    PQC_SIGNATURE_PRIMARY,
)
from sbp_lex.security.pqc_provider import (
    PQCProviderUnavailable,
    generate_signing_keypair,
    provider_available,
    provider_name,
    sign,
    supported_algorithms,
    verify,
)
from sbp_lex.security.token_stack import issue_token, verify_token


def test_pqc_policy_uses_nist_fips_203_204_205() -> None:
    assert PQC_POLICY_NAME == "NIST_FIPS_203_204_205"
    assert PQC_SIGNATURE_PRIMARY == "ML-DSA"
    assert PQC_SIGNATURE_BACKUP == "SLH-DSA"
    assert PQC_KEM_PRIMARY == "ML-KEM"
    assert PQC_REAL_PROVIDER_REQUIRED is True
    assert PQC_FAIL_CLOSED is True
    assert FN_DSA_ENABLED is False


def test_security_config_reports_real_provider_contract() -> None:
    config = build_pqc_config()

    assert config["policy_name"] == "NIST_FIPS_203_204_205"
    assert config["signature_algorithm"] == "ML-DSA"
    assert config["signature_backup_algorithm"] == "SLH-DSA"
    assert config["kem_algorithm"] == "ML-KEM"
    assert config["signature_encoding"] == "RAW_BYTES_OR_PROVIDER_DEFINED"
    assert config["provider_required"] is True
    assert config["fail_closed"] is True
    assert config["fn_dsa_enabled"] is False
    assert "PLACEHOLDER" not in str(config)


def test_provider_availability_is_explicit() -> None:
    assert provider_name() == "cryptography.mldsa"
    assert provider_available() is True
    assert supported_algorithms() == ("ML-DSA",)


def test_real_provider_sign_verify_round_trip_when_available() -> None:
    message = b"sbp-lex-pqc-contract"
    private_key, public_key = pqc.generate_signing_keypair("ML-DSA")
    signature = sign(message, private_key, "ML-DSA")

    assert verify(message, signature, public_key, "ML-DSA") is True
    assert verify(b"tampered", signature, public_key, "ML-DSA") is False


def test_verify_never_returns_true_without_real_provider(monkeypatch) -> None:
    payload = {"message": "provider unavailable"}
    signature = sign_payload(payload)

    monkeypatch.setattr(pqc, "provider_available", lambda: False)

    assert verify_signature(payload, signature) is False


def test_sign_fails_closed_without_provider(monkeypatch) -> None:
    monkeypatch.setattr(pqc, "provider_available", lambda: False)

    with pytest.raises(PQCProviderUnavailable):
        sign_payload({"message": "no provider"})


def test_token_signature_verification_cannot_be_faked() -> None:
    state = {
        "request_fingerprint": "request-1",
        "state_hash": "state-1",
        "safety_profile": {"computed_tier": "T1"},
        "corroboration_required": False,
    }
    issued = issue_token(state, name="authority", issued_at_stage="authority_first")
    token = issued["tokens"]["authority"]
    forged = dict(token)
    forged["verified"] = True
    forged["signature"] = dict(token["signature"])
    forged["signature"]["signature"] = token["signature"]["signature"][:-4] + "AAAA"

    assert verify_token(token, expected_request_fingerprint="request-1") is True
    assert verify_token(forged, expected_request_fingerprint="request-1") is False


def test_pqc_signature_envelope_is_real_provider_metadata() -> None:
    payload = {"message": "metadata"}
    signature = sign_payload(payload)

    assert signature["algorithm"] == "ML-DSA"
    assert signature["policy"] == "NIST_FIPS_203_204_205"
    assert signature["provider"] == "cryptography.mldsa"
    assert signature["provider_available"] is True
    assert signature["signature_version"] == "PQC_01_PROVIDER_SIGNATURE_V2"
    assert signature["key_fingerprint"] == hashlib.sha256(
        b64decode(signature["public_key"])
    ).hexdigest()
    assert "public_key" in signature
    assert "signature" in signature
    assert verify_signature(payload, signature) is True


def test_randomized_provider_proof_does_not_break_canonical_digest() -> None:
    payload = {"message": "stable digest"}
    first = {"payload": payload, "signature": sign_payload(payload)}
    second = {"payload": payload, "signature": sign_payload(payload)}

    assert first["signature"]["signature"] != second["signature"]["signature"]
    assert generate_digest(first) == generate_digest(second)
    assert verify_signature(payload, first["signature"]) is True
    assert verify_signature(payload, second["signature"]) is True


@pytest.mark.linkage_assurance
def test_self_supplied_unauthorised_signing_key_is_rejected() -> None:
    payload = {"message": "unauthorised self-supplied key"}
    digest = generate_digest(payload)
    private_key, public_key = generate_signing_keypair("ML-DSA")
    forged = {
        "issuer": "SBP_LEX_V6_INTERNAL_CONTROL_PLANE",
        "algorithm": "ML-DSA",
        "policy": "NIST_FIPS_203_204_205",
        "provider": provider_name(),
        "provider_available": True,
        "signature_version": "PQC_01_PROVIDER_SIGNATURE_V2",
        "key_fingerprint": hashlib.sha256(public_key).hexdigest(),
        "digest": digest,
        "signature": b64encode(
            sign(digest.encode("utf-8"), private_key, "ML-DSA")
        ).decode("ascii"),
        "public_key": b64encode(public_key).decode("ascii"),
    }

    assert verify_signature(payload, forged) is False


@pytest.mark.linkage_assurance
def test_signing_fails_closed_without_configured_trust_root(monkeypatch) -> None:
    monkeypatch.delenv("SBP_LEX_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY", raising=False)

    with pytest.raises(PQCProviderUnavailable, match="missing or invalid"):
        sign_payload({"message": "no trusted signer"})


@pytest.mark.linkage_assurance
def test_signing_seed_cannot_self_declare_its_public_trust_root(
    monkeypatch,
) -> None:
    monkeypatch.delenv(
        "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY", raising=False,
    )

    with pytest.raises(PQCProviderUnavailable, match="does not match"):
        sign_payload({"message": "seed without out-of-band public key"})


@pytest.mark.linkage_assurance
def test_public_key_only_verifier_accepts_only_pinned_signer(monkeypatch) -> None:
    payload = {"message": "independent verifier"}
    signature = sign_payload(payload)
    monkeypatch.setenv(
        "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY", signature["public_key"],
    )
    monkeypatch.delenv("SBP_LEX_SIGNING_SECRET", raising=False)

    assert verify_signature(payload, signature) is True


@pytest.mark.linkage_assurance
def test_mismatched_explicit_trust_anchor_blocks_signing(monkeypatch) -> None:
    _, unrelated_public_key = generate_signing_keypair("ML-DSA")
    monkeypatch.setenv(
        "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY",
        b64encode(unrelated_public_key).decode("ascii"),
    )

    with pytest.raises(PQCProviderUnavailable, match="does not match"):
        sign_payload({"message": "mismatched trust anchor"})


@pytest.mark.linkage_assurance
def test_signing_identity_cannot_rotate_inside_active_process(monkeypatch) -> None:
    sign_payload({"message": "establish active identity"})
    monkeypatch.setenv("SBP_LEX_SIGNING_SECRET", "0" * 64)

    with pytest.raises(PQCProviderUnavailable, match="changed during"):
        sign_payload({"message": "identity rotation attempt"})


@pytest.mark.linkage_assurance
def test_legacy_self_supplied_signature_envelope_is_rejected() -> None:
    payload = {"message": "legacy envelope"}
    signature = sign_payload(payload)
    signature["signature_version"] = "PQC_01_PROVIDER_SIGNATURE_V1"
    signature.pop("key_fingerprint")

    assert verify_signature(payload, signature) is False


def test_canonical_digest_masks_random_proof_but_binds_signer_identity() -> None:
    payload = {"message": "signer identity binding"}
    signature = sign_payload(payload)
    altered = dict(signature)
    altered["key_fingerprint"] = "0" * 64

    assert generate_digest({"signature": signature}) != generate_digest({
        "signature": altered,
    })


def test_no_homemade_pqc_algorithm_implementation_exists() -> None:
    import sbp_lex.security.pqc_provider as provider_module

    source = inspect.getsource(provider_module)
    assert "from cryptography.hazmat.primitives.asymmetric import mldsa" in source
    assert "hmac" not in source.lower()
    assert "falcon" not in source.lower()
    assert "fn-dsa" not in source.lower()

