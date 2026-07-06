from __future__ import annotations

import inspect

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


def test_no_homemade_pqc_algorithm_implementation_exists() -> None:
    import sbp_lex.security.pqc_provider as provider_module

    source = inspect.getsource(provider_module)
    assert "from cryptography.hazmat.primitives.asymmetric import mldsa" in source
    assert "hmac" not in source.lower()
    assert "falcon" not in source.lower()
    assert "fn-dsa" not in source.lower()

