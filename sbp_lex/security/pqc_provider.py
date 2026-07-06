from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sbp_lex.security.pqc_policy import PQC_SIGNATURE_PRIMARY


class PQCProviderUnavailable(RuntimeError):
    pass


class PQCProvider(Protocol):
    provider_name: str

    def provider_available(self) -> bool:
        ...

    def supported_algorithms(self) -> tuple[str, ...]:
        ...

    def generate_signing_keypair(self, algorithm: str = PQC_SIGNATURE_PRIMARY) -> tuple[bytes, bytes]:
        ...

    def sign(self, message: bytes, private_key: bytes, algorithm: str = PQC_SIGNATURE_PRIMARY) -> bytes:
        ...

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm: str = PQC_SIGNATURE_PRIMARY,
    ) -> bool:
        ...


@dataclass(frozen=True)
class CryptographyMLDSAProvider:
    provider_name: str = "cryptography.mldsa"

    def provider_available(self) -> bool:
        return _mldsa_module() is not None

    def supported_algorithms(self) -> tuple[str, ...]:
        return (PQC_SIGNATURE_PRIMARY,) if self.provider_available() else ()

    def generate_signing_keypair(self, algorithm: str = PQC_SIGNATURE_PRIMARY) -> tuple[bytes, bytes]:
        self._ensure_algorithm_available(algorithm)
        mldsa = _mldsa_module()
        if mldsa is None:
            raise PQCProviderUnavailable("PQC provider unavailable: cryptography ML-DSA support not installed.")
        private_key = mldsa.MLDSA65PrivateKey.generate()
        return private_key.private_bytes_raw(), private_key.public_key().public_bytes_raw()

    def sign(self, message: bytes, private_key: bytes, algorithm: str = PQC_SIGNATURE_PRIMARY) -> bytes:
        self._ensure_algorithm_available(algorithm)
        mldsa = _mldsa_module()
        if mldsa is None:
            raise PQCProviderUnavailable("PQC provider unavailable: cryptography ML-DSA support not installed.")
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(private_key).sign(message)

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm: str = PQC_SIGNATURE_PRIMARY,
    ) -> bool:
        self._ensure_algorithm_available(algorithm)
        mldsa = _mldsa_module()
        if mldsa is None:
            return False
        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        except Exception:
            return False
        return True

    def _ensure_algorithm_available(self, algorithm: str) -> None:
        if algorithm != PQC_SIGNATURE_PRIMARY:
            raise PQCProviderUnavailable(f"PQC algorithm not available in PQC-01 provider: {algorithm}")


def _mldsa_module():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except Exception:
        return None
    return mldsa


DEFAULT_PQC_PROVIDER = CryptographyMLDSAProvider()


def provider_name() -> str:
    return DEFAULT_PQC_PROVIDER.provider_name


def provider_available() -> bool:
    return DEFAULT_PQC_PROVIDER.provider_available()


def supported_algorithms() -> tuple[str, ...]:
    return DEFAULT_PQC_PROVIDER.supported_algorithms()


def generate_signing_keypair(algorithm: str = PQC_SIGNATURE_PRIMARY) -> tuple[bytes, bytes]:
    return DEFAULT_PQC_PROVIDER.generate_signing_keypair(algorithm)


def sign(message: bytes, private_key: bytes, algorithm: str = PQC_SIGNATURE_PRIMARY) -> bytes:
    return DEFAULT_PQC_PROVIDER.sign(message, private_key, algorithm)


def verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: str = PQC_SIGNATURE_PRIMARY,
) -> bool:
    return DEFAULT_PQC_PROVIDER.verify(message, signature, public_key, algorithm)

