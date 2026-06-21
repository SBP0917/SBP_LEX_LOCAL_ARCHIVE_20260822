"""Deterministic helpers shared by external substrates."""

from external_substrates.shared.canonical_json import canonical_bytes, canonical_dumps
from external_substrates.shared.digest import digest_mapping, sha256_digest
from external_substrates.shared.signal_envelope import build_signal_envelope, validate_signal_envelope

__all__ = [
    "build_signal_envelope",
    "canonical_bytes",
    "canonical_dumps",
    "digest_mapping",
    "sha256_digest",
    "validate_signal_envelope",
]

