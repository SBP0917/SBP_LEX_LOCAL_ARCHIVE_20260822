from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from external_substrates.dtn.signal_builder import validate_dtn_signal_package
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.freshness import utc_timestamp
from external_substrates.shared.pre_context_schema import PRE_CONTEXT_REQUIRED_FIELDS, PRE_CONTEXT_SIGNAL_TYPES
from external_substrates.shared.signal_envelope import validate_signal_envelope
from external_substrates.shared.signing import sign_payload, verify_signature
from external_substrates.shared.source_attestation import summarise_sources, validate_source_record
from external_substrates.shared.validation import contains_prohibited_authority, require_non_empty_string
from external_substrates.skg.signal_builder import validate_skg_signal_package


def _digest_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key not in {"digest", "signature"}}


def _signature_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key != "signature"}


def _unique_sources(*packages: Mapping[str, Any]) -> list[dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for package in packages:
        for source in package.get("source_records", []):
            indexed[str(source.get("digest"))] = deepcopy(dict(source))
    return [indexed[key] for key in sorted(indexed)]


def build_pre_context_package(
    *,
    skg_package: Mapping[str, Any],
    dtn_package: Mapping[str, Any],
    nonce: str,
    timestamp: str | None = None,
    signing_key: str | bytes | None = None,
) -> dict[str, Any]:
    if not validate_skg_signal_package(skg_package):
        raise ValueError("valid SKG package is required")
    if not validate_dtn_signal_package(dtn_package, skg_constraint_package=skg_package):
        raise ValueError("valid DTN package constrained by SKG is required")
    request_fingerprint = skg_package.get("request_fingerprint")
    if request_fingerprint != dtn_package.get("request_fingerprint"):
        raise ValueError("SKG and DTN request fingerprints must match")
    if not require_non_empty_string(nonce):
        raise ValueError("nonce is required")
    signals = {
        signal_type: deepcopy(
            skg_package["signals"].get(signal_type)
            or dtn_package["signals"].get(signal_type)
        )
        for signal_type in PRE_CONTEXT_SIGNAL_TYPES
    }
    if any(signal is None for signal in signals.values()):
        raise ValueError("required pre-context signal is missing")
    sources = _unique_sources(skg_package, dtn_package)
    package: dict[str, Any] = {
        "package_type": "external_pre_context_signal_package",
        "request_fingerprint": request_fingerprint,
        "package_version": "1.0",
        "skg_package_digest": skg_package["digest"],
        "dtn_package_digest": dtn_package["digest"],
        "signals": signals,
        "source_records": sources,
        "source_summary": summarise_sources(sources),
        "freshness_valid": skg_package.get("freshness_valid") is True and dtn_package.get("freshness_valid") is True,
        "consistency_valid": skg_package.get("consistency_valid") is True and dtn_package.get("consistency_valid") is True,
        "timestamp": timestamp or utc_timestamp(),
        "nonce": nonce,
    }
    package["digest"] = digest_mapping(_digest_body(package))
    package["signature"] = sign_payload(_signature_body(package), signing_key)
    return package


def validate_pre_context_package(
    package: Mapping[str, Any],
    *,
    skg_package: Mapping[str, Any] | None = None,
    dtn_package: Mapping[str, Any] | None = None,
    verification_key: str | bytes | None = None,
) -> bool:
    if not isinstance(package, Mapping) or not PRE_CONTEXT_REQUIRED_FIELDS.issubset(package):
        return False
    if package.get("package_type") != "external_pre_context_signal_package":
        return False
    if not all(require_non_empty_string(package.get(field)) for field in ("request_fingerprint", "nonce", "timestamp", "digest", "signature")):
        return False
    if contains_prohibited_authority(package):
        return False
    signals = package.get("signals")
    if not isinstance(signals, Mapping) or set(signals) != set(PRE_CONTEXT_SIGNAL_TYPES):
        return False
    if any(signal.get("request_fingerprint") != package.get("request_fingerprint") for signal in signals.values()):
        return False
    if not all(validate_signal_envelope(signal, verification_key=verification_key) for signal in signals.values()):
        return False
    sources = package.get("source_records")
    if not isinstance(sources, list) or not all(validate_source_record(source) for source in sources):
        return False
    if package.get("source_summary") != summarise_sources(sources):
        return False
    if package.get("freshness_valid") is not True or package.get("consistency_valid") is not True:
        return False
    if skg_package is not None:
        if package.get("skg_package_digest") != skg_package.get("digest") or package.get("request_fingerprint") != skg_package.get("request_fingerprint"):
            return False
    if dtn_package is not None:
        if package.get("dtn_package_digest") != dtn_package.get("digest") or package.get("request_fingerprint") != dtn_package.get("request_fingerprint"):
            return False
    if package.get("digest") != digest_mapping(_digest_body(package)):
        return False
    return verify_signature(_signature_body(package), str(package.get("signature")), verification_key)
