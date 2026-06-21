from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.freshness import utc_timestamp
from external_substrates.shared.signal_envelope import build_signal_envelope, validate_signal_envelope
from external_substrates.shared.signing import sign_payload, verify_signature
from external_substrates.shared.source_attestation import summarise_sources
from external_substrates.shared.validation import contains_prohibited_authority
from external_substrates.skg.authority_graph import resolve_authority_chain
from external_substrates.skg.conflict_resolver import resolve_policy_conflicts
from external_substrates.skg.jurisdiction_mapper import map_jurisdiction
from external_substrates.skg.precedence_engine import resolve_precedence
from external_substrates.skg.revocation_checker import check_revocations
from external_substrates.skg.rule_lineage_engine import validate_rule_lineage

SKG_SIGNAL_TYPES = (
    "authority_link_signal",
    "jurisdiction_signal",
    "precedence_signal",
    "policy_conflict_signal",
    "procedural_requirement_signal",
    "licensing_authority_signal",
    "classification_authority_signal",
    "revocation_signal",
    "truth_lineage_signal",
)


def _package_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key not in {"digest", "signature"}}


def _signature_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key != "signature"}


def build_skg_signal_package(
    *,
    request_fingerprint: str,
    authorities: Sequence[Mapping[str, Any]],
    rules: Sequence[Mapping[str, Any]],
    conflicts: Sequence[Mapping[str, Any]],
    source_records: Sequence[Mapping[str, Any]],
    authority_id: str,
    jurisdiction: str,
    procedural_requirements: Sequence[Mapping[str, Any]] = (),
    licensing_authorities: Sequence[Mapping[str, Any]] = (),
    classification_authorities: Sequence[Mapping[str, Any]] = (),
    timestamp: str | None = None,
    signing_key: str | bytes | None = None,
) -> dict[str, Any]:
    package_timestamp = timestamp or utc_timestamp()
    sources = [deepcopy(dict(source)) for source in source_records]
    payloads: dict[str, Mapping[str, Any]] = {
        "authority_link_signal": resolve_authority_chain(authorities, authority_id),
        "jurisdiction_signal": map_jurisdiction(authorities, jurisdiction),
        "precedence_signal": resolve_precedence(rules),
        "policy_conflict_signal": resolve_policy_conflicts(conflicts),
        "procedural_requirement_signal": {"requirements": sorted((dict(item) for item in procedural_requirements), key=lambda item: str(item.get("requirement_id", "")))},
        "licensing_authority_signal": {"authorities": sorted((dict(item) for item in licensing_authorities), key=lambda item: str(item.get("authority_id", "")))},
        "classification_authority_signal": {"authorities": sorted((dict(item) for item in classification_authorities), key=lambda item: str(item.get("authority_id", "")))},
        "revocation_signal": check_revocations([*authorities, *rules]),
        "truth_lineage_signal": validate_rule_lineage(rules, now=package_timestamp),
    }
    signals = {
        signal_type: build_signal_envelope(
            request_fingerprint=request_fingerprint,
            signal_type=signal_type,
            payload=payloads[signal_type],
            source_records=sources,
            timestamp=package_timestamp,
            signing_key=signing_key,
        )
        for signal_type in SKG_SIGNAL_TYPES
    }
    package: dict[str, Any] = {
        "package_type": "external_skg_signal_package",
        "package_version": "1.0",
        "request_fingerprint": request_fingerprint,
        "signals": signals,
        "source_records": sources,
        "source_summary": summarise_sources(sources),
        "freshness_valid": all(signal["freshness_valid"] for signal in signals.values()),
        "consistency_valid": all(signal["consistency_valid"] for signal in signals.values()),
        "timestamp": package_timestamp,
    }
    package["digest"] = digest_mapping(_package_body(package))
    package["signature"] = sign_payload(_signature_body(package), signing_key)
    return package


def validate_skg_signal_package(
    package: Mapping[str, Any],
    *,
    verification_key: str | bytes | None = None,
) -> bool:
    required = {"package_type", "request_fingerprint", "signals", "digest", "signature", "timestamp"}
    if not isinstance(package, Mapping) or not required.issubset(package):
        return False
    if package.get("package_type") != "external_skg_signal_package" or contains_prohibited_authority(package):
        return False
    if package.get("freshness_valid") is not True or package.get("consistency_valid") is not True:
        return False
    signals = package.get("signals")
    if not isinstance(signals, Mapping) or set(signals) != set(SKG_SIGNAL_TYPES):
        return False
    if any(signal.get("request_fingerprint") != package.get("request_fingerprint") for signal in signals.values()):
        return False
    if not all(validate_signal_envelope(signal, verification_key=verification_key) for signal in signals.values()):
        return False
    if package.get("digest") != digest_mapping(_package_body(package)):
        return False
    return verify_signature(_signature_body(package), str(package.get("signature")), verification_key)
