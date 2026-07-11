from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from external_substrates.dtn.signal_builder import validate_dtn_signal_package
from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.freshness import validate_freshness
from external_substrates.shared.package_identity import package_identity
from external_substrates.shared.pre_context_package import validate_pre_context_package
from external_substrates.shared.signing import sign_payload
from external_substrates.shared.source_attestation import validate_source_record
from external_substrates.shared.validation import contains_prohibited_authority
from external_substrates.skg.signal_builder import validate_skg_signal_package


class ExternalBoundaryError(ValueError):
    """Stable fail-closed error raised before canonical state construction."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class BoundaryPolicy:
    max_package_bytes: int = 262_144
    max_depth: int = 24
    max_container_items: int = 20_000
    max_age_seconds: int = 300
    schema_version: str = "1.0"
    package_version: str = "1.0"


@dataclass
class ReplayRegistry:
    """Caller-owned replay state; never mutates canonical runtime state."""

    package_ids: set[str] = field(default_factory=set)
    package_digests: set[str] = field(default_factory=set)

    def check_and_record(self, packages: Sequence[Mapping[str, Any]]) -> None:
        identifiers = [str(package.get("package_id", "")) for package in packages]
        digests = [str(package.get("digest", "")) for package in packages]
        if len(set(identifiers)) != len(identifiers):
            raise ExternalBoundaryError("duplicate_package_identifier")
        if any(identifier in self.package_ids for identifier in identifiers):
            raise ExternalBoundaryError("replayed_package_identifier")
        if any(digest in self.package_digests for digest in digests):
            raise ExternalBoundaryError("replayed_package_digest")
        self.package_ids.update(identifiers)
        self.package_digests.update(digests)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalBoundaryError("duplicate_json_key")
        result[key] = value
    return result


def _measure_structure(value: Any, *, depth: int, policy: BoundaryPolicy) -> int:
    if depth > policy.max_depth:
        raise ExternalBoundaryError("adapter_nesting_limit_exceeded")
    if isinstance(value, Mapping):
        count = len(value)
        for item in value.values():
            count += _measure_structure(item, depth=depth + 1, policy=policy)
    elif isinstance(value, list):
        count = len(value)
        for item in value:
            count += _measure_structure(item, depth=depth + 1, policy=policy)
    else:
        count = 1
    if count > policy.max_container_items:
        raise ExternalBoundaryError("adapter_item_limit_exceeded")
    return count


def parse_canonical_json(raw: str, *, policy: BoundaryPolicy = BoundaryPolicy()) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise ExternalBoundaryError("binary_package_rejected")
    try:
        encoded = raw.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ExternalBoundaryError("invalid_utf8") from exc
    if len(encoded) > policy.max_package_bytes:
        raise ExternalBoundaryError("oversized_package")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ExternalBoundaryError("non_finite_number")),
        )
    except ExternalBoundaryError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise ExternalBoundaryError("malformed_json") from exc
    if not isinstance(value, dict):
        raise ExternalBoundaryError("package_not_object")
    _measure_structure(value, depth=1, policy=policy)
    if raw.strip() != canonical_dumps(value):
        raise ExternalBoundaryError("non_canonical_json")
    return value


def _validate_metadata(package: Mapping[str, Any], *, expected_type: str, policy: BoundaryPolicy, now: str) -> None:
    if package.get("package_type") != expected_type:
        raise ExternalBoundaryError("protocol_confusion")
    if package.get("package_version") != policy.package_version:
        raise ExternalBoundaryError("package_version_rejected")
    if package.get("schema_version") != policy.schema_version:
        raise ExternalBoundaryError("schema_version_rejected")
    required_strings = (
        "package_id", "request_fingerprint", "issued_at", "transport_identity", "digest", "signature",
    )
    if any(not isinstance(package.get(key), str) or not str(package.get(key)).strip() for key in required_strings):
        raise ExternalBoundaryError("package_metadata_missing")
    if not validate_freshness(package.get("issued_at"), policy.max_age_seconds, now):
        raise ExternalBoundaryError("stale_package")
    sources = package.get("source_records")
    if not isinstance(sources, list) or not sources or not all(validate_source_record(source) for source in sources):
        raise ExternalBoundaryError("provenance_invalid")
    if any(
        source.get(flag) is not True
        for source in sources
        for flag in ("verified", "attested", "freshness_valid", "consistency_valid")
    ):
        raise ExternalBoundaryError("provenance_unqualified")
    if any(not validate_freshness(source.get("retrieved_at"), policy.max_age_seconds, now) for source in sources):
        raise ExternalBoundaryError("stale_provenance")
    source_ids = [str(source.get("source_id")) for source in sources]
    source_uris = [str(source.get("source_uri")) for source in sources]
    if len(set(source_ids)) != len(source_ids):
        raise ExternalBoundaryError("duplicate_provenance")
    if len(source_ids) > 1 and len(set(source_uris)) != len(source_uris):
        raise ExternalBoundaryError("source_independence_failure")
    expected_identity = package_identity(
        package_type=expected_type,
        package_version=str(package.get("package_version")),
        request_fingerprint=str(package.get("request_fingerprint")),
        issued_at=str(package.get("issued_at")),
        source_digests=[str(source.get("digest")) for source in sources],
        transport_identity=str(package.get("transport_identity")),
    )
    if package.get("package_id") != expected_identity:
        raise ExternalBoundaryError("package_identity_mismatch")
    if contains_prohibited_authority(package):
        raise ExternalBoundaryError("forged_external_authority")
    allowed_common = {
        "package_type", "package_version", "schema_version", "package_id", "request_fingerprint",
        "signals", "source_records", "source_summary", "freshness_valid", "consistency_valid",
        "timestamp", "issued_at", "transport_identity", "digest", "signature",
    }
    allowed_by_type = {
        "external_skg_signal_package": allowed_common | {"skg_truth_foundation_metadata"},
        "external_dtn_signal_package": allowed_common | {"skg_constraint_digest", "dtn_contextual_verification_metadata"},
        "external_pre_context_signal_package": allowed_common
        | {
            "skg_package_digest", "dtn_package_digest", "skg_truth_foundation_metadata",
            "dtn_contextual_verification_metadata", "nonce",
        },
    }
    if set(package) != allowed_by_type[expected_type]:
        raise ExternalBoundaryError("strict_schema_rejected")


def _dependency_ids(package: Mapping[str, Any]) -> list[str]:
    signal = package.get("signals", {}).get("dependency_signal", {})
    payload = signal.get("payload", {}) if isinstance(signal, Mapping) else {}
    dependencies = payload.get("dependencies", payload if isinstance(payload, list) else [])
    if not isinstance(dependencies, list):
        return []
    return [str(item.get("dependency_id", "")) for item in dependencies if isinstance(item, Mapping)]


def validate_external_chain(
    skg_package: Mapping[str, Any], dtn_package: Mapping[str, Any], pre_context_package: Mapping[str, Any],
    *, now: str, policy: BoundaryPolicy = BoundaryPolicy(), replay_registry: ReplayRegistry | None = None,
) -> None:
    _validate_metadata(skg_package, expected_type="external_skg_signal_package", policy=policy, now=now)
    _validate_metadata(dtn_package, expected_type="external_dtn_signal_package", policy=policy, now=now)
    _validate_metadata(pre_context_package, expected_type="external_pre_context_signal_package", policy=policy, now=now)
    if not validate_skg_signal_package(skg_package):
        raise ExternalBoundaryError("skg_verification_failed")
    if not validate_dtn_signal_package(dtn_package, skg_constraint_package=skg_package):
        raise ExternalBoundaryError("dtn_verification_failed")
    if not validate_pre_context_package(pre_context_package, skg_package=skg_package, dtn_package=dtn_package):
        raise ExternalBoundaryError("pre_context_verification_failed")
    expected_provenance = {
        str(source.get("digest"))
        for package in (skg_package, dtn_package)
        for source in package.get("source_records", [])
    }
    actual_provenance = {str(source.get("digest")) for source in pre_context_package.get("source_records", [])}
    if actual_provenance != expected_provenance:
        raise ExternalBoundaryError("mixed_source_contamination")
    authority_chain = (
        skg_package.get("signals", {})
        .get("authority_link_signal", {})
        .get("payload", {})
        .get("authority_chain", [])
    )
    if not isinstance(authority_chain, list) or not authority_chain or len(authority_chain) != len(set(authority_chain)):
        raise ExternalBoundaryError("authority_lineage_invalid")
    fingerprints = {package.get("request_fingerprint") for package in (skg_package, dtn_package, pre_context_package)}
    if len(fingerprints) != 1:
        raise ExternalBoundaryError("mixed_source_contamination")
    dependency_ids = _dependency_ids(dtn_package)
    if len(dependency_ids) != len(set(dependency_ids)):
        raise ExternalBoundaryError("dependency_ambiguity")
    if replay_registry is not None:
        replay_registry.check_and_record((skg_package, dtn_package, pre_context_package))


def adapt_external_chain(
    skg_json: str, dtn_json: str, pre_context_json: str, *, now: str,
    policy: BoundaryPolicy = BoundaryPolicy(), replay_registry: ReplayRegistry | None = None,
) -> dict[str, Any]:
    """Translate one complete external chain into one non-authoritative EIE candidate."""
    skg = parse_canonical_json(skg_json, policy=policy)
    dtn = parse_canonical_json(dtn_json, policy=policy)
    pre_context = parse_canonical_json(pre_context_json, policy=policy)
    validate_external_chain(skg, dtn, pre_context, now=now, policy=policy, replay_registry=replay_registry)
    body: dict[str, Any] = {
        "object_type": "ExternalIngressEnvelope",
        "eie_version": "1.0",
        "canonical_traversal_state": False,
        "authority_boundary": "EVIDENCE_ONLY_HARD_ENTRY_REQUIRED",
        "request_fingerprint": pre_context["request_fingerprint"],
        "skg_package_digest": skg["digest"],
        "dtn_package_digest": dtn["digest"],
        "pre_context_package_digest": pre_context["digest"],
        "source_records": deepcopy(pre_context["source_records"]),
        "signals": deepcopy(pre_context["signals"]),
    }
    body["eie_digest"] = digest_mapping(body)
    body["eie_signature"] = sign_payload(body)
    return body
