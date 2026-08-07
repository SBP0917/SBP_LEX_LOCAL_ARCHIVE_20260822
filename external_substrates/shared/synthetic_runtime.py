from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, MutableSet, Sequence
from urllib.parse import urlparse

from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.signing import sign_payload, verify_signature
from external_substrates.shared.validation import (
    PROHIBITED_AUTHORITY_KEYS,
    PROHIBITED_AUTHORITY_VALUES,
    contains_prohibited_authority,
)

SKG_SCHEMA_VERSION = "desktop-v1.synthetic.skg.v1"
DTN_SCHEMA_VERSION = "desktop-v1.synthetic.dtn.v1"
SIGNATURE_MODE = "CONTROLLED_LOCAL_HMAC_SHA256_V1"
PROVIDER_MODE = "synthetic_local"
DEFAULT_FRESHNESS_SECONDS = 300

SKG_FIELDS = frozenset({
    "package_type", "schema_version", "package_reference", "request_fingerprint",
    "eie_digest", "authority_hierarchy", "jurisdiction", "legitimacy", "precedence",
    "procedural_obligation_references", "evidentiary_references", "substrate_constraints",
    "provenance", "issued_at", "freshness_seconds", "nonce", "signature_mode",
    "digest", "signature",
})
DTN_FIELDS = frozenset({
    "package_type", "schema_version", "package_reference", "request_fingerprint",
    "eie_digest", "skg_constraint_digest", "authority_reference", "jurisdiction",
    "operational_context", "environmental_context", "feasibility_constraints",
    "dependencies", "pathway_viability", "consequence_risk_context", "provenance",
    "issued_at", "freshness_seconds", "nonce", "signature_mode", "digest", "signature",
})

_CREDENTIAL_KEYS = frozenset({
    "api_key", "access_key", "secret", "token", "credential", "credentials",
    "password", "private_key", "provider_credential",
})
_PROVIDER_KEYS = frozenset({
    "live_ingestion", "live_mode", "network_enabled", "external_service_mode",
    "production_sensor_feed", "sensor_ingestion", "cloud_endpoint", "provider_url",
    "endpoint", "url",
})
_LIVE_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "mqtt", "amqp"})


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    failures: tuple[str, ...]


@dataclass
class SyntheticReplayRegistry:
    """Caller-owned replay state with no governed-runtime reference."""

    nonces: MutableSet[str] = field(default_factory=set)
    digests: MutableSet[str] = field(default_factory=set)

    def validate_and_record(
        self, packages: Sequence[Mapping[str, Any]]
    ) -> ValidationResult:
        failures: list[str] = []
        nonces = [str(package.get("nonce", "")) for package in packages]
        digests = [str(package.get("digest", "")) for package in packages]
        if len(nonces) != len(set(nonces)):
            failures.append("duplicate_package_nonce")
        if any(nonce in self.nonces for nonce in nonces):
            failures.append("replayed_package_nonce")
        if any(digest in self.digests for digest in digests):
            failures.append("replayed_package_digest")
        if failures:
            return _result(failures)
        self.nonces.update(nonces)
        self.digests.update(digests)
        return ValidationResult(True, ())


def _result(failures: Sequence[str]) -> ValidationResult:
    unique = tuple(dict.fromkeys(str(failure) for failure in failures))
    return ValidationResult(not unique, unique)


def canonical_package(package: Mapping[str, Any]) -> str:
    return canonical_dumps(package)


def _digest_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in package.items()
        if key not in {"digest", "signature"}
    }


def _signature_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in package.items()
        if key != "signature"
    }


def _nonce(
    package_type: str, request_fingerprint: str, eie_digest: str, issued_at: str
) -> str:
    return digest_mapping({
        "package_type": package_type,
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie_digest,
        "issued_at": issued_at,
    })[:32]


def _finalise(
    package: dict[str, Any], signing_key: str | bytes | None
) -> dict[str, Any]:
    package["digest"] = digest_mapping(_digest_body(package))
    package["signature"] = sign_payload(_signature_body(package), signing_key)
    return package


def build_synthetic_skg_package(
    *,
    request_fingerprint: str,
    eie_digest: str,
    package_reference: str,
    authority_id: str,
    jurisdiction: str,
    issued_at: str,
    provenance: Sequence[Mapping[str, Any]],
    evidence_references: Sequence[str],
    procedural_references: Sequence[str],
    prohibited_pathway_ids: Sequence[str] = (),
    signing_key: str | bytes | None = None,
) -> dict[str, Any]:
    package_type = "synthetic_skg_package"
    package: dict[str, Any] = {
        "package_type": package_type,
        "schema_version": SKG_SCHEMA_VERSION,
        "package_reference": package_reference,
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie_digest,
        "authority_hierarchy": [{
            "authority_id": authority_id,
            "parent_authority_id": None,
            "legitimate": True,
            "precedence_rank": 1,
        }],
        "jurisdiction": {
            "jurisdiction_id": jurisdiction,
            "scope": "request_bound",
        },
        "legitimacy": {
            "valid": True,
            "basis_references": sorted(evidence_references),
        },
        "precedence": {
            "resolved": True,
            "ordered_authority_ids": [authority_id],
        },
        "procedural_obligation_references": sorted(procedural_references),
        "evidentiary_references": sorted(evidence_references),
        "substrate_constraints": {
            "prohibited_pathway_ids": sorted(prohibited_pathway_ids),
        },
        "provenance": sorted(
            (deepcopy(dict(item)) for item in provenance),
            key=lambda item: str(item.get("source_id", "")),
        ),
        "issued_at": issued_at,
        "freshness_seconds": DEFAULT_FRESHNESS_SECONDS,
        "nonce": _nonce(
            package_type, request_fingerprint, eie_digest, issued_at
        ),
        "signature_mode": SIGNATURE_MODE,
    }
    return _finalise(package, signing_key)


def build_synthetic_dtn_package(
    *,
    request_fingerprint: str,
    eie_digest: str,
    package_reference: str,
    skg_package: Mapping[str, Any],
    authority_id: str,
    jurisdiction: str,
    operational_context: Mapping[str, Any],
    environmental_context: Mapping[str, Any],
    dependencies: Sequence[Mapping[str, Any]],
    pathway_id: str,
    issued_at: str,
    provenance: Sequence[Mapping[str, Any]],
    signing_key: str | bytes | None = None,
) -> dict[str, Any]:
    package_type = "synthetic_dtn_package"
    dependency_items = sorted(
        (deepcopy(dict(item)) for item in dependencies),
        key=lambda item: str(item.get("dependency_id", "")),
    )
    required_ids = [
        str(item.get("dependency_id")) for item in dependency_items
    ]
    prohibited = skg_package.get(
        "substrate_constraints", {}
    ).get("prohibited_pathway_ids", [])
    viable = (
        pathway_id not in prohibited
        and all(item.get("available") is True for item in dependency_items)
    )
    package: dict[str, Any] = {
        "package_type": package_type,
        "schema_version": DTN_SCHEMA_VERSION,
        "package_reference": package_reference,
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie_digest,
        "skg_constraint_digest": skg_package.get("digest"),
        "authority_reference": authority_id,
        "jurisdiction": {
            "jurisdiction_id": jurisdiction,
            "scope": "request_bound",
        },
        "operational_context": deepcopy(dict(operational_context)),
        "environmental_context": deepcopy(dict(environmental_context)),
        "feasibility_constraints": [{
            "constraint_id": "synthetic_dependency_availability",
            "satisfied": all(
                item.get("available") is True for item in dependency_items
            ),
        }],
        "dependencies": dependency_items,
        "pathway_viability": {
            "pathway_id": pathway_id,
            "viable": viable,
            "required_dependency_ids": required_ids,
        },
        "consequence_risk_context": {
            "risk_level": "bounded" if viable else "nonviable",
            "consequences": (
                [] if viable
                else ["dependency_or_skg_constraint_failure"]
            ),
        },
        "provenance": sorted(
            (deepcopy(dict(item)) for item in provenance),
            key=lambda item: str(item.get("source_id", "")),
        ),
        "issued_at": issued_at,
        "freshness_seconds": DEFAULT_FRESHNESS_SECONDS,
        "nonce": _nonce(
            package_type, request_fingerprint, eie_digest, issued_at
        ),
        "signature_mode": SIGNATURE_MODE,
    }
    return _finalise(package, signing_key)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _validate_freshness(
    package: Mapping[str, Any], validation_time: str, failures: list[str]
) -> None:
    issued = _parse_time(package.get("issued_at"))
    checked = _parse_time(validation_time)
    window = package.get("freshness_seconds")
    if (
        issued is None
        or checked is None
        or not isinstance(window, int)
        or isinstance(window, bool)
        or window < 0
    ):
        failures.append("freshness_contract_invalid")
    elif not 0 <= (checked - issued).total_seconds() <= window:
        failures.append("stale_package")


def _exact_fields(
    value: Any,
    allowed: frozenset[str],
    reason: str,
    failures: list[str],
) -> bool:
    if not isinstance(value, Mapping) or set(value) != allowed:
        failures.append(reason)
        return False
    return True


def _strings(values: Any, *, nonempty: bool = True) -> bool:
    return (
        isinstance(values, list)
        and (bool(values) or not nonempty)
        and all(
            isinstance(item, str) and bool(item.strip())
            for item in values
        )
    )


def _local_uri(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"fixture", "local", "file"} and not parsed.netloc


def _validate_provenance(value: Any, failures: list[str]) -> None:
    allowed = frozenset({
        "source_id", "source_uri", "retrieved_at", "digest",
        "verified", "attested",
    })
    if not isinstance(value, list) or not value:
        failures.append("provenance_invalid")
        return
    ids: list[str] = []
    for item in value:
        if not _exact_fields(
            item, allowed, "provenance_invalid", failures
        ):
            continue
        assert isinstance(item, Mapping)
        if any(
            not isinstance(item.get(key), str)
            or not str(item.get(key)).strip()
            for key in ("source_id", "source_uri", "retrieved_at", "digest")
        ):
            failures.append("provenance_invalid")
        if item.get("verified") is not True or item.get("attested") is not True:
            failures.append("provenance_invalid")
        if not _local_uri(str(item.get("source_uri", ""))):
            failures.append("provenance_provider_uri_denied")
        ids.append(str(item.get("source_id", "")))
    if len(ids) != len(set(ids)):
        failures.append("provenance_duplicate_source")


def _validate_common(
    package: Any,
    *,
    expected_type: str,
    expected_version: str,
    allowed_fields: frozenset[str],
    validation_time: str,
    request_fingerprint: str | None,
    eie_digest: str | None,
    verification_key: str | bytes | None,
    failures: list[str],
) -> bool:
    if contains_prohibited_authority(package):
        failures.append("forbidden_authority_field")
    if not _exact_fields(
        package, allowed_fields, "schema_fields_rejected", failures
    ):
        return False
    assert isinstance(package, Mapping)
    if package.get("package_type") != expected_type:
        failures.append("package_type_rejected")
    if package.get("schema_version") != expected_version:
        failures.append("schema_version_rejected")
    for field_name in (
        "package_reference", "request_fingerprint", "eie_digest",
        "issued_at", "nonce", "digest", "signature",
    ):
        if (
            not isinstance(package.get(field_name), str)
            or not str(package.get(field_name)).strip()
        ):
            failures.append(f"required_field_invalid:{field_name}")
    if package.get("signature_mode") != SIGNATURE_MODE:
        failures.append("signature_mode_rejected")
    if (
        request_fingerprint is not None
        and package.get("request_fingerprint") != request_fingerprint
    ):
        failures.append("request_fingerprint_mismatch")
    if eie_digest is not None and package.get("eie_digest") != eie_digest:
        failures.append("eie_digest_mismatch")
    expected_nonce = _nonce(
        expected_type,
        str(package.get("request_fingerprint", "")),
        str(package.get("eie_digest", "")),
        str(package.get("issued_at", "")),
    )
    if package.get("nonce") != expected_nonce:
        failures.append("nonce_invalid")
    _validate_freshness(package, validation_time, failures)
    _validate_provenance(package.get("provenance"), failures)
    if package.get("digest") != digest_mapping(_digest_body(package)):
        failures.append("digest_invalid")
    if not verify_signature(
        _signature_body(package),
        str(package.get("signature", "")),
        verification_key,
    ):
        failures.append("signature_invalid")
    return True


def validate_synthetic_skg_package(
    package: Any,
    *,
    validation_time: str,
    request_fingerprint: str | None = None,
    eie_digest: str | None = None,
    verification_key: str | bytes | None = None,
) -> ValidationResult:
    failures: list[str] = []
    if not _validate_common(
        package,
        expected_type="synthetic_skg_package",
        expected_version=SKG_SCHEMA_VERSION,
        allowed_fields=SKG_FIELDS,
        validation_time=validation_time,
        request_fingerprint=request_fingerprint,
        eie_digest=eie_digest,
        verification_key=verification_key,
        failures=failures,
    ):
        return _result(failures)
    assert isinstance(package, Mapping)
    hierarchy = package.get("authority_hierarchy")
    hierarchy_fields = frozenset({
        "authority_id", "parent_authority_id",
        "legitimate", "precedence_rank",
    })
    if not isinstance(hierarchy, list) or not hierarchy:
        failures.append("authority_hierarchy_invalid")
    else:
        for item in hierarchy:
            if not _exact_fields(
                item, hierarchy_fields,
                "authority_hierarchy_invalid", failures,
            ):
                continue
            assert isinstance(item, Mapping)
            if (
                not isinstance(item.get("authority_id"), str)
                or not item.get("authority_id")
            ):
                failures.append("authority_hierarchy_invalid")
            if (
                item.get("parent_authority_id") is not None
                and not isinstance(item.get("parent_authority_id"), str)
            ):
                failures.append("authority_hierarchy_invalid")
            if (
                item.get("legitimate") is not True
                or not isinstance(item.get("precedence_rank"), int)
            ):
                failures.append("authority_legitimacy_invalid")
    jurisdiction = package.get("jurisdiction")
    if _exact_fields(
        jurisdiction,
        frozenset({"jurisdiction_id", "scope"}),
        "jurisdiction_invalid",
        failures,
    ) and not all(
        isinstance(jurisdiction.get(key), str) and jurisdiction.get(key)
        for key in ("jurisdiction_id", "scope")
    ):
        failures.append("jurisdiction_invalid")
    legitimacy = package.get("legitimacy")
    if (
        not _exact_fields(
            legitimacy,
            frozenset({"valid", "basis_references"}),
            "legitimacy_invalid",
            failures,
        )
        or legitimacy.get("valid") is not True
        or not _strings(legitimacy.get("basis_references"))
    ):
        failures.append("legitimacy_invalid")
    precedence = package.get("precedence")
    if (
        not _exact_fields(
            precedence,
            frozenset({"resolved", "ordered_authority_ids"}),
            "precedence_invalid",
            failures,
        )
        or precedence.get("resolved") is not True
        or not _strings(precedence.get("ordered_authority_ids"))
    ):
        failures.append("precedence_invalid")
    if not _strings(package.get("procedural_obligation_references")):
        failures.append("procedural_obligations_invalid")
    if not _strings(package.get("evidentiary_references")):
        failures.append("evidentiary_references_invalid")
    constraints = package.get("substrate_constraints")
    if (
        not _exact_fields(
            constraints,
            frozenset({"prohibited_pathway_ids"}),
            "substrate_constraints_invalid",
            failures,
        )
        or not _strings(
            constraints.get("prohibited_pathway_ids"), nonempty=False
        )
    ):
        failures.append("substrate_constraints_invalid")
    provenance_digests = {
        item.get("digest")
        for item in package.get("provenance", [])
        if isinstance(item, Mapping)
    }
    if not set(
        package.get("evidentiary_references", [])
    ).issubset(provenance_digests):
        failures.append("evidence_provenance_mismatch")
    return _result(failures)


def validate_synthetic_dtn_package(
    package: Any,
    *,
    validation_time: str,
    request_fingerprint: str | None = None,
    eie_digest: str | None = None,
    skg_digest: str | None = None,
    verification_key: str | bytes | None = None,
) -> ValidationResult:
    failures: list[str] = []
    if not _validate_common(
        package,
        expected_type="synthetic_dtn_package",
        expected_version=DTN_SCHEMA_VERSION,
        allowed_fields=DTN_FIELDS,
        validation_time=validation_time,
        request_fingerprint=request_fingerprint,
        eie_digest=eie_digest,
        verification_key=verification_key,
        failures=failures,
    ):
        return _result(failures)
    assert isinstance(package, Mapping)
    if (
        skg_digest is not None
        and package.get("skg_constraint_digest") != skg_digest
    ):
        failures.append("skg_constraint_digest_mismatch")
    for field_name in ("authority_reference", "skg_constraint_digest"):
        if (
            not isinstance(package.get(field_name), str)
            or not package.get(field_name)
        ):
            failures.append(f"required_field_invalid:{field_name}")
    _exact_fields(
        package.get("jurisdiction"),
        frozenset({"jurisdiction_id", "scope"}),
        "jurisdiction_invalid",
        failures,
    )
    for field_name in ("operational_context", "environmental_context"):
        if (
            not isinstance(package.get(field_name), Mapping)
            or not package.get(field_name)
        ):
            failures.append(f"{field_name}_invalid")
    constraints = package.get("feasibility_constraints")
    if not isinstance(constraints, list) or not constraints:
        failures.append("feasibility_constraints_invalid")
    else:
        for item in constraints:
            if (
                not _exact_fields(
                    item,
                    frozenset({"constraint_id", "satisfied"}),
                    "feasibility_constraints_invalid",
                    failures,
                )
                or item.get("satisfied") is not True
            ):
                failures.append("feasibility_constraint_unsatisfied")
    dependencies = package.get("dependencies")
    dependency_ids: set[str] = set()
    if not isinstance(dependencies, list):
        failures.append("dependencies_invalid")
    else:
        for item in dependencies:
            if not _exact_fields(
                item,
                frozenset({"dependency_id", "available"}),
                "dependencies_invalid",
                failures,
            ):
                continue
            assert isinstance(item, Mapping)
            dependency_id = item.get("dependency_id")
            if not isinstance(dependency_id, str) or not dependency_id:
                failures.append("dependencies_invalid")
            else:
                dependency_ids.add(dependency_id)
            if item.get("available") is not True:
                failures.append("dependency_unavailable")
    pathway = package.get("pathway_viability")
    if _exact_fields(
        pathway,
        frozenset({
            "pathway_id", "viable", "required_dependency_ids",
        }),
        "pathway_viability_invalid",
        failures,
    ):
        if (
            not isinstance(pathway.get("pathway_id"), str)
            or not pathway.get("pathway_id")
            or pathway.get("viable") is not True
        ):
            failures.append("pathway_nonviable")
        required = pathway.get("required_dependency_ids")
        if (
            not _strings(required, nonempty=False)
            or not set(required).issubset(dependency_ids)
        ):
            failures.append("missing_dependency")
    risk = package.get("consequence_risk_context")
    if _exact_fields(
        risk,
        frozenset({"risk_level", "consequences"}),
        "consequence_risk_context_invalid",
        failures,
    ) and (
        not isinstance(risk.get("risk_level"), str)
        or not isinstance(risk.get("consequences"), list)
    ):
        failures.append("consequence_risk_context_invalid")
    return _result(failures)


def validate_synthetic_bridge(
    skg_package: Any,
    dtn_package: Any,
    *,
    validation_time: str,
    expected_request_fingerprint: str,
    expected_eie_digest: str,
    replay_registry: SyntheticReplayRegistry | None = None,
    verification_key: str | bytes | None = None,
) -> ValidationResult:
    skg = validate_synthetic_skg_package(
        skg_package,
        validation_time=validation_time,
        request_fingerprint=expected_request_fingerprint,
        eie_digest=expected_eie_digest,
        verification_key=verification_key,
    )
    dtn = validate_synthetic_dtn_package(
        dtn_package,
        validation_time=validation_time,
        request_fingerprint=expected_request_fingerprint,
        eie_digest=expected_eie_digest,
        skg_digest=(
            skg_package.get("digest")
            if isinstance(skg_package, Mapping)
            else None
        ),
        verification_key=verification_key,
    )
    failures = [*skg.failures, *dtn.failures]
    if (
        not isinstance(skg_package, Mapping)
        or not isinstance(dtn_package, Mapping)
    ):
        return _result(failures or ["bridge_package_invalid"])
    if (
        skg_package.get("request_fingerprint")
        != dtn_package.get("request_fingerprint")
    ):
        failures.append("cross_package_request_mismatch")
    if skg_package.get("eie_digest") != dtn_package.get("eie_digest"):
        failures.append("cross_package_eie_mismatch")
    skg_jurisdiction = skg_package.get(
        "jurisdiction", {}
    ).get("jurisdiction_id")
    dtn_jurisdiction = dtn_package.get(
        "jurisdiction", {}
    ).get("jurisdiction_id")
    if skg_jurisdiction != dtn_jurisdiction:
        failures.append("jurisdiction_conflict")
    authority_ids = {
        item.get("authority_id")
        for item in skg_package.get("authority_hierarchy", [])
        if isinstance(item, Mapping)
    }
    if dtn_package.get("authority_reference") not in authority_ids:
        failures.append("authority_conflict")
    if skg_package.get("issued_at") != dtn_package.get("issued_at"):
        failures.append("temporal_conflict")
    skg_sources = {
        item.get("source_id")
        for item in skg_package.get("provenance", [])
        if isinstance(item, Mapping)
    }
    dtn_sources = {
        item.get("source_id")
        for item in dtn_package.get("provenance", [])
        if isinstance(item, Mapping)
    }
    if skg_sources != dtn_sources:
        failures.append("provenance_conflict")
    prohibited = set(
        skg_package.get(
            "substrate_constraints", {}
        ).get("prohibited_pathway_ids", [])
    )
    pathway_id = dtn_package.get(
        "pathway_viability", {}
    ).get("pathway_id")
    if pathway_id in prohibited:
        failures.append("skg_dtn_pathway_conflict")
    if failures:
        return _result(failures)
    if replay_registry is not None:
        return replay_registry.validate_and_record(
            (skg_package, dtn_package)
        )
    return ValidationResult(True, ())


def validate_provider_mode(configuration: Any) -> ValidationResult:
    failures: list[str] = []

    def inspect(value: Any) -> None:
        if isinstance(value, Mapping):
            for raw_key, item in value.items():
                key = str(raw_key).strip().lower()
                if (
                    key in _CREDENTIAL_KEYS
                    or key.endswith(
                        ("_api_key", "_credential", "_secret", "_token")
                    )
                ):
                    failures.append("provider_credentials_denied")
                if key == "provider_mode" and item != PROVIDER_MODE:
                    failures.append("external_provider_mode_denied")
                if (
                    key in _PROVIDER_KEYS
                    and item not in (False, None, "", PROVIDER_MODE)
                ):
                    if isinstance(item, str) and _local_uri(item):
                        pass
                    else:
                        failures.append("live_provider_surface_denied")
                inspect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                inspect(item)
        elif isinstance(value, str):
            parsed = urlparse(value)
            if parsed.scheme.lower() in _LIVE_SCHEMES:
                failures.append("live_url_denied")
            lowered = value.strip().lower()
            if any(
                token in lowered
                for token in (
                    "production_sensor",
                    "live_ingestion",
                    "cloud_provider",
                )
            ):
                failures.append("live_provider_surface_denied")

    inspect(configuration)
    return _result(failures)


def forbidden_authority_vocabulary() -> dict[str, tuple[str, ...]]:
    return {
        "keys": tuple(sorted(PROHIBITED_AUTHORITY_KEYS)),
        "values": tuple(sorted(PROHIBITED_AUTHORITY_VALUES)),
    }
