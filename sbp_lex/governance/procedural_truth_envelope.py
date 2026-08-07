from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from sbp_lex.config.thresholds import apply_thresholds
from sbp_lex.security.pqc import generate_digest


PT_EVIDENCE_ENVELOPE_SCHEMA_VERSION = "desktop-v1.pt-evidence-envelope.v2"
PT_SOURCE_ASSESSMENT_SCHEMA_VERSION = "desktop-v1.pt-source-assessment.v1"
PT_SOURCE_BINDING_SCHEMA_VERSION = "desktop-v1.pt-source-binding.v1"
PT_QUALIFICATION_BASIS_SCHEMA_VERSION = "desktop-v1.pt-qualification-basis.v1"

_DERIVED_SOURCE_FIELDS = {
    "pt_binding",
    "pt_binding_digest",
    "pt_content_digest",
    "pt_declared_binding_failures",
    "pt_record_digest",
}
_QUALIFICATION_FLAGS = (
    "verified",
    "attested",
    "freshness_valid",
    "consistency_valid",
    "provenance_valid",
    "integrity_valid",
    "authority_valid",
    "jurisdiction_valid",
    "runtime_validity_valid",
    "chain_of_custody_valid",
    "relevance_valid",
)


def _source_id(source: Mapping[str, Any]) -> str:
    return str(source.get("source_id") or source.get("source") or "").strip()


def _source_uri(source: Mapping[str, Any]) -> str:
    return str(source.get("source_uri") or "").strip()


def _base_source_record(source: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in dict(source).items()
        if key not in _DERIVED_SOURCE_FIELDS
    }


def _record_digest_payload(source: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in _base_source_record(source).items()
        if key not in {"digest", "content_digest"}
    }


def _expected_content_digest(source: Mapping[str, Any]) -> str | None:
    content = source.get("content")
    if not isinstance(content, str) or not content:
        return None
    return generate_digest({"content": content})


def _expected_record_digest(source: Mapping[str, Any]) -> str:
    return generate_digest(_record_digest_payload(source))


def _binding_payload(
    *,
    request_fingerprint: str | None,
    eie_digest: str | None,
    collective_signal_digest: str | None,
    action_digest: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": PT_SOURCE_BINDING_SCHEMA_VERSION,
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie_digest,
        "collective_signal_digest": collective_signal_digest,
        "action_digest": action_digest,
    }


def _bound_source_record(
    source: Mapping[str, Any],
    *,
    request_fingerprint: str | None,
    eie_digest: str | None,
    collective_signal_digest: str | None,
    action_digest: str | None,
) -> dict[str, Any]:
    declared = deepcopy(dict(source))
    record = _base_source_record(source)
    binding = _binding_payload(
        request_fingerprint=request_fingerprint,
        eie_digest=eie_digest,
        collective_signal_digest=collective_signal_digest,
        action_digest=action_digest,
    )
    declared_binding_failures: list[str] = []
    for field, expected in (
        ("request_fingerprint", request_fingerprint),
        ("eie_digest", eie_digest),
        ("collective_signal_digest", collective_signal_digest),
        ("action_digest", action_digest),
    ):
        if field in declared and declared.get(field) != expected:
            declared_binding_failures.append(
                f"source_binding_mismatch:declared_{field}"
            )
    supplied_binding = declared.get("pt_binding")
    if supplied_binding is not None and (
        not isinstance(supplied_binding, Mapping)
        or dict(supplied_binding) != binding
    ):
        declared_binding_failures.append(
            "source_binding_mismatch:declared_pt_binding"
        )
    record["pt_binding"] = binding
    record["pt_binding_digest"] = generate_digest(binding)
    record["pt_content_digest"] = _expected_content_digest(record)
    record["pt_declared_binding_failures"] = sorted(
        set(declared_binding_failures)
    )
    record["pt_record_digest"] = _expected_record_digest(record)
    return record


def _qualification_basis(
    package: Mapping[str, Any],
    *,
    admitted_basis: Mapping[str, Any] | None,
    request_fingerprint: str,
    eie_digest: str | None,
    collective_signal_digest: str | None,
) -> dict[str, Any]:
    inline_substrate = package.get("synthetic_substrate_evidence", {})
    inline_substrate = (
        inline_substrate if isinstance(inline_substrate, Mapping) else {}
    )
    substrate = (
        admitted_basis
        if isinstance(admitted_basis, Mapping) and admitted_basis
        else inline_substrate
    )
    request_bound = (
        substrate.get("request_fingerprint", request_fingerprint)
        == request_fingerprint
    )
    eie_bound = substrate.get("eie_digest", eie_digest) == eie_digest
    valid = all(
        (
            substrate.get("skg_validation_status") == "VALID",
            substrate.get("dtn_validation_status") == "VALID",
            substrate.get("bridge_validation_status") == "PASS",
            request_bound,
            eie_bound,
            bool(collective_signal_digest),
        )
    )
    payload = {
        "schema_version": PT_QUALIFICATION_BASIS_SCHEMA_VERSION,
        "basis_type": "ADMITTED_SIGNED_SYNTHETIC_BOUNDARY",
        "status": "VALID" if valid else "INVALID",
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie_digest,
        "collective_signal_digest": collective_signal_digest,
        "skg_package_digest": substrate.get("skg_package_digest"),
        "dtn_package_digest": substrate.get("dtn_package_digest"),
        "bridge_result_digest": substrate.get("bridge_result_digest"),
        "skg_validation_status": substrate.get("skg_validation_status"),
        "dtn_validation_status": substrate.get("dtn_validation_status"),
        "bridge_validation_status": substrate.get("bridge_validation_status"),
    }
    return {**payload, "qualification_basis_digest": generate_digest(payload)}


def _derived_validity(
    source: Mapping[str, Any],
    *,
    field: str,
    boundary_basis_valid: bool,
    binding_valid: bool,
    digest_valid: bool,
    identity_valid: bool,
    action_digest: str | None,
) -> tuple[bool, str]:
    explicit = source.get(field)
    if explicit is not None:
        return explicit is True, "EXPLICIT_SOURCE_ASSERTION"
    if field in {"verified", "attested", "freshness_valid", "consistency_valid"}:
        return False, "MISSING_REQUIRED_SOURCE_ASSERTION"
    if field == "provenance_valid":
        return (
            boundary_basis_valid and binding_valid and identity_valid,
            "DERIVED_ADMITTED_BOUNDARY_AND_STABLE_IDENTITY",
        )
    if field == "integrity_valid":
        return (
            boundary_basis_valid and binding_valid and digest_valid,
            "DERIVED_ADMITTED_BOUNDARY_AND_CANONICAL_DIGEST",
        )
    if field == "relevance_valid":
        claim_id = str(source.get("claim_id", "primary_intent_claim"))
        return (
            boundary_basis_valid
            and binding_valid
            and bool(action_digest)
            and claim_id == "primary_intent_claim",
            "DERIVED_PROTECTED_REQUEST_ACTION_BINDING",
        )
    return (
        boundary_basis_valid and binding_valid,
        "DERIVED_ADMITTED_BOUNDARY_BINDING",
    )


def assess_source_records(
    sources: object,
    *,
    request_fingerprint: str | None = None,
    eie_digest: str | None = None,
    collective_signal_digest: str | None = None,
    action_digest: str | None = None,
    qualification_basis: Mapping[str, Any] | None = None,
    corroboration_required: int = 0,
) -> dict[str, Any]:
    records = sources if isinstance(sources, list) else []
    basis = qualification_basis if isinstance(qualification_basis, Mapping) else {}
    boundary_basis_valid = basis.get("status") == "VALID"
    expected_binding = _binding_payload(
        request_fingerprint=request_fingerprint,
        eie_digest=eie_digest,
        collective_signal_digest=collective_signal_digest,
        action_digest=action_digest,
    )

    seen_primary: set[str] = set()
    seen_source_ids: set[str] = set()
    seen_source_uris: set[str] = set()
    seen_record_digests: set[str] = set()
    record_results: list[dict[str, Any]] = []
    qualifying_records: list[dict[str, Any]] = []
    duplicate_reasons: list[str] = []
    duplicate_record_count = 0
    rejection_reasons: list[str] = []

    for index, item in enumerate(records):
        reasons: list[str] = []
        derivations: dict[str, str] = {}
        if not isinstance(item, Mapping):
            record_results.append(
                {
                    "index": index,
                    "qualified": False,
                    "reasons": ["source_not_mapping"],
                }
            )
            rejection_reasons.append(f"source:{index}:source_not_mapping")
            continue

        source = deepcopy(dict(item))
        source_id = _source_id(source)
        source_uri = _source_uri(source)
        primary_identity = source_uri or source_id
        identity_valid = bool(source_id and primary_identity)
        if not identity_valid:
            reasons.append("source_identity_missing")
        if not (
            isinstance(source.get("content"), str) and source.get("content")
        ) and not source.get("content_digest"):
            reasons.append("source_content_missing")

        binding = source.get("pt_binding")
        binding_valid = (
            isinstance(binding, Mapping)
            and dict(binding) == expected_binding
            and source.get("pt_binding_digest") == generate_digest(expected_binding)
        )
        if not binding_valid:
            reasons.append("source_binding_mismatch")
        declared_binding_failures = source.get(
            "pt_declared_binding_failures", []
        )
        if not isinstance(declared_binding_failures, list):
            reasons.append("declared_source_binding_failures_malformed")
        else:
            reasons.extend(str(reason) for reason in declared_binding_failures)

        expected_content_digest = _expected_content_digest(source)
        declared_content_digest = source.get("content_digest")
        content_digest_valid = (
            expected_content_digest is not None
            and (
                declared_content_digest is None
                or declared_content_digest == expected_content_digest
            )
            and source.get("pt_content_digest") == expected_content_digest
        )
        expected_record_digest = _expected_record_digest(source)
        declared_record_digest = source.get("digest")
        record_digest_valid = (
            (
                declared_record_digest is None
                or declared_record_digest == expected_record_digest
            )
            and source.get("pt_record_digest") == expected_record_digest
        )
        digest_valid = content_digest_valid and record_digest_valid
        if not digest_valid:
            reasons.append("source_digest_invalid")

        validity: dict[str, bool] = {}
        for field in _QUALIFICATION_FLAGS:
            valid, basis_name = _derived_validity(
                source,
                field=field,
                boundary_basis_valid=boundary_basis_valid,
                binding_valid=binding_valid,
                digest_valid=digest_valid,
                identity_valid=identity_valid,
                action_digest=action_digest,
            )
            validity[field] = valid
            derivations[field] = basis_name
            if not valid:
                reasons.append(f"{field}_not_valid")

        if source.get("material_contradiction") is True:
            reasons.append("material_contradiction")
        if source.get("unresolved_contradiction") is True:
            reasons.append("unresolved_contradiction")
        if source.get("source_independent") is False:
            reasons.append("source_declared_non_independent")

        duplicate_for: list[str] = []
        if primary_identity and primary_identity in seen_primary:
            duplicate_for.append("duplicate_primary_identity")
        if source_id and source_id in seen_source_ids:
            duplicate_for.append("duplicate_source_identity")
        if source_uri and source_uri in seen_source_uris:
            duplicate_for.append("duplicate_provenance_identity")
        if expected_record_digest in seen_record_digests:
            duplicate_for.append("duplicate_evidence_record")
        reasons.extend(duplicate_for)
        if duplicate_for:
            duplicate_record_count += 1
        for reason in duplicate_for:
            duplicate_reasons.append(f"source:{index}:{reason}")

        unique = not duplicate_for
        qualified = not reasons and unique
        result = {
            "index": index,
            "source_identity": source_id,
            "provenance_identity": source_uri or source_id,
            "primary_identity": primary_identity,
            "record_digest": expected_record_digest,
            "binding_digest": source.get("pt_binding_digest"),
            "qualification_basis": derivations,
            "validity": validity,
            "unique": unique,
            "qualified": qualified,
            "reasons": sorted(set(reasons)),
        }
        record_results.append(result)
        if qualified:
            qualifying_records.append(deepcopy(source))
        else:
            rejection_reasons.extend(
                f"source:{index}:{reason}" for reason in result["reasons"]
            )

        if primary_identity:
            seen_primary.add(primary_identity)
        if source_id:
            seen_source_ids.add(source_id)
        if source_uri:
            seen_source_uris.add(source_uri)
        seen_record_digests.add(expected_record_digest)

    def dimension_status(field: str) -> str:
        if not record_results:
            return "MISSING"
        return (
            "VALID"
            if all(
                result.get("validity", {}).get(field) is True
                for result in record_results
            )
            else "INVALID"
        )

    unique_count = len(qualifying_records)
    independence_valid = (
        bool(record_results)
        and not duplicate_reasons
        and all(
            result.get("unique") is True
            and "source_declared_non_independent"
            not in result.get("reasons", [])
            for result in record_results
        )
    )
    unresolved = any(
        "unresolved_contradiction" in result.get("reasons", [])
        for result in record_results
    )
    material = any(
        "material_contradiction" in result.get("reasons", [])
        for result in record_results
    )
    completeness_valid = bool(records) and all(
        result.get("qualified") is True for result in record_results
    )
    floor_met = unique_count >= max(0, int(corroboration_required))
    sufficiency_valid = (
        floor_met
        and completeness_valid
        and independence_valid
        and not unresolved
        and not material
    )
    sufficiency_reasons = sorted(
        set(
            rejection_reasons
            + ([] if floor_met else ["qualifying_source_floor_not_met"])
            + ([] if independence_valid else ["source_independence_not_met"])
            + ([] if completeness_valid else ["evidence_completeness_not_met"])
            + ([] if not unresolved else ["unresolved_material_contradiction"])
        )
    )
    assessment_payload = {
        "schema_version": PT_SOURCE_ASSESSMENT_SCHEMA_VERSION,
        "source_count_total": len(records),
        "source_count_qualifying": unique_count,
        "source_count_rejected": len(records) - unique_count,
        "source_count_duplicates": duplicate_record_count,
        "corroboration_required": max(0, int(corroboration_required)),
        "corroboration_observed": unique_count,
        "source_floor_met": floor_met,
        "verification_result": dimension_status("verified"),
        "attestation_result": dimension_status("attested"),
        "freshness_result": dimension_status("freshness_valid"),
        "consistency_result": dimension_status("consistency_valid"),
        "provenance_result": dimension_status("provenance_valid"),
        "integrity_result": dimension_status("integrity_valid"),
        "authority_result": dimension_status("authority_valid"),
        "jurisdiction_result": dimension_status("jurisdiction_valid"),
        "runtime_validity_result": dimension_status("runtime_validity_valid"),
        "chain_of_custody_result": dimension_status("chain_of_custody_valid"),
        "relevance_result": dimension_status("relevance_valid"),
        "source_independence_result": "VALID" if independence_valid else "INVALID",
        "evidence_completeness_result": "PASS" if completeness_valid else "FAIL",
        "evidentiary_sufficiency_result": (
            "SUFFICIENT" if sufficiency_valid else "INSUFFICIENT"
        ),
        "material_contradictions": material,
        "unresolved_contradictions": unresolved,
        "source_identity_summary": [
            {
                "source_identity": result.get("source_identity"),
                "provenance_identity": result.get("provenance_identity"),
                "record_digest": result.get("record_digest"),
                "qualified": result.get("qualified"),
            }
            for result in record_results
        ],
        "record_results": record_results,
        "duplicate_reasons": sorted(set(duplicate_reasons)),
        "rejection_reasons": sorted(set(rejection_reasons)),
        "sufficiency_reasons": sufficiency_reasons,
    }
    sufficiency_payload = {
        "schema_version": "desktop-v1.evidentiary-sufficiency.v1",
        "source_count_total": assessment_payload["source_count_total"],
        "source_count_qualifying": assessment_payload[
            "source_count_qualifying"
        ],
        "corroboration_required": assessment_payload[
            "corroboration_required"
        ],
        "source_floor_met": assessment_payload["source_floor_met"],
        "source_independence_result": assessment_payload[
            "source_independence_result"
        ],
        "verification_result": assessment_payload["verification_result"],
        "attestation_result": assessment_payload["attestation_result"],
        "freshness_result": assessment_payload["freshness_result"],
        "consistency_result": assessment_payload["consistency_result"],
        "provenance_result": assessment_payload["provenance_result"],
        "integrity_result": assessment_payload["integrity_result"],
        "relevance_result": assessment_payload["relevance_result"],
        "evidence_completeness_result": assessment_payload[
            "evidence_completeness_result"
        ],
        "material_contradictions": assessment_payload[
            "material_contradictions"
        ],
        "unresolved_contradictions": assessment_payload[
            "unresolved_contradictions"
        ],
        "evidentiary_sufficiency_result": assessment_payload[
            "evidentiary_sufficiency_result"
        ],
        "sufficiency_reasons": sufficiency_reasons,
    }
    assessment_payload["evidentiary_sufficiency_digest"] = generate_digest(
        sufficiency_payload
    )
    assessment_digest = generate_digest(assessment_payload)
    return {
        **assessment_payload,
        "source_assessment_digest": assessment_digest,
        "qualifying_records": qualifying_records,
    }


def source_is_qualified(source: object) -> bool:
    if not isinstance(source, Mapping):
        return False
    source_id = _source_id(source)
    content_present = bool(
        source.get("content")
        or source.get("content_digest")
        or source.get("digest")
    )
    return (
        bool(source_id)
        and content_present
        and source.get("verified") is True
        and source.get("attested") is True
        and source.get("freshness_valid") is True
        and source.get("consistency_valid") is True
        and source.get("source_independent") is not False
        and source.get("material_contradiction") is not True
        and source.get("unresolved_contradiction") is not True
    )


def qualified_sources(sources: object) -> list[dict[str, Any]]:
    if not isinstance(sources, list):
        return []
    seen_primary: set[str] = set()
    seen_ids: set[str] = set()
    result: list[dict[str, Any]] = []
    for source in sources:
        if not isinstance(source, Mapping) or not source_is_qualified(source):
            continue
        source_id = _source_id(source)
        primary = _source_uri(source) or source_id
        if primary in seen_primary or source_id in seen_ids:
            continue
        seen_primary.add(primary)
        seen_ids.add(source_id)
        result.append(deepcopy(dict(source)))
    return result


def _source_records(
    request: Mapping[str, Any], package: Mapping[str, Any]
) -> list[dict[str, Any]]:
    # Canonical Desktop V1 source claims originate in the protected request.
    # External package source records describe substrate provenance and must not
    # replace the request's evidentiary claims.
    evidence = request.get("context", {}).get("evidence", [])
    if not isinstance(evidence, list):
        return []
    return [
        deepcopy(dict(item)) for item in evidence if isinstance(item, Mapping)
    ]


def _aggregate_status(records: list[dict[str, Any]], field: str) -> str:
    if not records:
        return "MISSING"
    return "VALID" if all(record.get(field) is True for record in records) else "INVALID"


def _bool_floor(records: list[dict[str, Any]], field: str) -> bool:
    return bool(records) and all(record.get(field) is True for record in records)


def _source_independence(records: list[dict[str, Any]]) -> bool:
    seen_ids: set[str] = set()
    seen_uris: set[str] = set()
    for record in records:
        source_id = _source_id(record)
        source_uri = _source_uri(record)
        if not source_id or source_id in seen_ids:
            return False
        if source_uri and source_uri in seen_uris:
            return False
        if record.get("source_independent") is False:
            return False
        seen_ids.add(source_id)
        if source_uri:
            seen_uris.add(source_uri)
    return bool(records)


def _claim_mapping(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "evidence_to_claim_linkage": [
            {
                "source_id": _source_id(record),
                "claim_id": record.get("claim_id", "primary_intent_claim"),
                "digest": record.get("pt_record_digest"),
            }
            for record in records
        ],
        "claim_support_mapping": {
            str(record.get("claim_id", "primary_intent_claim")): record.get(
                "pt_record_digest"
            )
            for record in records
        },
        "claim_conflict_mapping": [
            record for record in records if record.get("material_contradiction") is True
        ],
    }


def _skg_truth_foundation_metadata(
    package: Mapping[str, Any],
    records: list[dict[str, Any]],
    qualification_basis: Mapping[str, Any],
) -> dict[str, Any]:
    metadata = {
        "provenance_metadata": [
            {
                "source_id": _source_id(record),
                "source_type": record.get("source_type"),
                "source_uri": record.get("source_uri"),
                "retrieved_at": record.get("retrieved_at"),
            }
            for record in records
        ],
        "source_origin_metadata": [record.get("source_uri") for record in records],
        "source_relationship_mapping": package.get("source_relationship_mapping", {}),
        "source_independence_mapping": {
            "independent": _source_independence(records),
            "source_count": len(records),
        },
        "authority_relationship_mapping": package.get("authority_relationship_mapping", {}),
        "corroboration_metadata": {},
        "freshness_metadata": {"freshness_valid": _bool_floor(records, "freshness_valid")},
        "expiry_and_staleness_indicators": [
            record for record in records if record.get("freshness_valid") is not True
        ],
        "consistency_information": {
            "consistency_valid": _bool_floor(records, "consistency_valid")
        },
        "contradiction_indicators": [
            record for record in records if record.get("material_contradiction") is True
        ],
        "confidence_and_evidence_quality_metadata": package.get("evidence_quality", {}),
        "identity_relationships": package.get("identity_relationships", {}),
        "attestation_status": _aggregate_status(records, "attested"),
        "integrity_references": [record.get("pt_record_digest") for record in records],
        "chain_of_custody_status": "VALID" if _bool_floor(records, "chain_of_custody_valid") else "DERIVED_AT_PT",
        "jurisdictional_relevance": package.get("jurisdictional_relevance", "PRESERVED"),
        **_claim_mapping(records),
    }
    # Root validates the admitted SKG substrate, while PT independently
    # qualifies each claim source.  A source-level verification failure must
    # reduce PT corroboration; it must not rewrite the already-admitted SKG
    # substrate status and prevent PT from producing its required outcome.
    substrate_valid = all(
        (
            qualification_basis.get("status") == "VALID",
            qualification_basis.get("skg_validation_status") == "VALID",
            bool(qualification_basis.get("skg_package_digest")),
        )
    )
    metadata["skg_verification_status"] = (
        "VALID" if substrate_valid else "MISSING"
    )
    metadata["truth_foundation_readiness_status"] = (
        "READY" if metadata["skg_verification_status"] == "VALID" else "NOT_READY"
    )
    metadata["skg_enrichment_hash"] = generate_digest(metadata)
    return metadata


def _dtn_contextual_metadata(package: Mapping[str, Any]) -> dict[str, Any]:
    signals = package.get("signals", {}) if isinstance(package.get("signals"), Mapping) else {}
    operational = package.get("operational_context_signal") or signals.get("operational_context_signal", {})
    risk = package.get("risk_potential_signal") or signals.get("risk_potential_signal", {})
    dependency = package.get("dependency_signal") or signals.get("dependency_signal", {})
    cascading = package.get("cascading_impact_signal") or signals.get("cascading_impact_signal", {})
    metadata = {
        "locality_context": package.get("locality_context", {}),
        "landscape_context": package.get("landscape_context", {}),
        "close_proximity_situational_context": package.get("proximity_context", {}),
        "operational_state_context": operational,
        "environmental_context": package.get("environmental_context", {}),
        "infrastructure_relevance": package.get("infrastructure_relevance", {}),
        "system_state_relevance": package.get("system_state_relevance", {}),
        "runtime_world_correspondence": package.get("runtime_world_correspondence", package.get("freshness_valid") is True),
        "physical_world_digital_state_alignment": package.get("physical_world_digital_state_alignment", package.get("consistency_valid") is True),
        "consequence_context": risk,
        "affected_assets": package.get("affected_assets", []),
        "affected_dependencies": dependency,
        "cascading_effect_indicators": cascading,
        "state_correspondence_verification": package.get("state_correspondence_verification", package.get("consistency_valid") is True),
    }
    metadata["dtn_contextualisation_status"] = "VALID" if package.get("dtn_package_digest") or package.get("dtn_digest") else "MISSING"
    metadata["contextual_readiness_status"] = "READY" if metadata["dtn_contextualisation_status"] == "VALID" else "NOT_READY"
    metadata["dtn_enrichment_hash"] = generate_digest(metadata)
    return metadata


def build_pt_evidence_envelope(
    request: Mapping[str, Any],
    admitted_pre_context: Mapping[str, Any] | None,
    *,
    eie: Mapping[str, Any] | None = None,
    admitted_basis: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    request_copy = deepcopy(dict(request))
    package = deepcopy(dict(admitted_pre_context or {}))
    request_fingerprint = generate_digest(request_copy)
    eie_digest = eie.get("eie_hash") if isinstance(eie, Mapping) else None
    collective_signal_digest = package.get("digest")
    action_digest = generate_digest(
        {
            "action": request_copy.get("action"),
            "objective": request_copy.get("objective"),
        }
    )
    raw_records = _source_records(request_copy, package)
    records = [
        _bound_source_record(
            record,
            request_fingerprint=request_fingerprint,
            eie_digest=eie_digest,
            collective_signal_digest=collective_signal_digest,
            action_digest=action_digest,
        )
        for record in raw_records
    ]

    threshold_state = apply_thresholds(
        {
            "request_identity_snapshot": deepcopy(request_copy),
            "request_fingerprint": request_fingerprint,
            "eie_hash": eie_digest,
            "collective_signal_evidence": {
                "signal_digest": collective_signal_digest
            },
            "safety_profile": deepcopy(request_copy.get("safety_profile", {})),
            "context": deepcopy(request_copy.get("context", {})),
            "governance_feedback": {},
        }
    )
    snapshot = threshold_state["governance_feedback"]["threshold_snapshot"]
    qualification_basis = _qualification_basis(
        package,
        admitted_basis=admitted_basis,
        request_fingerprint=request_fingerprint,
        eie_digest=eie_digest,
        collective_signal_digest=collective_signal_digest,
    )
    assessment = assess_source_records(
        records,
        request_fingerprint=request_fingerprint,
        eie_digest=eie_digest,
        collective_signal_digest=collective_signal_digest,
        action_digest=action_digest,
        qualification_basis=qualification_basis,
        corroboration_required=snapshot["corroboration_required"],
    )
    qualifying_records = assessment.pop("qualifying_records")

    failures: list[str] = []
    if package.get("request_fingerprint") != request_fingerprint:
        failures.append("pt_envelope_request_fingerprint_mismatch")
    if package.get("eie_digest") != eie_digest:
        failures.append("pt_envelope_eie_digest_mismatch")
    if not records:
        failures.append("pt_envelope_source_records_missing")
    failures.extend(snapshot.get("validation_failures", []))
    failures.extend(assessment.get("sufficiency_reasons", []))

    source_summary = {
        "source_count": assessment["source_count_total"],
        "qualifying_source_count": assessment["source_count_qualifying"],
        "rejected_source_count": assessment["source_count_rejected"],
        "duplicate_source_count": assessment["source_count_duplicates"],
        "source_identifiers": [
            item.get("source_identity")
            for item in assessment["source_identity_summary"]
        ],
    }
    skg_metadata = _skg_truth_foundation_metadata(
        package, records, qualification_basis
    )
    dtn_metadata = _dtn_contextual_metadata(package)

    envelope = {
        "schema_version": PT_EVIDENCE_ENVELOPE_SCHEMA_VERSION,
        "request_fingerprint": request_fingerprint,
        "eie_hash": eie_digest,
        "collective_signal_digest": collective_signal_digest,
        "action_digest": action_digest,
        "traversal_id": eie.get("traversal_id") if isinstance(eie, Mapping) else None,
        "source_payload_hash": eie.get("source_payload_hash") if isinstance(eie, Mapping) else generate_digest(request_copy.get("payload", {})),
        "adapter_identity": eie.get("adapter_identity") if isinstance(eie, Mapping) else request_copy.get("adapter_identity", "LOCAL_RUNTIME_ADAPTER"),
        "source_system_identity": eie.get("source_system_identity") if isinstance(eie, Mapping) else request_copy.get("source_system_identity", "LOCAL_RUNTIME"),
        "skg_digest": package.get("skg_digest") or package.get("skg_package_digest"),
        "dtn_digest": package.get("dtn_digest") or package.get("dtn_package_digest"),
        "pre_context_digest": collective_signal_digest,
        "skg_truth_foundation_metadata": skg_metadata,
        "dtn_contextual_verification_metadata": dtn_metadata,
        "qualification_basis": qualification_basis,
        "source_origin_digest": generate_digest(raw_records),
        "source_set_digest": generate_digest(records),
        "source_summary": source_summary,
        "source_records": records,
        "source_assessment": assessment,
        "source_assessment_digest": assessment["source_assessment_digest"],
        "verification_status": assessment["verification_result"],
        "attestation_status": assessment["attestation_result"],
        "freshness_status": assessment["freshness_result"],
        "consistency_status": assessment["consistency_result"],
        "threshold_tier": snapshot["computed_tier"],
        "threshold_requirement": snapshot["corroboration_required"],
        "threshold_state_digest": snapshot["threshold_state_digest"],
        "qualifying_source_count": len(qualifying_records),
        "source_independence_status": assessment["source_independence_result"],
        "provenance_status": assessment["provenance_result"],
        "integrity_status": assessment["integrity_result"],
        "authority_status": assessment["authority_result"],
        "jurisdiction_status": assessment["jurisdiction_result"],
        "runtime_validity_status": assessment["runtime_validity_result"],
        "relevance_status": assessment["relevance_result"],
        "evidence_completeness_result": assessment["evidence_completeness_result"],
        "evidentiary_sufficiency_result": assessment["evidentiary_sufficiency_result"],
        "material_contradictions": assessment["material_contradictions"],
        "unresolved_contradictions": assessment["unresolved_contradictions"],
        "deterministic_failure_reasons": sorted(set(failures)),
    }
    return envelope, generate_digest(envelope)


def validate_pt_evidence_envelope(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    envelope = state.get("pt_evidence_envelope", {})
    failures: list[str] = []
    if not isinstance(envelope, Mapping):
        return False, ["pt_evidence_envelope_missing"]
    if envelope.get("schema_version") != PT_EVIDENCE_ENVELOPE_SCHEMA_VERSION:
        failures.append("pt_evidence_envelope_schema_invalid")
    if state.get("pt_evidence_envelope_digest") != generate_digest(dict(envelope)):
        failures.append("pt_evidence_envelope_digest_mismatch")
    if envelope.get("request_fingerprint") != state.get("request_fingerprint"):
        failures.append("pt_envelope_request_fingerprint_mismatch")
    if envelope.get("eie_hash") != state.get("eie_hash"):
        failures.append("pt_envelope_eie_digest_mismatch")
    collective_digest = state.get("collective_signal_evidence", {}).get(
        "signal_digest"
    )
    if envelope.get("collective_signal_digest") != collective_digest:
        failures.append("pt_envelope_collective_signal_digest_mismatch")
    if envelope.get("pre_context_digest") != collective_digest:
        failures.append("pt_envelope_pre_context_digest_mismatch")

    request_snapshot = state.get("request_identity_snapshot", {})
    request_snapshot = request_snapshot if isinstance(request_snapshot, Mapping) else {}
    raw_sources = request_snapshot.get("context", {}).get("evidence", [])
    if not isinstance(raw_sources, list):
        raw_sources = []
    if envelope.get("source_origin_digest") != generate_digest(raw_sources):
        failures.append("pt_source_origin_digest_mismatch")
    action_digest = generate_digest(
        {
            "action": request_snapshot.get("action"),
            "objective": request_snapshot.get("objective"),
        }
    )
    if envelope.get("action_digest") != action_digest:
        failures.append("pt_action_relevance_binding_mismatch")

    basis = envelope.get("qualification_basis", {})
    basis = basis if isinstance(basis, Mapping) else {}
    basis_payload = {
        key: deepcopy(value)
        for key, value in dict(basis).items()
        if key != "qualification_basis_digest"
    }
    if basis.get("qualification_basis_digest") != generate_digest(basis_payload):
        failures.append("pt_qualification_basis_digest_mismatch")
    references = state.get("verified_substrate_references", {})
    references = references if isinstance(references, Mapping) else {}
    for basis_field, reference_field in (
        ("skg_package_digest", "skg_package_digest"),
        ("dtn_package_digest", "dtn_package_digest"),
        ("bridge_result_digest", "bridge_result_digest"),
    ):
        if basis.get(basis_field) != references.get(reference_field):
            failures.append(f"pt_qualification_basis_mismatch:{basis_field}")
    if basis.get("request_fingerprint") != state.get("request_fingerprint"):
        failures.append("pt_qualification_request_mismatch")
    if basis.get("eie_digest") != state.get("eie_hash"):
        failures.append("pt_qualification_eie_mismatch")
    if basis.get("collective_signal_digest") != collective_digest:
        failures.append("pt_qualification_collective_signal_mismatch")
    if basis.get("status") != "VALID":
        failures.append("pt_qualification_basis_invalid")

    conditioned = apply_thresholds(
        {
            "request_identity_snapshot": deepcopy(request_snapshot),
            "request_fingerprint": state.get("request_fingerprint"),
            "eie_hash": state.get("eie_hash"),
            "collective_signal_evidence": {
                "signal_digest": collective_digest
            },
            "safety_profile": deepcopy(request_snapshot.get("safety_profile", {})),
            "context": deepcopy(request_snapshot.get("context", {})),
            "governance_feedback": {},
        }
    )
    snapshot = conditioned.get("governance_feedback", {}).get(
        "threshold_snapshot", {}
    )
    if envelope.get("threshold_tier") != snapshot.get("computed_tier"):
        failures.append("pt_threshold_tier_substitution")
    if envelope.get("threshold_requirement") != snapshot.get(
        "corroboration_required"
    ):
        failures.append("pt_threshold_requirement_relaxed")
    if envelope.get("threshold_state_digest") != snapshot.get(
        "threshold_state_digest"
    ):
        failures.append("pt_threshold_state_digest_mismatch")

    records = envelope.get("source_records", [])
    if envelope.get("source_set_digest") != generate_digest(records):
        failures.append("pt_source_set_digest_mismatch")
    expected_assessment = assess_source_records(
        records,
        request_fingerprint=state.get("request_fingerprint"),
        eie_digest=state.get("eie_hash"),
        collective_signal_digest=collective_digest,
        action_digest=action_digest,
        qualification_basis=basis,
        corroboration_required=snapshot.get("corroboration_required", 0),
    )
    expected_assessment.pop("qualifying_records", None)
    actual_assessment = envelope.get("source_assessment", {})
    if actual_assessment != expected_assessment:
        failures.append("pt_source_assessment_mismatch")
    if envelope.get("source_assessment_digest") != expected_assessment.get(
        "source_assessment_digest"
    ):
        failures.append("pt_source_assessment_digest_mismatch")
    expected_projection = {
        "qualifying_source_count": expected_assessment.get(
            "source_count_qualifying"
        ),
        "verification_status": expected_assessment.get("verification_result"),
        "attestation_status": expected_assessment.get("attestation_result"),
        "freshness_status": expected_assessment.get("freshness_result"),
        "consistency_status": expected_assessment.get("consistency_result"),
        "source_independence_status": expected_assessment.get(
            "source_independence_result"
        ),
        "provenance_status": expected_assessment.get("provenance_result"),
        "integrity_status": expected_assessment.get("integrity_result"),
        "authority_status": expected_assessment.get("authority_result"),
        "jurisdiction_status": expected_assessment.get("jurisdiction_result"),
        "runtime_validity_status": expected_assessment.get(
            "runtime_validity_result"
        ),
        "relevance_status": expected_assessment.get("relevance_result"),
        "evidence_completeness_result": expected_assessment.get(
            "evidence_completeness_result"
        ),
        "evidentiary_sufficiency_result": expected_assessment.get(
            "evidentiary_sufficiency_result"
        ),
    }
    for field, expected in expected_projection.items():
        if envelope.get(field) != expected:
            failures.append(f"pt_envelope_projection_mismatch:{field}")
    return not failures, sorted(set(failures))
