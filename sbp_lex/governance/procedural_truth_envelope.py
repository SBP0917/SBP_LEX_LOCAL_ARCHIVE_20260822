from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from sbp_lex.config.thresholds import apply_thresholds
from sbp_lex.security.pqc import generate_digest


def source_is_qualified(source: object) -> bool:
    return (
        isinstance(source, Mapping)
        and bool(source.get("source") or source.get("source_id"))
        and bool(source.get("content") or source.get("content_digest") or source.get("digest"))
        and source.get("verified") is True
        and source.get("attested") is True
        and source.get("freshness_valid") is True
        and source.get("consistency_valid") is True
    )


def qualified_sources(sources: object) -> list[dict[str, Any]]:
    if not isinstance(sources, list):
        return []
    return [deepcopy(dict(source)) for source in sources if source_is_qualified(source)]


def _source_records(request: Mapping[str, Any], package: Mapping[str, Any]) -> list[dict[str, Any]]:
    package_records = package.get("source_records")
    if isinstance(package_records, list):
        return [deepcopy(dict(item)) for item in package_records if isinstance(item, Mapping)]
    evidence = request.get("context", {}).get("evidence", [])
    if not isinstance(evidence, list):
        return []
    return [deepcopy(dict(item)) for item in evidence if isinstance(item, Mapping)]


def _aggregate_status(records: list[dict[str, Any]], field: str) -> str:
    if not records:
        return "MISSING"
    return "VALID" if all(record.get(field) is True for record in records) else "INVALID"


def _bool_floor(records: list[dict[str, Any]], field: str, fallback: bool) -> bool:
    if not records:
        return False
    return all(record.get(field, fallback) is True for record in records)


def _source_independence(records: list[dict[str, Any]]) -> bool:
    identifiers = [
        str(record.get("source_id") or record.get("source") or record.get("source_uri") or "")
        for record in records
    ]
    identifiers = [identifier for identifier in identifiers if identifier]
    if not identifiers:
        return False
    if any(record.get("source_independent") is False for record in records):
        return False
    return len(set(identifiers)) == len(identifiers)


def _claim_mapping(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "evidence_to_claim_linkage": [
            {
                "source_id": record.get("source_id") or record.get("source"),
                "claim_id": record.get("claim_id", "primary_intent_claim"),
                "digest": record.get("digest") or record.get("content_digest"),
            }
            for record in records
        ],
        "claim_support_mapping": {
            str(record.get("claim_id", "primary_intent_claim")): record.get("digest") or record.get("content_digest")
            for record in records
        },
        "claim_conflict_mapping": [
            record for record in records if record.get("material_contradiction") is True
        ],
    }


def _skg_truth_foundation_metadata(package: Mapping[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    metadata = {
        "provenance_metadata": [
            {
                "source_id": record.get("source_id") or record.get("source"),
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
        "corroboration_metadata": deepcopy(dict(package.get("source_summary", {}))) if isinstance(package.get("source_summary"), Mapping) else {},
        "freshness_metadata": {"freshness_valid": package.get("freshness_valid")},
        "expiry_and_staleness_indicators": [record for record in records if record.get("freshness_valid") is not True],
        "consistency_information": {"consistency_valid": package.get("consistency_valid")},
        "contradiction_indicators": [record for record in records if record.get("material_contradiction") is True],
        "confidence_and_evidence_quality_metadata": package.get("evidence_quality", {}),
        "identity_relationships": package.get("identity_relationships", {}),
        "attestation_status": _aggregate_status(records, "attested"),
        "integrity_references": [record.get("digest") or record.get("content_digest") for record in records],
        "chain_of_custody_status": "VALID" if _bool_floor(records, "chain_of_custody_valid", True) else "INVALID",
        "jurisdictional_relevance": package.get("jurisdictional_relevance", "PRESERVED"),
        **_claim_mapping(records),
    }
    metadata["skg_verification_status"] = "VALID" if (
        package.get("skg_package_digest") or package.get("skg_digest")
    ) and records and _bool_floor(records, "verified", False) else "MISSING"
    metadata["truth_foundation_readiness_status"] = "READY" if metadata["skg_verification_status"] == "VALID" else "NOT_READY"
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
) -> tuple[dict[str, Any], str]:
    request_copy = deepcopy(dict(request))
    package = deepcopy(dict(admitted_pre_context or {}))
    request_fingerprint = generate_digest(request_copy)
    records = _source_records(request_copy, package)
    qualified = qualified_sources(records)

    threshold_state = apply_thresholds(
        {
            "safety_profile": deepcopy(request_copy.get("safety_profile", {})),
            "context": deepcopy(request_copy.get("context", {})),
            "governance_feedback": {},
        }
    )
    snapshot = threshold_state["governance_feedback"]["threshold_snapshot"]

    failures: list[str] = []
    if package.get("request_fingerprint") != request_fingerprint:
        failures.append("pt_envelope_request_fingerprint_mismatch")
    if not records:
        failures.append("pt_envelope_source_records_missing")
    for field, reason in (
        ("verified", "pt_source_unverified"),
        ("attested", "pt_source_unattested"),
        ("freshness_valid", "pt_source_stale"),
        ("consistency_valid", "pt_source_inconsistent"),
    ):
        if any(record.get(field) is not True for record in records):
            failures.append(reason)

    source_summary = package.get("source_summary")
    if not isinstance(source_summary, Mapping):
        source_summary = {
            "source_count": len(records),
            "source_identifiers": [
                str(record.get("source") or record.get("source_id") or "")
                for record in records
            ],
        }
    skg_metadata = deepcopy(dict(package.get("skg_truth_foundation_metadata", {}))) if isinstance(package.get("skg_truth_foundation_metadata"), Mapping) else _skg_truth_foundation_metadata(package, records)
    if "skg_enrichment_hash" not in skg_metadata:
        skg_metadata["skg_enrichment_hash"] = generate_digest(skg_metadata)
    dtn_metadata = deepcopy(dict(package.get("dtn_contextual_verification_metadata", {}))) if isinstance(package.get("dtn_contextual_verification_metadata"), Mapping) else _dtn_contextual_metadata(package)
    if "dtn_enrichment_hash" not in dtn_metadata:
        dtn_metadata["dtn_enrichment_hash"] = generate_digest(dtn_metadata)
    eie_hash = eie.get("eie_hash") if isinstance(eie, Mapping) else None

    envelope = {
        "request_fingerprint": request_fingerprint,
        "eie_hash": eie_hash,
        "traversal_id": eie.get("traversal_id") if isinstance(eie, Mapping) else None,
        "source_payload_hash": eie.get("source_payload_hash") if isinstance(eie, Mapping) else generate_digest(request_copy.get("payload", {})),
        "adapter_identity": eie.get("adapter_identity") if isinstance(eie, Mapping) else request_copy.get("adapter_identity", "LOCAL_RUNTIME_ADAPTER"),
        "source_system_identity": eie.get("source_system_identity") if isinstance(eie, Mapping) else request_copy.get("source_system_identity", "LOCAL_RUNTIME"),
        "skg_digest": package.get("skg_digest") or package.get("skg_package_digest"),
        "dtn_digest": package.get("dtn_digest") or package.get("dtn_package_digest"),
        "pre_context_digest": package.get("digest"),
        "skg_truth_foundation_metadata": skg_metadata,
        "dtn_contextual_verification_metadata": dtn_metadata,
        "source_summary": deepcopy(dict(source_summary)),
        "source_records": records,
        "verification_status": _aggregate_status(records, "verified"),
        "attestation_status": _aggregate_status(records, "attested"),
        "freshness_status": _aggregate_status(records, "freshness_valid"),
        "consistency_status": _aggregate_status(records, "consistency_valid"),
        "threshold_tier": snapshot["computed_tier"],
        "threshold_requirement": snapshot["corroboration_required"],
        "qualifying_source_count": len(qualified),
        "source_independence_status": "VALID" if _source_independence(records) else "INVALID",
        "provenance_status": "VALID" if _bool_floor(records, "provenance_valid", True) else "INVALID",
        "integrity_status": "VALID" if _bool_floor(records, "integrity_valid", True) else "INVALID",
        "authority_status": "VALID" if _bool_floor(records, "authority_valid", True) else "INVALID",
        "jurisdiction_status": "VALID" if _bool_floor(records, "jurisdiction_valid", True) else "INVALID",
        "runtime_validity_status": "VALID" if _bool_floor(records, "runtime_validity_valid", True) else "INVALID",
        "material_contradictions": any(record.get("material_contradiction") is True for record in records),
        "unresolved_contradictions": any(record.get("unresolved_contradiction") is True for record in records),
        "deterministic_failure_reasons": sorted(set(failures)),
    }
    return envelope, generate_digest(envelope)


def validate_pt_evidence_envelope(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    envelope = state.get("pt_evidence_envelope", {})
    failures: list[str] = []
    if not isinstance(envelope, Mapping):
        return False, ["pt_evidence_envelope_missing"]
    if state.get("pt_evidence_envelope_digest") != generate_digest(dict(envelope)):
        failures.append("pt_evidence_envelope_digest_mismatch")
    if envelope.get("request_fingerprint") != state.get("request_fingerprint"):
        failures.append("pt_envelope_request_fingerprint_mismatch")

    conditioned = apply_thresholds(state)
    snapshot = conditioned.get("governance_feedback", {}).get("threshold_snapshot", {})
    if envelope.get("threshold_tier") != snapshot.get("computed_tier"):
        failures.append("pt_threshold_tier_substitution")
    if envelope.get("threshold_requirement") != snapshot.get("corroboration_required"):
        failures.append("pt_threshold_requirement_relaxed")

    records = envelope.get("source_records", [])
    if envelope.get("qualifying_source_count") != len(qualified_sources(records)):
        failures.append("pt_qualifying_source_count_mismatch")
    return not failures, sorted(set(failures))
