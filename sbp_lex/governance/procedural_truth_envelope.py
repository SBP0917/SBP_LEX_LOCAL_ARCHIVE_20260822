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


def build_pt_evidence_envelope(
    request: Mapping[str, Any], admitted_pre_context: Mapping[str, Any] | None
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

    envelope = {
        "request_fingerprint": request_fingerprint,
        "skg_digest": package.get("skg_digest") or package.get("skg_package_digest"),
        "dtn_digest": package.get("dtn_digest") or package.get("dtn_package_digest"),
        "pre_context_digest": package.get("digest"),
        "source_summary": deepcopy(dict(source_summary)),
        "source_records": records,
        "verification_status": _aggregate_status(records, "verified"),
        "attestation_status": _aggregate_status(records, "attested"),
        "freshness_status": _aggregate_status(records, "freshness_valid"),
        "consistency_status": _aggregate_status(records, "consistency_valid"),
        "threshold_tier": snapshot["computed_tier"],
        "threshold_requirement": snapshot["corroboration_required"],
        "qualifying_source_count": len(qualified),
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
