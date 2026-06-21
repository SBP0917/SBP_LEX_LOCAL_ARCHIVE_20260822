from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from external_substrates.shared.digest import digest_mapping

SOURCE_FIELDS = {
    "source_id",
    "source_type",
    "source_uri",
    "verified",
    "attested",
    "freshness_valid",
    "consistency_valid",
    "retrieved_at",
    "digest",
}


def build_source_record(**values: Any) -> dict[str, Any]:
    record = deepcopy(values)
    record.setdefault("source_type", "declared")
    record.setdefault("source_uri", "local://declared")
    record.setdefault("verified", False)
    record.setdefault("attested", False)
    record.setdefault("freshness_valid", False)
    record.setdefault("consistency_valid", False)
    body = {key: value for key, value in record.items() if key != "digest"}
    record["digest"] = digest_mapping(body)
    return record


def validate_source_record(source: Mapping[str, Any]) -> bool:
    if not isinstance(source, Mapping) or not SOURCE_FIELDS.issubset(source):
        return False
    if not all(source.get(field) for field in ("source_id", "source_type", "source_uri", "retrieved_at")):
        return False
    if not all(
        isinstance(source.get(field), bool)
        for field in ("verified", "attested", "freshness_valid", "consistency_valid")
    ):
        return False
    body = {key: value for key, value in source.items() if key != "digest"}
    return source.get("digest") == digest_mapping(body)


def source_record_status(source: Mapping[str, Any]) -> dict[str, Any]:
    valid = validate_source_record(source)
    flags = {
        field: bool(source.get(field))
        for field in ("verified", "attested", "freshness_valid", "consistency_valid")
    }
    return {"valid": valid, **flags, "qualified": valid and all(flags.values())}


def count_attested_sources(sources: Sequence[Mapping[str, Any]]) -> int:
    return sum(1 for source in sources if source_record_status(source)["qualified"])


def summarise_sources(sources: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    statuses = [source_record_status(source) for source in sources]
    return {
        "total_sources": len(statuses),
        "verified_sources": sum(item["valid"] and item["verified"] for item in statuses),
        "attested_sources": sum(item["valid"] and item["attested"] for item in statuses),
        "fresh_sources": sum(item["valid"] and item["freshness_valid"] for item in statuses),
        "consistent_sources": sum(item["valid"] and item["consistency_valid"] for item in statuses),
    }
