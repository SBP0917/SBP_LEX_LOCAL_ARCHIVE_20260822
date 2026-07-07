from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.state_builder import build_state

PHASE19A_FIXTURE_TIMESTAMP = "2026-07-08T00:00:00Z"


def build_eie_fixture(request: Mapping[str, Any]) -> dict[str, Any]:
    state = build_state(dict(request))
    eie = deepcopy(dict(state["eie"]))
    eie["fixture_timestamp"] = PHASE19A_FIXTURE_TIMESTAMP
    eie["freshness_status"] = "FRESH"
    eie["fixture_digest"] = generate_digest(
        {key: value for key, value in eie.items() if key != "fixture_digest"}
    )
    return eie


def validate_eie_fixture(
    fixture: Mapping[str, Any], *, request: Mapping[str, Any] | None = None
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(fixture, Mapping):
        return False, ["eie_fixture_not_mapping"]
    required = {
        "object_type",
        "eie_version",
        "canonical_traversal_state",
        "request_fingerprint",
        "traversal_id",
        "eie_hash",
        "freshness_status",
        "fixture_digest",
    }
    missing = required.difference(fixture)
    failures.extend(f"eie_fixture_missing:{field}" for field in sorted(missing))
    if fixture.get("object_type") != "ExecutionIntentEnvelope":
        failures.append("eie_malformed_object_type")
    if fixture.get("canonical_traversal_state") is not True:
        failures.append("eie_not_canonical_traversal_state")
    if fixture.get("freshness_status") != "FRESH":
        failures.append("eie_stale")
    if request is not None and fixture.get("request_fingerprint") != generate_digest(dict(request)):
        failures.append("eie_unbound_to_request")
    expected_digest = generate_digest(
        {key: deepcopy(value) for key, value in dict(fixture).items() if key != "fixture_digest"}
    )
    if fixture.get("fixture_digest") != expected_digest:
        failures.append("eie_fixture_digest_mismatch")
    return len(failures) == 0, failures


PHASE19A_FAILURE_MODE_CASES = (
    "raw_external_package_self_traverse",
    "external_package_request_fingerprint_unbound",
    "external_package_contains_authority",
    "external_pre_context_package_invalid",
    "skg_package_unavailable",
    "dtn_package_unavailable",
    "dtn_package_invalid_or_not_skg_constrained",
    "eie_malformed_object_type",
    "eie_unbound_to_request",
    "eie_stale",
)
