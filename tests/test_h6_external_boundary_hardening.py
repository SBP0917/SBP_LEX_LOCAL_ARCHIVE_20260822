from __future__ import annotations

from copy import deepcopy

import pytest

from external_substrates.demo.build_demo_pre_context_package import build_demo_chain
from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.external_boundary import (
    BoundaryPolicy,
    ExternalBoundaryError,
    ReplayRegistry,
    adapt_external_chain,
    parse_canonical_json,
    validate_external_chain,
)
from external_substrates.shared.signing import sign_payload
from external_substrates.shared.source_attestation import build_source_record


NOW = "2026-06-19T00:01:00Z"


def chain() -> tuple[dict, dict, dict]:
    return build_demo_chain()


def fail_code(code: str, function, *args, **kwargs) -> None:
    with pytest.raises(ExternalBoundaryError) as raised:
        function(*args, **kwargs)
    assert raised.value.code == code


def resign_package(package: dict) -> None:
    body = {key: deepcopy(value) for key, value in package.items() if key not in {"digest", "signature"}}
    package["digest"] = digest_mapping(body)
    signature_body = {key: deepcopy(value) for key, value in package.items() if key != "signature"}
    package["signature"] = sign_payload(signature_body)


def resign_signal(signal: dict) -> None:
    body = {key: deepcopy(value) for key, value in signal.items() if key not in {"digest", "signature"}}
    signal["digest"] = digest_mapping(body)
    signature_body = {key: deepcopy(value) for key, value in signal.items() if key != "signature"}
    signal["signature"] = sign_payload(signature_body)


def test_valid_chain_produces_exactly_one_non_authoritative_eie_candidate() -> None:
    skg, dtn, pre = chain()
    result = adapt_external_chain(*(canonical_dumps(item) for item in (skg, dtn, pre)), now=NOW)
    assert result["object_type"] == "ExternalIngressEnvelope"
    assert result["canonical_traversal_state"] is False
    assert result["authority_boundary"] == "EVIDENCE_ONLY_HARD_ENTRY_REQUIRED"
    assert result["eie_digest"] and result["eie_signature"]


@pytest.mark.parametrize(
    ("index", "mutation", "code"),
    [
        (0, lambda item: item.pop("signature"), "package_metadata_missing"),
        (1, lambda item: item.update(signature="forged"), "dtn_verification_failed"),
        (0, lambda item: item.update(schema_version="0.9"), "schema_version_rejected"),
        (1, lambda item: item.update(package_version="0.9"), "package_version_rejected"),
        (2, lambda item: item.update(package_type="external_skg_signal_package"), "protocol_confusion"),
        (0, lambda item: item.update(execution_permission="ALLOW"), "forged_external_authority"),
        (2, lambda item: item.update(package_id="substituted"), "package_identity_mismatch"),
    ],
)
def test_package_integrity_and_protocol_fail_closed(index, mutation, code) -> None:
    packages = list(chain())
    mutation(packages[index])
    fail_code(code, validate_external_chain, *packages, now=NOW)


def test_stale_package_is_measured_not_trusted_from_boolean_flag() -> None:
    fail_code(
        "stale_package",
        validate_external_chain,
        *chain(),
        now="2026-06-19T01:00:00Z",
        policy=BoundaryPolicy(max_age_seconds=300),
    )


def test_replay_is_rejected_by_identifier_and_digest() -> None:
    registry = ReplayRegistry()
    validate_external_chain(*chain(), now=NOW, replay_registry=registry)
    fail_code("replayed_package_identifier", validate_external_chain, *chain(), now=NOW, replay_registry=registry)


def test_malformed_skg_and_dtn_packages_stop_before_eie() -> None:
    skg, dtn, pre = chain()
    skg.pop("signals")
    fail_code("strict_schema_rejected", validate_external_chain, skg, dtn, pre, now=NOW)
    skg, dtn, pre = chain()
    dtn.pop("skg_constraint_digest")
    fail_code("strict_schema_rejected", validate_external_chain, skg, dtn, pre, now=NOW)


def test_wrong_provenance_and_duplicate_provenance_are_rejected() -> None:
    skg, dtn, pre = chain()
    skg["source_records"][0]["digest"] = "0" * 64
    fail_code("provenance_invalid", validate_external_chain, skg, dtn, pre, now=NOW)
    skg, dtn, pre = chain()
    skg["source_records"].append(deepcopy(skg["source_records"][0]))
    fail_code("duplicate_provenance", validate_external_chain, skg, dtn, pre, now=NOW)


def test_shared_origin_cannot_masquerade_as_independent_evidence() -> None:
    skg, dtn, pre = chain()
    first = skg["source_records"][0]
    second = build_source_record(
        source_id="masquerade-source",
        source_type=first["source_type"],
        source_uri=first["source_uri"],
        verified=True,
        attested=True,
        freshness_valid=True,
        consistency_valid=True,
        retrieved_at=first["retrieved_at"],
    )
    skg["source_records"].append(second)
    fail_code("source_independence_failure", validate_external_chain, skg, dtn, pre, now=NOW)


def test_dependency_ambiguity_is_rejected_after_valid_signature() -> None:
    skg, dtn, pre = chain()
    signal = dtn["signals"]["dependency_signal"]
    signal["payload"]["dependencies"].append(deepcopy(signal["payload"]["dependencies"][0]))
    resign_signal(signal)
    resign_package(dtn)
    pre["dtn_package_digest"] = dtn["digest"]
    resign_package(pre)
    fail_code("dependency_ambiguity", validate_external_chain, skg, dtn, pre, now=NOW)


def test_duplicate_json_keys_malformed_structure_and_noncanonical_json_fail() -> None:
    fail_code("duplicate_json_key", parse_canonical_json, '{"a":1,"a":2}')
    fail_code("malformed_json", parse_canonical_json, '{"a":')
    fail_code("non_canonical_json", parse_canonical_json, '{ "a": 1 }')


def test_adapter_limits_recursion_nesting_items_and_size() -> None:
    nested: object = "leaf"
    for _ in range(8):
        nested = {"a": nested}
    fail_code("adapter_nesting_limit_exceeded", parse_canonical_json, canonical_dumps(nested), policy=BoundaryPolicy(max_depth=4))
    fail_code("adapter_item_limit_exceeded", parse_canonical_json, canonical_dumps({"a": [1, 2, 3]}), policy=BoundaryPolicy(max_container_items=3))
    fail_code("oversized_package", parse_canonical_json, canonical_dumps({"a": "x" * 50}), policy=BoundaryPolicy(max_package_bytes=20))


def test_binary_and_invalid_unicode_are_rejected() -> None:
    fail_code("binary_package_rejected", parse_canonical_json, b'{"a":1}')
    fail_code("invalid_utf8", parse_canonical_json, '{"a":"\ud800"}')


def test_mixed_chain_and_poisoned_authority_never_produce_eie() -> None:
    skg, _, _ = chain()
    _, dtn, pre = chain()
    dtn["request_fingerprint"] = "other-request"
    fail_code("package_identity_mismatch", validate_external_chain, skg, dtn, pre, now=NOW)
    skg, dtn, pre = chain()
    pre["signals"]["authority_link_signal"]["payload"]["governance_result"] = "ALLOW"
    fail_code("forged_external_authority", validate_external_chain, skg, dtn, pre, now=NOW)


def test_adapter_is_deterministic_and_replay_registry_is_caller_owned() -> None:
    serialized = tuple(canonical_dumps(item) for item in chain())
    assert adapt_external_chain(*serialized, now=NOW) == adapt_external_chain(*serialized, now=NOW)
    registry = ReplayRegistry()
    adapt_external_chain(*serialized, now=NOW, replay_registry=registry)
    fail_code("replayed_package_identifier", adapt_external_chain, *serialized, now=NOW, replay_registry=registry)
