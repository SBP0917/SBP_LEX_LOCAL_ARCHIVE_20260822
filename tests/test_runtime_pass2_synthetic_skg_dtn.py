from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.signing import sign_payload
from external_substrates.shared.synthetic_runtime import (
    DTN_FIELDS,
    DTN_SCHEMA_VERSION,
    SIGNATURE_MODE,
    SKG_FIELDS,
    SKG_SCHEMA_VERSION,
    SyntheticReplayRegistry,
    canonical_package,
    validate_provider_mode,
    validate_synthetic_bridge,
    validate_synthetic_dtn_package,
    validate_synthetic_skg_package,
)
from external_substrates.demo.synthetic_runtime_fixtures import (
    build_controlled_fixture_set,
)
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.runtime.synthetic_substrates import (
    FIXTURE_VALIDATION_TIME,
    STAGE_ORDER,
    build_synthetic_fixture_chain,
    prepare_synthetic_substrate_signals,
    validate_raw_synthetic_chain,
)
from sbp_lex.shared.state_builder import build_execution_intent_envelope


def request() -> dict:
    return {
        "action": "test_action",
        "payload": {
            "classification": {
                "ap_acf_class": "CLASS_4B",
                "autonomy_level": 25,
                "autonomy_ceiling": 50,
                "operational_scope": "controlled_test",
                "public_exposure": "controlled",
            },
            "licence_state": "VALID",
        },
        "resolved_authority": "desktop-test-authority",
        "jurisdiction": "AU-PACIFIC",
        "context": {
            "environment": "controlled_test",
            "operational_scope": "controlled_test",
            "operational_containment": "bounded",
            "evidence": [{
                "source": "fixture-source-a",
                "content": "fixture-evidence-a",
                "verified": True,
                "attested": True,
                "freshness_valid": True,
                "consistency_valid": True,
            }],
        },
        "safety_profile": {
            "human_safety": 1,
            "irreversibility": 1,
            "cascading_impact": 1,
            "financial_operational": 1,
        },
    }


def chain() -> tuple[dict, dict, dict]:
    return build_synthetic_fixture_chain(request())


def reseal(package: dict) -> dict:
    result = deepcopy(package)
    body = {
        key: deepcopy(value)
        for key, value in result.items()
        if key not in {"digest", "signature"}
    }
    result["digest"] = digest_mapping(body)
    signature_body = {
        key: deepcopy(value)
        for key, value in result.items()
        if key != "signature"
    }
    result["signature"] = sign_payload(signature_body)
    return result


def bridge(skg: dict, dtn: dict, **kwargs):
    eie = build_execution_intent_envelope(request())
    return validate_synthetic_bridge(
        skg,
        dtn,
        validation_time=FIXTURE_VALIDATION_TIME,
        expected_request_fingerprint=eie["request_fingerprint"],
        expected_eie_digest=eie["eie_hash"],
        **kwargs,
    )


def test_fixture_generation_is_deterministic_and_repeated_run_equal() -> None:
    first = chain()
    second = chain()
    assert first == second
    assert canonical_dumps(first) == canonical_dumps(second)


def test_canonical_serialization_is_stable_and_round_trips() -> None:
    _, skg, dtn = chain()
    assert canonical_package(skg) == canonical_dumps(skg)
    assert canonical_package(dtn) == canonical_dumps(dtn)
    assert canonical_dumps({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_eie_is_explicit_and_contains_deterministic_package_references() -> None:
    eie, skg, dtn = chain()
    assert all(
        field in eie
        for field in (
            "objective", "autonomy", "deployment", "environment",
            "consequence", "resolved_authority", "jurisdiction",
        )
    )
    refs = eie["external_substrate_references"]
    assert skg["package_reference"] == refs["skg_package_reference"]
    assert dtn["package_reference"] == refs["dtn_package_reference"]
    assert skg["eie_digest"] == dtn["eie_digest"] == eie["eie_hash"]


def test_skg_schema_pass_and_unknown_field_fail() -> None:
    eie, skg, _ = chain()
    result = validate_synthetic_skg_package(
        skg,
        validation_time=FIXTURE_VALIDATION_TIME,
        request_fingerprint=eie["request_fingerprint"],
        eie_digest=eie["eie_hash"],
    )
    assert result.accepted
    invalid = {**skg, "unknown_field": True}
    assert "schema_fields_rejected" in validate_synthetic_skg_package(
        invalid, validation_time=FIXTURE_VALIDATION_TIME
    ).failures


def test_dtn_schema_pass_and_type_fail() -> None:
    eie, skg, dtn = chain()
    result = validate_synthetic_dtn_package(
        dtn,
        validation_time=FIXTURE_VALIDATION_TIME,
        request_fingerprint=eie["request_fingerprint"],
        eie_digest=eie["eie_hash"],
        skg_digest=skg["digest"],
    )
    assert result.accepted
    invalid = reseal({**dtn, "dependencies": "not-a-list"})
    assert "dependencies_invalid" in validate_synthetic_dtn_package(
        invalid, validation_time=FIXTURE_VALIDATION_TIME
    ).failures


@pytest.mark.parametrize(
    ("target", "field"),
    [("skg", "digest"), ("dtn", "digest")],
)
def test_digest_tamper_is_rejected(target: str, field: str) -> None:
    _, skg, dtn = chain()
    package = skg if target == "skg" else dtn
    package[field] = "0" * 64
    validator = (
        validate_synthetic_skg_package
        if target == "skg"
        else validate_synthetic_dtn_package
    )
    assert "digest_invalid" in validator(
        package, validation_time=FIXTURE_VALIDATION_TIME
    ).failures


@pytest.mark.parametrize("target", ["skg", "dtn"])
def test_signature_tamper_is_rejected(target: str) -> None:
    _, skg, dtn = chain()
    package = skg if target == "skg" else dtn
    package["signature"] = "f" * 64
    validator = (
        validate_synthetic_skg_package
        if target == "skg"
        else validate_synthetic_dtn_package
    )
    assert "signature_invalid" in validator(
        package, validation_time=FIXTURE_VALIDATION_TIME
    ).failures


def test_stale_package_is_rejected_against_declared_clock() -> None:
    _, skg, _ = chain()
    result = validate_synthetic_skg_package(
        skg, validation_time="2026-08-07T00:05:01Z"
    )
    assert "stale_package" in result.failures


def test_replay_nonce_and_digest_are_rejected_with_equal_results() -> None:
    _, skg, dtn = chain()
    registry = SyntheticReplayRegistry()
    assert bridge(skg, dtn, replay_registry=registry).accepted
    first = bridge(skg, dtn, replay_registry=registry)
    second = bridge(skg, dtn, replay_registry=registry)
    assert first == second
    assert {
        "replayed_package_nonce", "replayed_package_digest"
    }.issubset(first.failures)


def test_request_fingerprint_mismatch_is_rejected() -> None:
    eie, skg, _ = chain()
    result = validate_synthetic_skg_package(
        skg,
        validation_time=FIXTURE_VALIDATION_TIME,
        request_fingerprint=eie["request_fingerprint"] + "x",
    )
    assert "request_fingerprint_mismatch" in result.failures


def test_eie_digest_mismatch_is_rejected() -> None:
    _, skg, _ = chain()
    result = validate_synthetic_skg_package(
        skg,
        validation_time=FIXTURE_VALIDATION_TIME,
        eie_digest="0" * 64,
    )
    assert "eie_digest_mismatch" in result.failures


def test_cross_package_request_and_eie_mismatch_are_rejected() -> None:
    _, skg, dtn = chain()
    dtn["request_fingerprint"] = "different-request"
    dtn["eie_digest"] = "different-eie"
    dtn = reseal(dtn)
    result = bridge(skg, dtn)
    assert "cross_package_request_mismatch" in result.failures
    assert "cross_package_eie_mismatch" in result.failures


def test_jurisdiction_conflict_is_rejected() -> None:
    _, skg, dtn = chain()
    dtn["jurisdiction"]["jurisdiction_id"] = "CONFLICT"
    result = bridge(skg, reseal(dtn))
    assert "jurisdiction_conflict" in result.failures


def test_authority_conflict_is_rejected() -> None:
    _, skg, dtn = chain()
    dtn["authority_reference"] = "different-authority"
    result = bridge(skg, reseal(dtn))
    assert "authority_conflict" in result.failures


def test_missing_dependency_and_nonviable_pathway_fail_closed() -> None:
    _, skg, dtn = chain()
    dtn["dependencies"] = []
    result = bridge(skg, reseal(dtn))
    assert "missing_dependency" in result.failures


def test_skg_constraint_conflict_is_applied_to_dtn_pathway() -> None:
    _, skg, dtn = chain()
    skg["substrate_constraints"]["prohibited_pathway_ids"] = [
        dtn["pathway_viability"]["pathway_id"]
    ]
    skg = reseal(skg)
    dtn["skg_constraint_digest"] = skg["digest"]
    dtn = reseal(dtn)
    assert "skg_dtn_pathway_conflict" in bridge(skg, dtn).failures


@pytest.mark.parametrize(
    "leak",
    [
        {"runtime_authority": "external"},
        {"external_governance_result": "anything"},
        {"nested": {"value": "EXECUTE"}},
    ],
)
def test_forbidden_authority_leakage_is_rejected(leak: dict) -> None:
    _, skg, _ = chain()
    skg.update(leak)
    result = validate_synthetic_skg_package(
        reseal(skg), validation_time=FIXTURE_VALIDATION_TIME
    )
    assert "forbidden_authority_field" in result.failures


@pytest.mark.parametrize(
    "configuration",
    [
        {"provider_mode": "live"},
        {"provider_mode": "synthetic_local", "url": "https://live.example"},
        {"provider_mode": "synthetic_local", "api_key": "secret"},
        {"provider_mode": "synthetic_local", "cloud_endpoint": "aws"},
        {"provider_mode": "synthetic_local", "production_sensor_feed": True},
        {"provider_mode": "synthetic_local", "live_ingestion": True},
        {"provider_mode": "synthetic_local", "network_enabled": True},
    ],
)
def test_provider_mode_activation_attempts_are_blocked(
    configuration: dict,
) -> None:
    assert not validate_provider_mode(configuration).accepted


def test_provider_mode_allows_only_local_synthetic_fixture_source() -> None:
    result = validate_provider_mode({
        "provider_mode": "synthetic_local",
        "source_uri": "fixture:/synthetic/source",
        "network_enabled": False,
        "live_ingestion": False,
    })
    assert result.accepted


@pytest.mark.parametrize(
    ("raw_skg", "raw_dtn"),
    [
        ("{", "{}"),
        ("[]", "{}"),
        ('{"duplicate":1,"duplicate":2}', "{}"),
        ('{"not":"canonical", "spacing":true}', "{}"),
    ],
)
def test_malformed_raw_input_fails_closed_without_signals(
    raw_skg: str, raw_dtn: str
) -> None:
    result = validate_raw_synthetic_chain(
        request=request(),
        raw_skg=raw_skg,
        raw_dtn=raw_dtn,
        validation_time=FIXTURE_VALIDATION_TIME,
    )
    assert not result.accepted
    assert result.signals is None
    assert result.evidence["raw_packages_crossed_hard_entry"] is False
    assert result.evidence["direct_state_write"] is False


def test_valid_pair_emits_minimal_signals_without_raw_packages() -> None:
    result = prepare_synthetic_substrate_signals(request())
    assert result.accepted
    assert result.signals is not None
    assert result.evidence["stage_order"] == list(STAGE_ORDER)
    assert result.evidence["raw_packages_crossed_hard_entry"] is False
    assert result.evidence["direct_state_write"] is False
    forbidden_raw_fields = {
        "authority_hierarchy", "provenance", "package_type",
        "feasibility_constraints", "pathway_viability",
    }
    assert forbidden_raw_fields.isdisjoint(result.signals)


def test_default_pipeline_uses_synthetic_path_before_state_and_attachment() -> None:
    state = run_pipeline(request())
    evidence = state["collective_signal_evidence"]
    assert state["hard_entry_gate"]["accepted"] is True
    assert state["collective_signal_status"] == "ATTACHED"
    assert evidence["eie_digest"] == state["eie_hash"]
    assert evidence["provenance"]["skg_package_digest"] == state[
        "verified_substrate_references"
    ]["skg_package_digest"]
    assert "synthetic_substrate_evidence" not in state["collective_signals"]


def test_schema_versions_and_controlled_local_signature_mode_are_locked() -> None:
    _, skg, dtn = chain()
    assert skg["schema_version"] == SKG_SCHEMA_VERSION
    assert dtn["schema_version"] == DTN_SCHEMA_VERSION
    assert skg["signature_mode"] == dtn["signature_mode"] == SIGNATURE_MODE
    downgraded = reseal({**skg, "signature_mode": "NONE"})
    assert "signature_mode_rejected" in validate_synthetic_skg_package(
        downgraded, validation_time=FIXTURE_VALIDATION_TIME
    ).failures


def test_declared_schemas_and_named_fixture_corpus_are_complete() -> None:
    schema_root = (
        Path(__file__).resolve().parents[1]
        / "external_substrates" / "shared" / "schemas"
    )
    skg_schema = json.loads(
        (schema_root / "synthetic_skg_package.schema.json").read_text(
            encoding="utf-8"
        )
    )
    dtn_schema = json.loads(
        (schema_root / "synthetic_dtn_package.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(skg_schema["required"]) == set(SKG_FIELDS)
    assert set(dtn_schema["required"]) == set(DTN_FIELDS)
    _, skg, dtn = chain()
    fixtures = build_controlled_fixture_set(skg, dtn)
    assert set(fixtures) == {
        "valid_skg_package", "valid_dtn_package", "valid_paired_package",
        "malformed_package", "stale_package", "replayed_package",
        "request_mismatch", "eie_mismatch", "digest_mismatch",
        "signature_mismatch", "jurisdiction_conflict", "authority_conflict",
        "forbidden_authority_leakage",
        "provider_mode_activation_attempt",
    }
    assert fixtures == build_controlled_fixture_set(skg, dtn)
    SKG_FIELDS,
