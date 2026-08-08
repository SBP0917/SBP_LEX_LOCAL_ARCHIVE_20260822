from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from external_substrates.dtn.signal_builder import build_dtn_signal_package
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.pre_context_package import build_pre_context_package
from external_substrates.shared.signing import sign_payload as sign_external_payload
from external_substrates.shared.source_attestation import build_source_record
from external_substrates.skg.signal_builder import build_skg_signal_package

from main import main, sample_request
from sbp_lex.phase19a.evidence_summary import build_detached_evidence_summary
from sbp_lex.phase19a.fixtures import (
    PHASE19A_FAILURE_MODE_CASES,
    build_eie_fixture,
    validate_eie_fixture,
)
from sbp_lex.phase19a.pre_context_translator import translate_external_pre_context_package
from sbp_lex.pipeline.hard_ingress import validate_pre_context_signal_package
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.security.pqc import generate_digest
from sbp_oda import constants as oda_constants
from sbp_pvpl import constants as pvpl_constants
from sbp_simulation.boundary import run_boundary_check

EXPECTED_STAGE_ORDER = [
    "hard_ingress",
    "state_construction",
    "collective_attach",
    "ap_acf_precheck",
    "root_of_trust",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain_wrap",
    "aurion_runtime",
    "execution_gate",
    "audit",
    "controlled_return",
]


def _external_chain(request: dict) -> tuple[dict, dict, dict]:
    request_fingerprint = generate_digest(request)
    timestamp = "2026-07-08T00:00:00Z"
    skg_sources = [
        build_source_record(
            source_id="phase19a-skg-source-a",
            source_type="authority-register",
            source_uri="local://phase19a/skg/a",
            verified=True,
            attested=True,
            freshness_valid=True,
            consistency_valid=True,
            retrieved_at=timestamp,
        )
    ]
    dtn_sources = [
        build_source_record(
            source_id="phase19a-dtn-source-a",
            source_type="operational-declaration",
            source_uri="local://phase19a/dtn/a",
            verified=True,
            attested=True,
            freshness_valid=True,
            consistency_valid=True,
            retrieved_at=timestamp,
        )
    ]
    skg_package = build_skg_signal_package(
        request_fingerprint=request_fingerprint,
        authorities=[
            {
                "authority_id": "test-root",
                "name": "Test Root",
                "jurisdiction": "AU-PACIFIC",
                "legitimacy_status": "verified",
            },
            {
                "authority_id": "test_authority",
                "name": "Test Authority",
                "jurisdiction": "AU-PACIFIC",
                "parent_authority_id": "test-root",
                "legitimacy_status": "verified",
            },
        ],
        rules=[
            {
                "rule_id": "phase19a-rule",
                "authority_id": "test-root",
                "jurisdiction": "AU-PACIFIC",
                "effective_at": "2026-01-01T00:00:00Z",
                "precedence": 10,
            }
        ],
        conflicts=[],
        source_records=skg_sources,
        authority_id="test_authority",
        jurisdiction="AU-PACIFIC",
        procedural_requirements=[{"requirement_id": "phase19a-procedure", "required": True}],
        licensing_authorities=[{"authority_id": "test-root", "scope": "phase19a-license"}],
        classification_authorities=[{"authority_id": "test-root", "scope": "phase19a-classification"}],
        timestamp=timestamp,
    )
    dtn_package = build_dtn_signal_package(
        request_fingerprint=request_fingerprint,
        skg_constraint_package=skg_package,
        context={
            "environment": {
                "type": "controlled-desktop-v1",
                "controlled": True,
                "human_proximity": "low",
            },
            "operational_state": {
                "status": "declared-ready",
                "contained": True,
                "emergency_stop_available": True,
            },
            "dependencies": [{"dependency_id": "local-runtime", "available": True}],
            "capabilities": [{"capability_id": "observe-only", "available": True}],
            "pathway": {
                "pathway_id": "phase19a-bounded-pathway",
                "objective": "bounded local validation",
                "steps": ["inspect", "translate"],
            },
            "declared_risk": 1,
            "cascading_impact": {
                "affected_dependencies": 0,
                "propagation_level": 0,
                "bounded": True,
            },
        },
        source_records=dtn_sources,
        timestamp=timestamp,
    )
    package = build_pre_context_package(
        skg_package=skg_package,
        dtn_package=dtn_package,
        nonce="phase19a-bounded-nonce",
        timestamp=timestamp,
    )
    return skg_package, dtn_package, package


def _resign_external_pre_context_package(package: dict) -> dict:
    body = {key: deepcopy(value) for key, value in package.items() if key not in {"digest", "signature"}}
    signature_body = {key: deepcopy(value) for key, value in package.items() if key != "signature"}
    package["digest"] = digest_mapping(body)
    package["signature"] = sign_external_payload(signature_body)
    return package


def _translate(request: dict, skg_package: dict | None, dtn_package: dict | None, package: dict):
    return translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=skg_package,
        dtn_package=dtn_package,
    )


def test_phase19a_valid_external_package_translates_to_runtime_local_signals() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)

    result = translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=skg_package,
        dtn_package=dtn_package,
    )

    assert result.accepted is True
    assert result.failures == ()
    assert result.signals is not None
    state = main(request, result.signals)
    assert state["hard_entry_gate"]["accepted"] is True
    assert state["collective_signal_evidence"]["role"] == "context_only_non_authoritative"
    assert state["integration_stage_order"] == EXPECTED_STAGE_ORDER
    assert state["domain_result"] == "pass"
    assert state["execution_result"] == "EXECUTE"


def test_phase19a_raw_external_package_cannot_self_traverse() -> None:
    request = sample_request()
    _, _, package = _external_chain(request)

    state = run_pipeline(request, package)

    assert state["hard_entry_gate"]["accepted"] is False
    assert state["integration_stage_order"] == ["hard_ingress"]
    assert state["governed_state_formed"] is False
    assert state["decision"] == "DENY"
    assert state["execution_result"] == "HALT"
    assert state["execution_verified"] is False


def test_phase19a_unbound_external_package_fails_closed() -> None:
    request = sample_request()
    other_request = sample_request()
    other_request["action"] = "different_action"
    skg_package, dtn_package, package = _external_chain(other_request)

    result = translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=skg_package,
        dtn_package=dtn_package,
    )

    assert result.accepted is False
    assert "external_package_request_fingerprint_unbound" in result.failures


def test_phase19a_prohibited_external_authority_fails_closed() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)
    package = deepcopy(package)
    package["signals"]["authority_link_signal"]["payload"]["governance_result"] = "ALLOW"

    result = translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=skg_package,
        dtn_package=dtn_package,
    )

    assert result.accepted is False
    assert "external_package_contains_authority" in result.failures


def test_phase19a_missing_skg_or_dtn_packages_fail_closed() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)

    missing_skg = translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=None,
        dtn_package=dtn_package,
    )
    missing_dtn = translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=skg_package,
        dtn_package=None,
    )

    assert missing_skg.accepted is False
    assert "skg_package_unavailable" in missing_skg.failures
    assert missing_dtn.accepted is False
    assert "dtn_package_unavailable" in missing_dtn.failures


def test_phase19a_dtn_cannot_override_skg_constraint() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)
    altered_dtn = deepcopy(dtn_package)
    altered_dtn["skg_constraint_digest"] = "not-the-skg-digest"

    result = translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=skg_package,
        dtn_package=altered_dtn,
    )

    assert result.accepted is False
    assert "dtn_package_invalid_or_not_skg_constrained" in result.failures


def test_phase19a_invalid_external_digest_or_signature_fails_closed() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)
    package = deepcopy(package)
    package["digest"] = "bad-digest"

    result = translate_external_pre_context_package(
        request=request,
        package=package,
        skg_package=skg_package,
        dtn_package=dtn_package,
    )

    assert result.accepted is False
    assert "external_pre_context_package_invalid" in result.failures


def test_phase19a_eie_malformed_unbound_and_stale_fixtures_fail_closed() -> None:
    request = sample_request()
    valid_fixture = build_eie_fixture(request)
    ok, failures = validate_eie_fixture(valid_fixture, request=request)
    assert ok is True
    assert failures == []

    malformed = deepcopy(valid_fixture)
    malformed["object_type"] = "NotEIE"
    malformed["fixture_digest"] = generate_digest(
        {key: value for key, value in malformed.items() if key != "fixture_digest"}
    )
    ok, failures = validate_eie_fixture(malformed, request=request)
    assert ok is False
    assert "eie_malformed_object_type" in failures

    unbound = deepcopy(valid_fixture)
    unbound["request_fingerprint"] = "wrong"
    unbound["fixture_digest"] = generate_digest(
        {key: value for key, value in unbound.items() if key != "fixture_digest"}
    )
    ok, failures = validate_eie_fixture(unbound, request=request)
    assert ok is False
    assert "eie_unbound_to_request" in failures

    stale = deepcopy(valid_fixture)
    stale["freshness_status"] = "STALE"
    stale["fixture_digest"] = generate_digest(
        {key: value for key, value in stale.items() if key != "fixture_digest"}
    )
    ok, failures = validate_eie_fixture(stale, request=request)
    assert ok is False
    assert "eie_stale" in failures

    missing_adapter = deepcopy(valid_fixture)
    missing_adapter["adapter_identity"] = ""
    missing_adapter["fixture_digest"] = generate_digest(
        {key: value for key, value in missing_adapter.items() if key != "fixture_digest"}
    )
    ok, failures = validate_eie_fixture(missing_adapter, request=request)
    assert ok is False
    assert "eie_missing_adapter_identity" in failures

    missing_source = deepcopy(valid_fixture)
    missing_source["source_system_identity"] = ""
    missing_source["fixture_digest"] = generate_digest(
        {key: value for key, value in missing_source.items() if key != "fixture_digest"}
    )
    ok, failures = validate_eie_fixture(missing_source, request=request)
    assert ok is False
    assert "eie_missing_source_system_identity" in failures


def test_phase19a_skg_conflict_and_insufficient_truth_foundation_fail_closed() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)

    conflict = deepcopy(package)
    conflict["skg_truth_foundation_metadata"]["contradiction_indicators"] = {
        "conflict_detected": True
    }
    _resign_external_pre_context_package(conflict)
    result = _translate(request, skg_package, dtn_package, conflict)
    assert result.accepted is False
    assert "skg_conflict_detected" in result.failures

    insufficient = deepcopy(package)
    insufficient["skg_truth_foundation_metadata"]["provenance_metadata"] = []
    _resign_external_pre_context_package(insufficient)
    result = _translate(request, skg_package, dtn_package, insufficient)
    assert result.accepted is False
    assert "skg_truth_foundation_insufficient" in result.failures


def test_phase19a_dtn_conflict_stale_environment_and_dependency_fail_closed() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)

    conflict = deepcopy(package)
    conflict["dtn_contextual_verification_metadata"]["state_correspondence_verification"] = False
    _resign_external_pre_context_package(conflict)
    result = _translate(request, skg_package, dtn_package, conflict)
    assert result.accepted is False
    assert "dtn_context_conflict" in result.failures

    stale = deepcopy(package)
    stale["signals"]["operational_context_signal"]["payload"]["freshness_status"] = "STALE"
    _resign_external_pre_context_package(stale)
    result = _translate(request, skg_package, dtn_package, stale)
    assert result.accepted is False
    assert "dtn_context_stale" in result.failures

    environmental = deepcopy(package)
    environmental["dtn_contextual_verification_metadata"]["runtime_world_correspondence"] = False
    _resign_external_pre_context_package(environmental)
    result = _translate(request, skg_package, dtn_package, environmental)
    assert result.accepted is False
    assert "dtn_environmental_mismatch" in result.failures

    dependency = deepcopy(package)
    dependency["signals"]["dependency_signal"]["payload"]["dependency_mismatch"] = True
    _resign_external_pre_context_package(dependency)
    result = _translate(request, skg_package, dtn_package, dependency)
    assert result.accepted is False
    assert "dtn_dependency_mismatch" in result.failures


def test_phase19a_pre_context_digest_signature_stale_and_provenance_fail_closed() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)

    digest_mismatch = deepcopy(package)
    digest_mismatch["digest"] = "bad-digest"
    result = _translate(request, skg_package, dtn_package, digest_mismatch)
    assert result.accepted is False
    assert "external_pre_context_package_invalid" in result.failures

    signature_mismatch = deepcopy(package)
    signature_mismatch["signature"] = "bad-signature"
    result = _translate(request, skg_package, dtn_package, signature_mismatch)
    assert result.accepted is False
    assert "external_pre_context_package_invalid" in result.failures

    stale = deepcopy(package)
    stale["freshness_valid"] = False
    _resign_external_pre_context_package(stale)
    result = _translate(request, skg_package, dtn_package, stale)
    assert result.accepted is False
    assert "external_pre_context_package_invalid" in result.failures

    missing_provenance = deepcopy(package)
    missing_provenance["source_records"] = []
    _resign_external_pre_context_package(missing_provenance)
    result = _translate(request, skg_package, dtn_package, missing_provenance)
    assert result.accepted is False
    assert "external_pre_context_package_invalid" in result.failures


def test_phase19a_external_result_injection_attempts_are_rejected() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)
    injection_cases = {
        "governance_result": "ALLOW",
        "classification_result": "ALLOW",
        "licensing_result": "ALLOW",
        "domain_result": "pass",
        "aurion15_result": "pass",
        "execution_result": "EXECUTE",
    }
    for key, value in injection_cases.items():
        injected = deepcopy(package)
        injected["signals"]["authority_link_signal"]["payload"][key] = value
        result = _translate(request, skg_package, dtn_package, injected)
        assert result.accepted is False, key
        assert "external_package_contains_authority" in result.failures, key
        state = run_pipeline(request, injected)
        assert state["governed_state_formed"] is False, key
        assert state["decision"] == "DENY", key
        assert state["execution_result"] == "HALT", key
        assert state["execution_verified"] is False, key
        assert state["hard_entry_gate"]["accepted"] is False, key


def test_phase19a_translated_signals_enter_only_after_hard_entry_validation() -> None:
    request = sample_request()
    skg_package, dtn_package, package = _external_chain(request)
    result = _translate(request, skg_package, dtn_package, package)
    assert result.accepted is True
    assert result.signals is not None

    request_fingerprint = generate_digest(request)
    valid, failures = validate_pre_context_signal_package(
        signals=result.signals, request_fingerprint=request_fingerprint
    )
    assert valid is True
    assert failures == []

    tampered = deepcopy(result.signals)
    tampered["digest"] = "wrong"
    valid, failures = validate_pre_context_signal_package(
        signals=tampered, request_fingerprint=request_fingerprint
    )
    assert valid is False
    assert "signal_digest_mismatch" in failures
    state = run_pipeline(request, tampered)
    assert state["hard_entry_gate"]["accepted"] is False
    assert state["governed_state_formed"] is False
    assert state["decision"] == "DENY"
    assert state["execution_result"] == "HALT"
    assert state["execution_verified"] is False


def test_phase19a_detached_evidence_summary_is_support_only() -> None:
    summary = build_detached_evidence_summary(
        translator_outcomes=[
            {"case": "valid_translation", "accepted": True},
            {"case": "skg_unavailable", "accepted": False},
        ]
    )
    assert summary["runtime_attached"] is False
    assert summary["publication_active"] is False
    assert summary["network_publication_active"] is False
    assert summary["blockchain_publication_active"] is False
    assert summary["hosted_runtime_active"] is False
    assert summary["runtime_authority"] == "NONE"
    assert summary["decision_authority"] == "NONE"
    assert summary["execution_authority"] == "NONE"
    assert summary["support_layers"]["oda_readable"] is True
    assert summary["support_layers"]["pvpl_readable"] is True
    assert summary["support_layers"]["sim_readable"] is True
    assert summary["translator_accepted_count"] == 1
    assert summary["translator_rejected_count"] == 1


def test_phase19a_oda_pvpl_and_sim_remain_detached_support_only() -> None:
    assert oda_constants.RUNTIME_AUTHORITY == "NONE"
    assert oda_constants.RUNTIME_PIPELINE_MUTATION_ALLOWED is False
    assert oda_constants.EXECUTION_AUTHORITY_ALLOWED is False
    assert pvpl_constants.RUNTIME_ATTACHED is False
    assert pvpl_constants.PUBLICATION_ACTIVE is False
    assert pvpl_constants.RUNTIME_AUTHORITY == "NONE"
    assert pvpl_constants.DECISION_AUTHORITY_ALLOWED is False
    sim_boundary = run_boundary_check(".")
    assert sim_boundary["status"] == "SIM_OK"


def test_phase19a_fixture_schema_and_failure_mode_files_exist() -> None:
    root = Path("fixtures/phase19a")
    expected_schema_files = {
        "schemas/eie.schema.json",
        "schemas/skg_readiness.schema.json",
        "schemas/dtn_readiness.schema.json",
        "schemas/runtime_pre_context_signals.schema.json",
        "schemas/external_pre_context_package.schema.json",
    }
    for path in expected_schema_files:
        assert (root / path).is_file()
    assert (root / "examples/eie_valid.json").is_file()
    assert (root / "examples/eie_malformed.json").is_file()
    assert (root / "examples/eie_stale.json").is_file()
    assert (root / "examples/eie_unbound.json").is_file()
    assert (root / "examples/detached_evidence_summary_shape.json").is_file()
    assert (root / "failure_mode_cases.json").is_file()
    required_cases = {
        "malformed_eie",
        "stale_eie",
        "unbound_eie",
        "mismatched_eie_fingerprint",
        "missing_adapter_identity",
        "missing_source_system_identity",
        "skg_unavailable",
        "skg_conflict",
        "skg_insufficient_truth_foundation",
        "dtn_unavailable",
        "dtn_conflict",
        "dtn_stale_context",
        "dtn_environmental_mismatch",
        "dtn_dependency_mismatch",
        "dtn_attempting_to_override_skg",
        "pre_context_digest_mismatch",
        "pre_context_signature_mismatch",
        "stale_pre_context_package",
        "missing_pre_context_provenance",
        "prohibited_external_authority_fields",
        "external_governance_status_injection",
        "external_classification_result_injection",
        "external_licensing_result_injection",
        "external_domain_result_injection",
        "external_aurion_result_injection",
        "external_execution_result_injection",
    }
    assert required_cases.issubset(set(PHASE19A_FAILURE_MODE_CASES))


def test_phase19a_domain_wrap_order_remains_locked() -> None:
    state = main(sample_request())
    order = state["integration_stage_order"]
    assert order.index("governance") < order.index("grc")
    assert order.index("grc") < order.index("domain_wrap")
    assert order.index("domain_wrap") < order.index("aurion_runtime")
    assert order.index("aurion_runtime") < order.index("execution_gate")
    assert order.index("execution_gate") < order.index("audit")
