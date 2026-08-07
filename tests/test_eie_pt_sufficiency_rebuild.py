from __future__ import annotations

from copy import deepcopy

from main import sample_request
from sbp_lex.execution.execution_gate import evaluate_strict_execution_security
from sbp_lex.pipeline.runner import run_pipeline


def _sources(count: int) -> list[dict[str, object]]:
    return [
        {
            "source": f"rebuild_source_{index}",
            "content": f"rebuild_evidence_{index}",
            "verified": True,
            "attested": True,
            "freshness_valid": True,
            "consistency_valid": True,
            "source_independent": True,
            "provenance_valid": True,
            "integrity_valid": True,
            "authority_valid": True,
            "jurisdiction_valid": True,
            "runtime_validity_valid": True,
        }
        for index in range(count)
    ]


def _request(count: int = 3) -> dict:
    request = sample_request()
    request["safety_profile"] = {
        "human_safety": 2,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 0,
    }
    request["context"]["financial_amount"] = 0
    request["context"]["evidence"] = _sources(count)
    return request


def test_eie_remains_canonical_traversal_state_and_is_formalised() -> None:
    state = run_pipeline(_request())
    assert state["active_traversal_state_type"] == "EIE"
    assert state["eie"]["object_type"] == "ExecutionIntentEnvelope"
    assert state["eie"]["canonical_traversal_state"] is True
    assert state["eie_hash"] == state["pt_evidence_envelope"]["eie_hash"]
    assert state["traversal_id"] == state["eie"]["traversal_id"]


def test_skg_and_dtn_enrichment_are_preserved_without_authorising_execution() -> None:
    state = run_pipeline(_request())
    skg = state["pt_evidence_envelope"]["skg_truth_foundation_metadata"]
    dtn = state["pt_evidence_envelope"]["dtn_contextual_verification_metadata"]
    assert skg["skg_verification_status"] == "VALID"
    assert skg["truth_foundation_readiness_status"] == "READY"
    assert skg["skg_enrichment_hash"]
    assert "execution_permission" not in skg
    assert dtn["dtn_contextualisation_status"] == "VALID"
    assert dtn["contextual_readiness_status"] == "READY"
    assert dtn["dtn_enrichment_hash"]
    assert "governance_result" not in dtn


def test_root_of_trust_binds_validated_eie_truth_foundations() -> None:
    state = run_pipeline(_request())
    payload = state["root_of_trust_evidence_anchor"]["payload"]
    assert state["root_of_trust_evidence_anchor"]["anchorage_status"] == "VALID"
    assert payload["eie_hash"] == state["eie_hash"]
    assert payload["source_payload_hash"] == state["source_payload_hash"]
    assert payload["skg_verification_status"] == "VALID"
    assert payload["dtn_contextualisation_status"] == "VALID"
    assert payload["traversal_id"] == state["traversal_id"]


def test_procedural_truth_requires_independence_beyond_source_floor() -> None:
    request = _request()
    request["context"]["evidence"][0]["source"] = "same_source"
    request["context"]["evidence"][1]["source"] = "same_source"
    state = run_pipeline(request)
    certification = state["procedural_truth_certification"]
    assert certification["source_floor_met"] is False
    assert certification["independence_met"] is False
    assert certification["certification_status"] == "NOT_CERTIFIED"
    assert state["classification_result"] == "UNSET"
    assert state["execution_result"] == "HALT"


def test_procedural_truth_denies_unresolved_material_contradiction() -> None:
    request = _request()
    request["context"]["evidence"][0]["material_contradiction"] = True
    request["context"]["evidence"][0]["unresolved_contradiction"] = True
    state = run_pipeline(request)
    certification = state["procedural_truth_certification"]
    assert certification["unresolved_contradictions"] is True
    assert certification["procedural_truth_status"] == "DENY"
    assert certification["certification_status"] == "NOT_CERTIFIED"


def test_execution_gate_rejects_missing_or_mismatched_pt_token() -> None:
    state = run_pipeline(_request())
    tampered = deepcopy(state)
    tampered["procedural_truth_certification"]["pt_token_hash"] = "mismatch"
    result = evaluate_strict_execution_security(tampered)
    assert result["valid"] is False
    assert "procedural_truth_token_hash_mismatch" in result["failures"]


def test_audit_trace_preserves_new_certification_metadata() -> None:
    state = run_pipeline(_request())
    binding = state["audit_record"]["payload"]["integration_evidence"]["procedural_truth_binding"]
    assert binding["pt_outcome"] == "PT_PASS"
    assert binding["procedural_truth_certification"]["certification_status"] == "CERTIFIED"
    assert binding["skg_truth_foundation_metadata"]["skg_verification_status"] == "VALID"
    assert binding["dtn_contextual_verification_metadata"]["dtn_contextualisation_status"] == "VALID"
    assert state["procedural_truth_certification"]["certification_status"] == "CERTIFIED"
    assert "procedural_truth_certification" not in state["eie"]
