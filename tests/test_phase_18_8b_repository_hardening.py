from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from main import sample_request
from sbp_lex.audit.historical_integrity import verify_historical_state
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.engine import run_classification
from sbp_lex.execution.execution_gate import evaluate_strict_execution_security, run_execution_gate
from sbp_lex.governance.engine import run_governance
from sbp_lex.local_trust.validation_dossier import build_validation_dossier
from sbp_lex.local_trust.dossier_validator import validate_dossier_manifest
from sbp_lex.pipeline.replay_runner import run_replay_check, verify_replay_result
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.control_chain_validation import (
    validate_eie_binding,
    validate_root_anchor_binding,
    validate_skg_dtn_binding,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _sources(count: int = 3) -> list[dict[str, object]]:
    return [
        {
            "source": f"phase18_8b_source_{index}",
            "content": f"phase18_8b_evidence_{index}",
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


def _request(label: str = "baseline") -> dict:
    request = sample_request()
    request["action"] = f"phase_18_8b_{label}"
    request["adapter_identity"] = "LOCAL_RUNTIME_ADAPTER"
    request["source_system_identity"] = "LOCAL_RUNTIME"
    request["safety_profile"] = {
        "human_safety": 2,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 0,
    }
    request["context"]["financial_amount"] = 0
    request["context"]["evidence"] = _sources()
    return request


def _valid_state() -> dict:
    state = run_pipeline(_request())
    assert state["decision"] == "ALLOW"
    return state


def test_rogue_eie_with_wrong_hash_fails_before_classification() -> None:
    state = _valid_state()
    state["eie"]["eie_hash"] = "0" * 64
    classified = run_classification(state)
    assert classified["classification_result"] == "DENY"
    assert "eie_hash_state_mismatch" in classified["classification_reason"]


def test_eie_missing_source_identity_is_rejected() -> None:
    state = _valid_state()
    state["eie"]["source_system_identity"] = ""
    valid, failures = validate_eie_binding(state)
    assert valid is False
    assert "eie_missing:source_system_identity" in failures


def test_eie_missing_source_payload_hash_is_rejected() -> None:
    state = _valid_state()
    state["eie"]["source_payload_hash"] = ""
    valid, failures = validate_eie_binding(state)
    assert valid is False
    assert "eie_missing:source_payload_hash" in failures


def test_eie_mismatched_request_fingerprint_is_rejected() -> None:
    state = _valid_state()
    state["eie"]["request_fingerprint"] = "wrong"
    valid, failures = validate_eie_binding(state)
    assert valid is False
    assert "eie_request_fingerprint_mismatch" in failures


def test_skg_enrichment_hash_missing_is_rejected() -> None:
    state = _valid_state()
    del state["pt_evidence_envelope"]["skg_truth_foundation_metadata"]["skg_enrichment_hash"]
    valid, failures = validate_skg_dtn_binding(state)
    assert valid is False
    assert "skg_metadata_missing:skg_enrichment_hash" in failures


def test_dtn_contextualisation_hash_missing_is_rejected() -> None:
    state = _valid_state()
    del state["pt_evidence_envelope"]["dtn_contextual_verification_metadata"]["dtn_enrichment_hash"]
    valid, failures = validate_skg_dtn_binding(state)
    assert valid is False
    assert "dtn_metadata_missing:dtn_enrichment_hash" in failures


def test_skg_dtn_mismatch_is_rejected() -> None:
    state = _valid_state()
    state["eie"]["dtn_contextual_verification"]["dtn_contextualisation_status"] = "MISMATCHED"
    valid, failures = validate_skg_dtn_binding(state)
    assert valid is False
    assert "eie_dtn_metadata_mismatch" in failures


def test_root_anchorage_missing_eie_hash_is_rejected() -> None:
    state = _valid_state()
    state["root_of_trust_evidence_anchor"]["payload"]["eie_hash"] = ""
    valid, failures = validate_root_anchor_binding(state)
    assert valid is False
    assert "root_anchor_missing:eie_hash" in failures


def test_root_anchorage_mismatched_evidence_package_hash_is_rejected() -> None:
    state = _valid_state()
    state["root_of_trust_evidence_anchor"]["payload"]["evidence_package_hash"] = "wrong"
    valid, failures = validate_root_anchor_binding(state)
    assert valid is False
    assert "root_anchor_mismatch:evidence_package_hash" in failures


def test_pt_source_floor_alone_is_not_sufficient() -> None:
    request = _request()
    request["context"]["evidence"][1]["source"] = request["context"]["evidence"][0]["source"]
    state = run_pipeline(request)
    certification = state["procedural_truth_certification"]
    assert certification["source_floor_met"] is True
    assert certification["independence_met"] is False
    assert certification["certification_status"] == "NOT_CERTIFIED"
    assert state["classification_result"] == "UNSET"


def test_pt_unresolved_contradiction_is_not_certified() -> None:
    request = _request()
    request["context"]["evidence"][0]["material_contradiction"] = True
    request["context"]["evidence"][0]["unresolved_contradiction"] = True
    state = run_pipeline(request)
    assert state["procedural_truth_certification"]["procedural_truth_status"] == "DENY"
    assert state["procedural_truth_certification"]["certification_status"] == "NOT_CERTIFIED"


def test_pt_token_hash_mismatch_is_rejected() -> None:
    state = _valid_state()
    state["procedural_truth_certification"]["pt_token_hash"] = "wrong"
    result = evaluate_strict_execution_security(state)
    assert result["valid"] is False
    assert "procedural_truth_token_hash_mismatch" in result["failures"]


def test_threshold_token_missing_is_rejected() -> None:
    state = _valid_state()
    del state["tokens"]["threshold_bundle"]
    result = evaluate_strict_execution_security(state)
    assert result["valid"] is False
    assert "missing_token:threshold_bundle" in result["failures"]


def test_stale_token_reuse_attempt_is_rejected() -> None:
    source = _valid_state()
    target = run_pipeline(_request("different_request"))
    target["tokens"]["procedural_truth"] = deepcopy(source["tokens"]["procedural_truth"])
    result = evaluate_strict_execution_security(target)
    assert result["valid"] is False
    assert "signature_payload_mismatch:procedural_truth" in result["failures"]


def test_execution_gate_direct_call_bypass_attempt_denies() -> None:
    state = _valid_state()
    state["integration_stage_order"].remove("aurion_runtime")
    result = run_execution_gate(state)
    assert result["decision"] == "DENY"
    assert "traversal_bypass_detected:aurion_runtime" in result["token_verification_failures"]


def test_classification_attempt_before_pt_certification_denies() -> None:
    state = _valid_state()
    state["tokens"].pop("procedural_truth")
    classified = run_classification(state)
    assert classified["classification_result"] == "DENY"
    assert "missing_token:procedural_truth" in classified["classification_reason"]


def test_governance_attempt_before_pt_certification_denies() -> None:
    state = _valid_state()
    state["tokens"].pop("procedural_truth")
    governed = run_governance(state)
    assert governed["governance_result"] == "DENY"
    assert (
        "confused_deputy_rejected:missing_token:procedural_truth"
        in governed["governance_feedback"]["governance"]["failures"]
    )


def test_audit_metadata_dropout_is_detected() -> None:
    state = _valid_state()
    del state["audit_record"]["payload"]["integration_evidence"]["procedural_truth_binding"]["root_of_trust_evidence_anchor"]
    valid, failures = verify_historical_state(state)
    assert valid is False
    assert "ROOT_OF_TRUST_MISMATCH" in failures


def test_replay_mutation_is_detected() -> None:
    replay = run_replay_check(request=_request())
    replay["runs"][1]["pt_bound_metadata"]["eie_hash"] = "mutated"
    replay["matched"] = True
    valid, failures = verify_replay_result(replay)
    assert valid is False
    assert "REPLAY_MISMATCH" in failures


def test_dossier_overclaim_detection_rejects_production_claim(tmp_path: Path) -> None:
    dossier_dir = tmp_path / "dossier"
    build_validation_dossier(REPOSITORY_ROOT, output_dir=dossier_dir)
    manifest, claims, questions, artifacts, scope, commands = (
        _load_json(dossier_dir / "DOSSIER_MANIFEST.json"),
        _load_json(dossier_dir / "MASTER_CLAIMS_TO_EVIDENCE_INDEX.json"),
        _load_json(dossier_dir / "VALIDATION_QUESTIONS.json"),
        _load_json(dossier_dir / "EVIDENCE_ARTIFACT_INDEX.json"),
        _load_json(dossier_dir / "SCOPE_AND_EXCLUSIONS_LOCK.json"),
        _load_json(dossier_dir / "REVIEWER_VERIFICATION_COMMANDS.json"),
    )
    claims["claims"][0]["claim_text"] = "This repository has production deployment readiness."
    validation = validate_dossier_manifest(
        manifest,
        repository_root=REPOSITORY_ROOT,
        claims_index=claims,
        validation_questions=questions,
        evidence_artifact_index=artifacts,
        scope_lock=scope,
        reviewer_commands=commands,
    )
    assert validation["dossier_status"] == "VALIDATION_DOSSIER_FAIL"
    assert any(item.startswith("false_validation_or_certification_claim:") for item in validation["validation_failures"])


def test_root_of_trust_rejects_malformed_eie_before_pt() -> None:
    state = _valid_state()
    pre_root = deepcopy(state)
    pre_root["authority_first_result"] = "UNSET"
    pre_root["eie"]["adapter_identity"] = ""
    result = run_root_of_trust(pre_root)
    assert result["authority_first_result"] == "FAIL"
    assert "eie_missing:adapter_identity" in result["governance_feedback"]["root_of_trust_evidence_anchor"]["failures"]


def test_execution_required_token_with_wrong_state_hash_is_rejected() -> None:
    state = _valid_state()
    state["tokens"]["governance"]["state_hash"] = "1" * 64
    result = evaluate_strict_execution_security(state)
    assert result["valid"] is False
    assert "signature_payload_mismatch:governance" in result["failures"]


def _load_json(path: Path) -> dict:
    import json

    return json.loads(path.read_text(encoding="utf-8"))
