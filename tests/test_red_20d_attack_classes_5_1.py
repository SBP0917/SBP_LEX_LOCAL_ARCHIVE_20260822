from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from main import sample_request
from sbp_lex.audit.historical_integrity import verify_historical_state
from sbp_lex.audit.pipeline_replay_ledger import PipelineReplayLedger, compare_replay_ledger_heads
from sbp_lex.execution.execution_gate import evaluate_strict_execution_security
from sbp_lex.persistence.integrity_store import IntegrityStore
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.security.authority_boundary import validate_canonical_upstream, verify_canonical_stage_lineage
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.security.supply_chain import build_supply_chain_manifest, validate_supply_chain_manifest
from sbp_lex.security.token_stack import TOKEN_SIGNED_FIELDS


def _state(action: str = "red20d") -> dict:
    request = sample_request()
    request["action"] = action
    state = run_dual_pipeline(request)
    assert state["execution_result"] == "EXECUTE"
    return state


def _resign_token(token: dict) -> None:
    payload = {key: token[key] for key in TOKEN_SIGNED_FIELDS}
    token["digest"] = generate_digest(payload)
    token["signature"] = sign_payload(payload)


def _boundary_rejects(state: dict, token: str) -> list[str]:
    valid, failures = validate_canonical_upstream(state, required_tokens=(token,))
    assert valid is False
    return failures


def _supply_attack(name: str) -> list[str]:
    artifacts = {name: "trusted-content"}
    manifest = build_supply_chain_manifest(artifacts)
    trusted = manifest["manifest_digest"]
    valid, failures = validate_supply_chain_manifest(
        manifest, {name: "substituted-content"}, trusted_manifest_digest=trusted
    )
    assert valid is False
    return failures


def test_d1_forged_audit_signature_does_not_hide_lineage_change() -> None:
    state = _state("d1")
    state["audit_record"]["payload"]["decision"] = "DENY"
    payload = state["audit_record"]["payload"]
    state["audit_record"]["audit_hash"] = generate_digest(payload)
    state["audit_record"]["signature"] = sign_payload(payload)
    state["audit_hash"] = state["audit_record"]["audit_hash"]
    valid, failures = verify_historical_state(state)
    assert valid is False and "LINEAGE_MISMATCH" in failures


def test_d2_forged_replay_signature_conflicts_with_trusted_head() -> None:
    trusted = PipelineReplayLedger()
    forged = PipelineReplayLedger()
    trusted.append(_state("d2-trusted"))
    forged.append(_state("d2-forged"))
    valid, failures = compare_replay_ledger_heads(trusted.checkpoint(), forged.checkpoint())
    assert valid is False and failures == ["split_history_detected"]


def test_d3_forged_procedural_truth_token_rejected_by_active_state() -> None:
    state = _state("d3")
    state["tokens"]["procedural_truth"]["payload"]["procedural_truth_outcome"] = "PT_FAIL"
    _resign_token(state["tokens"]["procedural_truth"])
    assert "validation_state_mismatch:procedural_truth" in _boundary_rejects(state, "procedural_truth")


def test_d4_forged_governance_token_rejected_by_active_state() -> None:
    state = _state("d4")
    state["tokens"]["governance"]["payload"]["governance_result"] = "DENY"
    _resign_token(state["tokens"]["governance"])
    assert "validation_state_mismatch:governance" in _boundary_rejects(state, "governance")


def test_d5_forged_root_artifact_rejected_by_envelope_lineage() -> None:
    state = _state("d5")
    anchor = state["root_of_trust_evidence_anchor"]
    anchor["payload"]["skg_digest"] = "forged"
    anchor["anchor_digest"] = generate_digest(anchor["payload"])
    anchor["signature"] = sign_payload(anchor["payload"])
    valid, failures = verify_historical_state(state)
    assert valid is False and "ROOT_OF_TRUST_MISMATCH" in failures


def test_d6_hard_entry_bypass_rejected() -> None:
    state = _state("d6"); state["hard_entry_gate"]["accepted"] = False
    assert "traversal_bypass_detected:hard_entry_gate" in _boundary_rejects(state, "authority")


def test_d7_root_of_trust_bypass_rejected() -> None:
    state = _state("d7"); state["integration_stage_order"].remove("root_of_trust")
    assert "traversal_bypass_detected:root_of_trust" in _boundary_rejects(state, "authority")


def test_d8_procedural_truth_bypass_rejected() -> None:
    state = _state("d8"); state["integration_stage_order"].remove("procedural_truth")
    assert "traversal_bypass_detected:procedural_truth" in _boundary_rejects(state, "procedural_truth")


def test_d9_governance_bypass_rejected() -> None:
    state = _state("d9"); state["integration_stage_order"].remove("governance")
    assert "traversal_bypass_detected:governance" in _boundary_rejects(state, "governance")


def test_d10_execution_gate_bypass_rejected() -> None:
    state = _state("d10"); state["integration_stage_order"].remove("execution_gate")
    valid, failures = verify_canonical_stage_lineage(state, required_tokens=("execution_attestation",))
    assert valid is False and "traversal_bypass_detected:execution_gate" in failures


def test_d11_dependency_substitution_rejected() -> None:
    assert "supply_chain_compromise_detected:artifact_substitution" in _supply_attack("dependency.lock")


def test_d12_fixture_substitution_rejected() -> None:
    assert "supply_chain_compromise_detected:artifact_substitution" in _supply_attack("fixture.json")


def test_d13_build_artifact_substitution_rejected() -> None:
    assert "supply_chain_compromise_detected:artifact_substitution" in _supply_attack("build.whl")


def test_d14_release_package_substitution_rejected() -> None:
    assert "supply_chain_compromise_detected:artifact_substitution" in _supply_attack("release.zip")


def test_d15_validation_tool_substitution_rejected() -> None:
    artifacts = {"release.zip": "trusted"}; manifest = build_supply_chain_manifest(artifacts)
    trusted = manifest["manifest_digest"]
    manifest["payload"]["validation_tool_id"] = "COMPROMISED_VALIDATOR"
    manifest["manifest_digest"] = generate_digest(manifest["payload"])
    manifest["signature"] = sign_payload(manifest["payload"])
    valid, failures = validate_supply_chain_manifest(manifest, artifacts, trusted_manifest_digest=trusted)
    assert valid is False and "supply_chain_compromise_detected:validation_tool" in failures


def test_d16_false_authority_token_rejected() -> None:
    state = _state("d16"); state["tokens"]["authority"]["signature"]["signature"] = "0" * 64
    assert "signature_payload_mismatch:authority" in _boundary_rejects(state, "authority")


def test_d17_false_authority_lineage_rejected() -> None:
    state = _state("d17"); state["token_trace"] = [x for x in state["token_trace"] if x.get("name") != "authority"]
    assert "token_lineage_mismatch:authority" in _boundary_rejects(state, "authority")


def test_d18_false_jurisdiction_authority_rejected() -> None:
    state = _state("d18"); state["jurisdiction"] = "forged-jurisdiction"
    assert "toctou_state_mismatch:jurisdiction" in _boundary_rejects(state, "authority")


def test_d19_false_licensing_authority_rejected() -> None:
    state = _state("d19"); state["licensing_result"] = "DENY"
    assert "validation_state_mismatch:licensing" in _boundary_rejects(state, "licensing")


def test_d20_false_governance_authority_rejected() -> None:
    state = _state("d20"); state["governance_result"] = "DENY"
    assert "validation_state_mismatch:governance" in _boundary_rejects(state, "governance")


def test_d21_token_theft_plus_replay_rejected() -> None:
    source, target = _state("d21-source"), _state("d21-target")
    target["tokens"]["authority"] = deepcopy(source["tokens"]["authority"])
    assert "signature_payload_mismatch:authority" in _boundary_rejects(target, "authority")


def test_d22_token_theft_plus_pt_manipulation_rejected() -> None:
    source, target = _state("d22-source"), _state("d22-target")
    target["tokens"]["procedural_truth"] = deepcopy(source["tokens"]["procedural_truth"])
    target["procedural_truth_outcome"] = "PT_FAIL"
    assert _boundary_rejects(target, "procedural_truth")


def test_d23_rollback_plus_authority_substitution_rejected() -> None:
    ledger = PipelineReplayLedger(); ledger.append(_state("d23-a")); old = ledger.checkpoint(); ledger.append(_state("d23-b"))
    assert compare_replay_ledger_heads(ledger.checkpoint(), old) == (False, ["rollback_rejected"])
    state = _state("d23-c"); state["tokens"]["authority"] = deepcopy(_state("d23-d")["tokens"]["authority"])
    assert _boundary_rejects(state, "authority")


def test_d24_persistence_poisoning_plus_authority_capture_rejected(tmp_path: Path) -> None:
    path = tmp_path / "integrity.jsonl"; store = IntegrityStore(path, allowed_root=tmp_path)
    state = _state("d24"); store.append_state_summary(state)
    record = json.loads(path.read_text(encoding="utf-8")); record["decision"] = "DENY"; path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert IntegrityStore(path, allowed_root=tmp_path).verify()[0] is False
    state["tokens"]["governance"]["signature"]["signature"] = "0" * 64
    assert _boundary_rejects(state, "governance")


def test_d25_full_coordinated_boundary_collapse_fails_closed() -> None:
    source, target = _state("d25-source"), _state("d25-target")
    target["tokens"]["authority"] = deepcopy(source["tokens"]["authority"])
    target["integration_stage_order"].remove("procedural_truth")
    target["pt_evidence_envelope_digest"] = "forged"
    target["decision"] = "ALLOW"; target["execution_result"] = "EXECUTE"
    result = evaluate_strict_execution_security(target)
    assert result["valid"] is False and result["allowed"] is False
    assert any("traversal_bypass_detected" in failure for failure in result["failures"])
