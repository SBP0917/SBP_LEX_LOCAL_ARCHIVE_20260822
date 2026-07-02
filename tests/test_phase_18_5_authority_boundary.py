from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

from external_substrates.demo.build_demo_pre_context_package import build_demo_chain
from external_substrates.shared.validation import contains_prohibited_authority
from main import sample_request
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.collective.context_interface import attach_collective_signals, prepare_pre_context_signals
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.shared.hash_chain import rebuild_state_hash
from sbp_lex.shared.state_builder import build_state


ROOT = Path(__file__).resolve().parents[1]
PROHIBITED_TOPOLOGY = {
    "node_quorum",
    "node_attestation",
    "distributed consensus",
    "multi-node execution",
    "distributed mesh",
    "quorum execution",
}


def _resign(signals: dict) -> dict:
    payload = {key: value for key, value in signals.items() if key not in {"digest", "signature"}}
    signals["digest"] = generate_digest(payload)
    signals["signature"] = sign_payload(payload)
    return signals


def _root_ready_state() -> dict:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    state = build_state(request, signals)
    state["hard_entry_gate"] = {
        "accepted": True,
        "request_fingerprint": state["request_fingerprint"],
        "signal_digest": signals["digest"],
        "failures": [],
    }
    state = attach_collective_signals(state, signals)
    return run_ap_acf_precheck(state)


def test_external_package_cannot_self_traverse() -> None:
    _, _, external_package = build_demo_chain()
    state = run_pipeline(sample_request(), external_package)
    assert state["hard_entry_gate"]["accepted"] is False
    assert state["integration_stage_order"] == ["hard_ingress", "audit", "controlled_return"]
    assert state["authority_first_result"] == "UNSET"


def test_external_package_cannot_bypass_hard_entry() -> None:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    signals["nested_claim"] = {"decision": "ALLOW"}
    state = run_pipeline(request, _resign(signals))
    assert state["hard_entry_gate"]["accepted"] is False
    assert "external_signal_contains_authority_result" in state["hard_entry_gate"]["failures"]
    assert "root_of_trust" not in state["integration_stage_order"]


def test_external_package_cannot_overwrite_request_fingerprint() -> None:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    signals["request_fingerprint"] = "external-overwrite-attempt"
    state = run_pipeline(request, _resign(signals))
    assert state["hard_entry_gate"]["accepted"] is False
    assert state["request_fingerprint"] == generate_digest(request)


def test_external_package_cannot_overwrite_governance_result() -> None:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    signals["governance_result"] = "ALLOW"
    state = run_pipeline(request, _resign(signals))
    assert state["hard_entry_gate"]["accepted"] is False
    assert state["governance_result"] == "UNSET"


def test_external_package_cannot_overwrite_execution_result() -> None:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    signals["execution_result"] = "EXECUTE"
    state = run_pipeline(request, _resign(signals))
    assert state["hard_entry_gate"]["accepted"] is False
    assert state["execution_result"] == "HALT"


def test_missing_pt_envelope_blocks_progression() -> None:
    state = _root_ready_state()
    state.pop("pt_evidence_envelope")
    result = run_root_of_trust(state)
    assert result["authority_first_result"] == "FAIL"
    assert result["classification_result"] == "UNSET"
    assert "pt_evidence_envelope_missing" in result["root_of_trust_evidence_anchor"]["failures"]


def test_invalid_pt_envelope_digest_blocks_progression() -> None:
    state = _root_ready_state()
    state["pt_evidence_envelope_digest"] = "tampered"
    result = run_root_of_trust(state)
    assert result["authority_first_result"] == "FAIL"
    assert "pt_evidence_envelope_digest_invalid" in result["root_of_trust_evidence_anchor"]["failures"]


def test_root_of_trust_missing_external_digest_blocks_progression() -> None:
    state = _root_ready_state()
    state["pt_evidence_envelope"]["skg_digest"] = None
    state["pt_evidence_envelope_digest"] = generate_digest(state["pt_evidence_envelope"])
    result = run_root_of_trust(state)
    assert result["authority_first_result"] == "FAIL"
    assert "root_anchor_missing:skg_digest" in result["root_of_trust_evidence_anchor"]["failures"]


def test_pt_result_mismatch_blocks_execution_progression() -> None:
    state = run_pipeline(sample_request())
    state["procedural_truth_outcome"] = "PT_REFINE"
    state["state_hash"] = rebuild_state_hash(state)
    result = run_execution_gate(state)
    assert result["execution_result"] == "HALT"
    assert "procedural_truth_outcome_mismatch" in result["token_verification_failures"]


def test_replay_preserves_pt_bound_external_metadata() -> None:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    replay = run_replay_check(request=request, pre_context_signals=signals, replay_count=2)
    first = replay["runs"][0]["pt_bound_metadata"]
    second = replay["runs"][1]["pt_bound_metadata"]
    assert replay["matched"] is True
    assert first == second
    assert {
        key: first[key]
        for key in (
            "request_fingerprint",
            "skg_digest",
            "dtn_digest",
            "pre_context_digest",
            "pt_evidence_envelope_digest",
        )
    } == {
        "request_fingerprint": generate_digest(request),
        "skg_digest": signals["skg_digest"],
        "dtn_digest": signals["dtn_digest"],
        "pre_context_digest": signals["digest"],
        "pt_evidence_envelope_digest": replay["runs"][0]["pt_evidence_envelope_digest"],
    }
    for key in (
        "eie_hash",
        "traversal_id",
        "source_payload_hash",
        "skg_enrichment_hash",
        "dtn_enrichment_hash",
        "root_anchor_digest",
        "token_chain_reference",
    ):
        assert first[key]


def test_audit_includes_full_pt_external_digest_lineage() -> None:
    state = run_pipeline(sample_request())
    binding = state["audit_record"]["payload"]["integration_evidence"]["procedural_truth_binding"]
    anchor = binding["root_of_trust_evidence_anchor"]
    envelope = state["pt_evidence_envelope"]
    assert binding["pt_envelope_digest"] == state["pt_evidence_envelope_digest"]
    assert anchor["payload"]["skg_digest"] == envelope["skg_digest"]
    assert anchor["payload"]["dtn_digest"] == envelope["dtn_digest"]
    assert anchor["payload"]["pre_context_digest"] == envelope["pre_context_digest"]
    assert anchor["payload"]["pt_evidence_envelope_digest"] == state["pt_evidence_envelope_digest"]


def test_no_sbp_lex_imports_inside_external_substrates() -> None:
    for path in (ROOT / "external_substrates").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(alias.name.startswith("sbp_lex") for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("sbp_lex")


def test_external_authority_results_are_prohibited() -> None:
    for value in ("ALLOW", "DENY", "ESCALATE"):
        assert contains_prohibited_authority({"signal": value}) is True
    assert contains_prohibited_authority({"execution_permission": True}) is True
    assert contains_prohibited_authority({"governance_result": "anything"}) is True


def test_no_prohibited_topology_in_active_source() -> None:
    roots = [ROOT / "sbp_lex", ROOT / "external_substrates"]
    for source_root in roots:
        for path in source_root.rglob("*.py"):
            if "tests" in path.parts:
                continue
            text = path.read_text(encoding="utf-8").lower()
            assert not any(term in text for term in PROHIBITED_TOPOLOGY)
