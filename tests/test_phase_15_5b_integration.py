from __future__ import annotations

from copy import deepcopy

from external_substrates.shared.canonical_json import canonical_dumps
from main import main, sample_request
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.collective.context_interface import prepare_pre_context_signals
from sbp_lex.execution.controlled_outcome import verify_controlled_outcome
from sbp_lex.governance.reentry_engine import evaluate_reentry
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.pipeline.runner import (
    PreparedPipelineBoundary,
    prepare_pipeline_boundary,
    run_pipeline,
)
from sbp_lex.security.pqc import generate_digest, sign_payload


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


def _resign_signal_package(signals: dict) -> dict:
    payload = {key: value for key, value in signals.items() if key not in {"digest", "signature"}}
    signals["digest"] = generate_digest(payload)
    signals["signature"] = sign_payload(payload)
    return signals


def _initial_state(request: dict, signals: dict | None = None) -> dict:
    prepared = prepare_pipeline_boundary(request, signals)
    assert isinstance(prepared, PreparedPipelineBoundary)
    return prepared.materialize()


def test_canonical_integration_stage_order_is_locked() -> None:
    state = main(sample_request())
    assert state["integration_stage_order"] == EXPECTED_STAGE_ORDER
    assert state["domain_result"] == "pass"
    assert state["aurion15_result"] == "pass"
    assert state["execution_result"] == "EXECUTE"


def test_hard_entry_gate_rejects_before_authoritative_traversal() -> None:
    request = sample_request()
    request.pop("resolved_authority")
    state = run_pipeline(request)
    assert state["hard_entry_gate"]["accepted"] is False
    assert state["integration_stage_order"] == ["hard_ingress"]
    assert state["governed_state_formed"] is False
    assert state["authority_token_issued"] is False
    assert "authority_first_result" not in state
    assert state["decision"] == "DENY"
    assert state["execution_result"] == "HALT"
    assert state["execution_verified"] is False


def test_request_fingerprint_remains_stable_across_hash_chain() -> None:
    request = sample_request()
    state = main(request)
    expected = generate_digest(request)
    assert state["request_fingerprint"] == expected
    assert all(entry["request_fingerprint"] == expected for entry in state["hash_chain"])


def test_skg_dtn_relation_mismatch_is_rejected_before_root_of_trust() -> None:
    request = sample_request()
    signals = prepare_pre_context_signals(request)
    dtn = deepcopy(signals["dtn_context"])
    dtn["skg_constraint_digest"] = "wrong-skg-digest"
    dtn_payload = {
        key: value for key, value in dtn.items() if key not in {"dtn_digest", "dtn_signature"}
    }
    dtn["dtn_digest"] = generate_digest(dtn_payload)
    dtn["dtn_signature"] = sign_payload({**dtn_payload, "dtn_digest": dtn["dtn_digest"]})
    signals["dtn_context"] = dtn
    signals["dtn_digest"] = dtn["dtn_digest"]
    _resign_signal_package(signals)

    state = run_pipeline(request, signals)
    assert state["governed_state_formed"] is False
    assert "dtn_skg_constraint_mismatch" in state["failures"]
    assert state["downstream_stage_reached"] is False


def test_collective_signals_are_context_only_and_verified() -> None:
    state = main(sample_request())
    evidence = state["collective_signal_evidence"]
    assert evidence["role"] == "context_only_non_authoritative"
    assert evidence["request_bound"] is True
    assert evidence["skg_verified"] is True
    assert evidence["dtn_verified"] is True
    assert evidence["skg_dtn_relation_verified"] is True


def test_ap_acf_precheck_precedes_root_and_cannot_change() -> None:
    request = sample_request()
    state = _initial_state(request)
    state["collective_signals"] = prepare_pre_context_signals(request)
    state = run_ap_acf_precheck(state)
    assert state["ap_acf_precheck_result"] == "PASS"
    state["ap_acf_declaration"]["ap_acf_class"] = "CLASS_1"
    from sbp_lex.classification.engine import run_classification

    classified = run_classification(state)
    assert classified["classification_result"] == "DENY"
    assert "ap_acf_declaration_changed_after_precheck" in classified["classification_reason"]


def test_root_of_trust_blocks_unresolved_authority() -> None:
    request = sample_request()
    state = _initial_state(request)
    state["resolved_authority"] = ""
    state["ap_acf_precheck_result"] = "PASS"
    result = run_root_of_trust(state)
    assert result["authority_first_result"] == "FAIL"
    assert result["execution_result"] == "HALT"
    assert "protected_state_field_mutation" in result[
        "root_of_trust_evidence_anchor"
    ]["failures"]


def test_classification_failure_prevents_all_later_authority_stages() -> None:
    request = sample_request()
    request["payload"]["classification"]["autonomy_level"] = 100
    state = run_pipeline(request)
    assert state["classification_result"] == "DENY"
    assert "licensing" not in state["integration_stage_order"]
    assert "governance" not in state["integration_stage_order"]
    assert "domain_wrap" not in state["integration_stage_order"]
    assert "aurion_runtime" not in state["integration_stage_order"]
    assert "execution_gate" not in state["integration_stage_order"]
    assert state["persistent_inoperability"] is True


def test_audit_contains_required_integration_evidence() -> None:
    state = main(sample_request())
    evidence = state["audit_record"]["payload"]["integration_evidence"]
    assert evidence["stage_order"] == EXPECTED_STAGE_ORDER[:-1]
    assert evidence["hard_entry_gate"]["accepted"] is True
    assert evidence["collective_signal_evidence"]["skg_dtn_relation_verified"] is True
    assert evidence["authority_first_result"] == "PASS"
    assert evidence["procedural_truth_result"] == "PASS"
    assert evidence["grc_result"] == "PASS"
    assert evidence["domain_wrap"]["result"] == "pass"
    assert evidence["aurion15_result"] == "pass"


def test_denied_state_is_persistently_inoperable_and_controlled() -> None:
    request = sample_request()
    request["payload"]["classification"]["autonomy_level"] = 100
    state = run_pipeline(request)
    assert state["operational_state"] == "PERSISTENT_INOPERABILITY"
    assert state["persistent_inoperability"] is True
    assert state["controlled_return_required"] is True
    assert verify_controlled_outcome(state["controlled_outcome"]) is True
    assert state["final_outcome"]["allowed"] is False


def test_identical_denied_request_cannot_self_authorize_reentry() -> None:
    fingerprint = "a" * 64
    result = evaluate_reentry(
        {
            "governance_result": "ALLOW",
            "request_fingerprint": fingerprint,
            "last_denied_fingerprint": fingerprint,
            "context": {
                "material_change_declared": True,
                "material_change_reason": "claimed change",
            },
        }
    )
    assert result["reentry_permitted"] is False
    assert result["required_action"] == "remain_inoperative"


def test_governed_reentry_requires_material_change_and_full_traversal() -> None:
    denied_request = sample_request()
    denied_request["payload"]["classification"]["autonomy_level"] = 100
    denied = run_pipeline(denied_request)

    corrected = sample_request()
    corrected["context"]["prior_denied_fingerprint"] = denied["request_fingerprint"]
    corrected["context"]["material_change_declared"] = True
    corrected["context"]["material_change_reason"] = "autonomy returned within locked ceiling"
    corrected["context"]["evidence"].append(
        {
            "source": "controlled_denial_proof",
            "content": canonical_dumps(denied["controlled_outcome"]),
            "verified": True,
            "attested": True,
            "freshness_valid": True,
            "consistency_valid": True,
        }
    )
    state = run_pipeline(corrected)
    assert state["integration_stage_order"] == EXPECTED_STAGE_ORDER
    assert state["governed_reentry"]["reentry_permitted"] is True
    assert state["governed_reentry"]["reentry_completed"] is True
    assert state["execution_result"] == "EXECUTE"


def test_replay_remains_deterministic_after_integration_alignment() -> None:
    replay = run_replay_check(request=sample_request(), replay_count=2)
    assert replay["matched"] is True
    assert replay["mismatches"] == []
