from __future__ import annotations

from copy import deepcopy

from main import sample_request
from sbp_lex.audit.historical_integrity import (
    AUDIT_CORRUPTION_DETECTED,
    HASH_CHAIN_MISMATCH,
    LINEAGE_MISMATCH,
    PT_ENVELOPE_MISMATCH,
    REQUEST_IDENTITY_MISMATCH,
    ROOT_OF_TRUST_MISMATCH,
    verify_historical_state,
)
from sbp_lex.audit.pipeline_replay_ledger import (
    PipelineReplayLedger,
    verify_replay_ledger_entries,
)
from sbp_lex.pipeline.replay_runner import run_replay_check, verify_replay_result
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.runtime.chronology import CanonicalChronology


def _completed_state() -> dict:
    state = run_pipeline(sample_request())
    assert verify_historical_state(state) == (True, [])
    return state


def _assert_state_attack_detected(state: dict, expected: str) -> None:
    valid, failures = verify_historical_state(state)
    assert valid is False
    assert expected in failures


def _ledger_fixture() -> tuple[list[dict], dict]:
    ledger = PipelineReplayLedger()
    for index in range(3):
        state = _completed_state()
        state["request_fingerprint"] = f"historical-request-{index}"
        ledger.append(state)
    entries = ledger.export()
    checkpoint = ledger.checkpoint()
    assert verify_replay_ledger_entries(entries, checkpoint) == (True, [])
    return entries, checkpoint


def test_attack_01_historical_audit_field_mutation_detected() -> None:
    state = _completed_state()
    state["audit_record"]["payload"]["decision"] = "DENY"
    _assert_state_attack_detected(state, AUDIT_CORRUPTION_DETECTED)


def test_attack_02_stored_pt_outcome_mutation_detected() -> None:
    state = _completed_state()
    state["procedural_truth_outcome"] = "PT_REFINE"
    _assert_state_attack_detected(state, LINEAGE_MISMATCH)


def test_attack_03_pt_envelope_digest_mutation_detected() -> None:
    state = _completed_state()
    state["pt_evidence_envelope_digest"] = "tampered-pt-envelope-digest"
    _assert_state_attack_detected(state, PT_ENVELOPE_MISMATCH)


def test_attack_04_request_fingerprint_lineage_mutation_detected() -> None:
    state = _completed_state()
    state["request_fingerprint"] = "mutated-request-fingerprint"
    _assert_state_attack_detected(state, REQUEST_IDENTITY_MISMATCH)


def test_attack_05_skg_digest_mutation_detected() -> None:
    state = _completed_state()
    state["pt_evidence_envelope"]["skg_digest"] = "mutated-skg-digest"
    _assert_state_attack_detected(state, PT_ENVELOPE_MISMATCH)


def test_attack_06_dtn_digest_mutation_detected() -> None:
    state = _completed_state()
    state["pt_evidence_envelope"]["dtn_digest"] = "mutated-dtn-digest"
    _assert_state_attack_detected(state, PT_ENVELOPE_MISMATCH)


def test_attack_07_pre_context_digest_mutation_detected() -> None:
    state = _completed_state()
    state["pt_evidence_envelope"]["pre_context_digest"] = "mutated-pre-context-digest"
    _assert_state_attack_detected(state, PT_ENVELOPE_MISMATCH)


def test_attack_08_root_of_trust_anchor_mutation_detected() -> None:
    state = _completed_state()
    state["root_of_trust_evidence_anchor"]["payload"]["skg_digest"] = "mutated-anchor"
    _assert_state_attack_detected(state, ROOT_OF_TRUST_MISMATCH)


def test_attack_09_execution_result_mutation_detected() -> None:
    state = _completed_state()
    state["execution_result"] = "HALT"
    _assert_state_attack_detected(state, LINEAGE_MISMATCH)


def test_attack_10_chronology_marker_mutation_detected() -> None:
    chronology = CanonicalChronology()
    chronology.append(event_type="traversal_started", payload={"request_id": "attack-10"})
    chronology.append(event_type="traversal_completed", payload={"request_id": "attack-10"})
    chronology._events[0]["timestamp"] = "FABRICATED_TIME"
    valid, failures = chronology.verify()
    assert valid is False
    assert "chronology_hash_mismatch:0" in failures


def test_attack_11_removed_audit_ledger_record_detected() -> None:
    entries, checkpoint = _ledger_fixture()
    entries.pop()
    valid, failures = verify_replay_ledger_entries(entries, checkpoint)
    assert valid is False
    assert "ledger_checkpoint_mismatch" in failures


def test_attack_12_fabricated_audit_ledger_record_detected() -> None:
    entries, checkpoint = _ledger_fixture()
    fabricated = deepcopy(entries[-1])
    entries.append(fabricated)
    valid, failures = verify_replay_ledger_entries(entries, checkpoint)
    assert valid is False
    assert any(reason.startswith("ledger_sequence_invalid") for reason in failures)
    assert "ledger_checkpoint_mismatch" in failures


def test_attack_13_reordered_audit_ledger_records_detected() -> None:
    entries, checkpoint = _ledger_fixture()
    entries[0], entries[1] = entries[1], entries[0]
    valid, failures = verify_replay_ledger_entries(entries, checkpoint)
    assert valid is False
    assert any(
        reason.startswith("ledger_sequence_invalid") or reason.startswith("ledger_link_broken")
        for reason in failures
    )


def test_attack_14_hash_chain_continuity_mutation_detected() -> None:
    state = _completed_state()
    state["hash_chain"][1]["previous_hash"] = "fabricated-previous-hash"
    _assert_state_attack_detected(state, HASH_CHAIN_MISMATCH)


def test_attack_15_replay_reference_identifier_mutation_detected() -> None:
    replay = run_replay_check(request=sample_request(), replay_count=2)
    assert verify_replay_result(replay) == (True, [])
    replay["reference"]["request_fingerprint"] = "fabricated-replay-reference"
    valid, failures = verify_replay_result(replay)
    assert valid is False
    assert failures == ["REPLAY_MISMATCH"]
