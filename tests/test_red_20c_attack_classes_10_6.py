from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from external_substrates.demo.build_demo_pre_context_package import build_demo_chain
from main import sample_request
from sbp_lex.api.schema_validation import (
    validate_connector_envelope_schema,
    validate_runtime_request_schema,
)
from sbp_lex.audit.audit_finalisation import verify_audit_record
from sbp_lex.audit.historical_integrity import (
    AUDIT_CORRUPTION_DETECTED,
    HASH_CHAIN_MISMATCH,
    LINEAGE_MISMATCH,
    detect_competing_historical_states,
    verify_historical_state,
)
from sbp_lex.audit.pipeline_replay_ledger import (
    PipelineReplayLedger,
    compare_replay_ledger_heads,
    verify_replay_ledger_entries,
)
from sbp_lex.connector.envelope import build_connector_envelope
from sbp_lex.connector.recovery import ConnectorRecoveryStore
from sbp_lex.execution.controlled_outcome import build_controlled_outcome, finalise_outcome
from sbp_lex.persistence.integrity_store import (
    IntegrityStore,
    quarantine_poisoned_integrity_store,
)
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.runtime.chronology import CanonicalChronology, compare_chronology_heads
from sbp_lex.security.authority_boundary import validate_canonical_upstream
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.security.token_stack import verify_token


def _state(request: dict | None = None) -> dict:
    state = run_pipeline(request or sample_request())
    assert verify_historical_state(state) == (True, [])
    return state


def _state_variant(action: str) -> dict:
    request = sample_request()
    request["action"] = action
    return _state(request)


def _integrity_state(sequence: int) -> dict:
    return {
        "request_fingerprint": f"request-{sequence}",
        "state_hash": f"state-{sequence}",
        "decision": "DENY",
        "execution_result": "HALT",
        "audit_hash": f"audit-{sequence}",
        "pipeline_convergence": {"convergence_hash": f"convergence-{sequence}"},
    }


def test_01_competing_chronology_heads_rejected() -> None:
    first = CanonicalChronology()
    second = CanonicalChronology()
    first.append(event_type="traversal_started", payload={"branch": "a"})
    second.append(event_type="traversal_started", payload={"branch": "b"})
    valid, failures = compare_chronology_heads(first.checkpoint(), second.checkpoint())
    assert valid is False
    assert failures == ["split_history_detected"]


def test_02_competing_replay_heads_rejected() -> None:
    first = PipelineReplayLedger()
    second = PipelineReplayLedger()
    first.append(_state_variant("fork_a"))
    second.append(_state_variant("fork_b"))
    valid, failures = compare_replay_ledger_heads(first.checkpoint(), second.checkpoint())
    assert valid is False
    assert failures == ["split_history_detected"]


def test_03_competing_audit_chain_mutation_rejected() -> None:
    state = _state()
    state["audit_record"]["payload"]["audit_chain"][0]["hash"] = "forked-chain"
    payload = state["audit_record"]["payload"]
    state["audit_record"]["audit_hash"] = generate_digest(payload)
    state["audit_record"]["signature"] = sign_payload(payload)
    state["audit_hash"] = state["audit_record"]["audit_hash"]
    valid, failures = verify_historical_state(state)
    assert valid is False
    assert HASH_CHAIN_MISMATCH in failures


def test_04_two_individually_signed_histories_are_detected_as_split() -> None:
    first = _state()
    second = deepcopy(first)
    second["audit_record"]["payload"]["integration_evidence"]["fork_marker"] = "branch_b"
    payload = second["audit_record"]["payload"]
    second["audit_record"]["audit_hash"] = generate_digest(payload)
    second["audit_record"]["signature"] = sign_payload(payload)
    second["audit_hash"] = second["audit_record"]["audit_hash"]
    second["controlled_outcome"] = build_controlled_outcome(second)
    second["final_outcome"] = finalise_outcome(second["controlled_outcome"])
    assert verify_historical_state(second) == (True, [])
    valid, failures = detect_competing_historical_states([first, second])
    assert valid is False
    assert failures == ["split_history_detected"]


def test_05_rollback_to_earlier_replay_head_rejected() -> None:
    ledger = PipelineReplayLedger()
    ledger.append(_state_variant("rollback_1"))
    earlier = ledger.checkpoint()
    ledger.append(_state_variant("rollback_2"))
    current = ledger.checkpoint()
    valid, failures = compare_replay_ledger_heads(current, earlier)
    assert valid is False
    assert failures == ["rollback_rejected"]


def test_06_local_audit_modification_detected() -> None:
    state = _state()
    state["audit_record"]["payload"]["decision"] = "DENY"
    valid, failures = verify_historical_state(state)
    assert valid is False
    assert AUDIT_CORRUPTION_DETECTED in failures


def test_07_local_replay_record_modification_detected() -> None:
    ledger = PipelineReplayLedger()
    ledger.append(_state())
    entries = ledger.export()
    entries[0]["decision"] = "DENY"
    valid, failures = verify_replay_ledger_entries(entries, ledger.checkpoint())
    assert valid is False
    assert "ledger_corruption:0" in failures


def test_08_local_checkpoint_modification_detected() -> None:
    ledger = PipelineReplayLedger()
    ledger.append(_state())
    checkpoint = ledger.checkpoint()
    checkpoint["payload"]["head_hash"] = "insider-head"
    valid, failures = verify_replay_ledger_entries(ledger.export(), checkpoint)
    assert valid is False
    assert "ledger_checkpoint_mismatch" in failures


def test_09_local_execution_attestation_modification_detected() -> None:
    state = _state()
    state["execution_attestation"]["payload"]["execution_result"] = "HALT"
    valid, failures = verify_historical_state(state)
    assert valid is False
    assert LINEAGE_MISMATCH in failures


def test_10_stolen_authority_token_rejected() -> None:
    victim = _state_variant("victim_authority")
    attacker = _state_variant("attacker_authority")
    attacker["tokens"]["authority"] = deepcopy(victim["tokens"]["authority"])
    valid, failures = validate_canonical_upstream(
        attacker, required_tokens=("authority",)
    )
    assert valid is False
    assert "signature_payload_mismatch:authority" in failures


def test_11_cross_request_governance_token_replay_rejected() -> None:
    first = _state_variant("token_source")
    second = _state_variant("token_target")
    second["tokens"]["governance"] = deepcopy(first["tokens"]["governance"])
    assert verify_token(
        second["tokens"]["governance"],
        expected_request_fingerprint=second["request_fingerprint"],
    ) is False


def test_12_authority_escalation_attempt_rejected() -> None:
    state = _state()
    token = state["tokens"]["authority"]
    token["payload"]["authority_result"] = "SUPERUSER"
    assert verify_token(token, expected_request_fingerprint=state["request_fingerprint"]) is False


def test_13_token_lineage_substitution_rejected() -> None:
    state = _state()
    state["token_trace"] = [
        entry for entry in state["token_trace"] if entry.get("name") != "governance"
    ]
    valid, failures = validate_canonical_upstream(
        state, required_tokens=("governance",)
    )
    assert valid is False
    assert "token_lineage_mismatch:governance" in failures


def test_14_command_injection_payload_rejected() -> None:
    request = sample_request()
    request["payload"]["parameters"] = {"instruction": "safe && powershell -c whoami"}
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert any(reason.startswith("command_injection_rejected:") for reason in failures)


def test_15_template_injection_payload_rejected() -> None:
    request = sample_request()
    request["payload"]["metadata"] = {"template": "{{ authority.override }}"}
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert any(reason.startswith("template_injection_rejected:") for reason in failures)


def test_16_report_injection_payload_rejected() -> None:
    request = sample_request()
    request["context"]["evidence"][0]["content"] = "evidence\n# Forged Audit Result"
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert any(reason.startswith("report_injection_rejected:") for reason in failures)


def test_17_connector_metadata_injection_rejected() -> None:
    envelope = build_connector_envelope(
        request_id="red-20c-injection",
        source="red20c",
        request=sample_request(),
        metadata={"operator_template": "${execute_authority}"},
    )
    valid, failures = validate_connector_envelope_schema(envelope)
    assert valid is False
    assert any(reason.startswith("template_injection_rejected:") for reason in failures)


def test_18_poisoned_recovery_state_rejected() -> None:
    store = ConnectorRecoveryStore()
    store.claim("recovery-poison")
    store.save(
        "recovery-poison",
        {
            "request_fingerprint": "request",
            "state_hash": "state",
            "decision": "DENY",
            "execution_result": "HALT",
            "audit_hash": "audit",
            "pipeline_mode": "MODE_3_SINGLE_CONSTRAINED",
        },
    )
    store._history[0]["decision"] = "ALLOW"
    valid, failures = store.verify()
    assert valid is False
    assert any("connector_checkpoint" in reason for reason in failures)


def test_19_poisoned_integrity_store_rejected(tmp_path: Path) -> None:
    path = tmp_path / "runtime_artifacts" / "integrity.jsonl"
    store = IntegrityStore(path, allowed_root=path.parent)
    store.append_state_summary(_integrity_state(1))
    record = json.loads(path.read_text(encoding="utf-8"))
    record["decision"] = "ALLOW"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    restarted = IntegrityStore(path, allowed_root=path.parent)
    valid, failures = restarted.verify()
    assert valid is False
    assert "persistence_poisoning_detected" in failures


def test_20_compromised_persistence_baseline_rollback_rejected(tmp_path: Path) -> None:
    path = tmp_path / "runtime_artifacts" / "integrity.jsonl"
    store = IntegrityStore(path, allowed_root=path.parent)
    store.append_state_summary(_integrity_state(1))
    store.append_state_summary(_integrity_state(2))
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")
    restarted = IntegrityStore(path, allowed_root=path.parent)
    valid, failures = restarted.verify()
    assert valid is False
    assert "persistence_poisoning_detected" in failures


def test_21_restart_from_poisoned_checkpoint_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "runtime_artifacts" / "integrity.jsonl"
    store = IntegrityStore(path, allowed_root=path.parent)
    store.append_state_summary(_integrity_state(1))
    checkpoint_path = path.with_suffix(path.suffix + ".checkpoint.json")
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["payload"]["head_hash"] = "poisoned-head"
    checkpoint_path.write_text(json.dumps(checkpoint) + "\n", encoding="utf-8")
    restarted = IntegrityStore(path, allowed_root=path.parent)
    with pytest.raises(RuntimeError, match="persistence_poisoning_detected"):
        restarted.append_state_summary(_integrity_state(2))


def test_22_poisoned_integrity_store_quarantine_preserves_evidence(tmp_path: Path) -> None:
    path = tmp_path / "runtime_artifacts" / "integrity.jsonl"
    path.parent.mkdir(parents=True)
    payload = '{"sequence":1,"sequence":2}\n'
    path.write_text(payload, encoding="utf-8")
    result = quarantine_poisoned_integrity_store(path, allowed_root=path.parent)
    quarantined = Path(result["quarantine_path"])
    assert path.exists() is False
    assert quarantined.exists() is True
    assert quarantined.read_text(encoding="utf-8") == payload
    assert result["source"] == str(path.resolve())
    assert result["checkpoint_quarantine_path"] is None
    assert result["size"] == quarantined.stat().st_size
    assert result["sha256"] in quarantined.name
    assert result["failures"] == ["persistence_parse_failure:0"]


def test_23_valid_integrity_store_is_not_quarantined(tmp_path: Path) -> None:
    path = tmp_path / "runtime_artifacts" / "integrity.jsonl"
    store = IntegrityStore(path, allowed_root=path.parent)
    store.append_state_summary(_integrity_state(1))
    with pytest.raises(RuntimeError, match="integrity_store_valid"):
        quarantine_poisoned_integrity_store(path, allowed_root=path.parent)
    assert path.exists() is True
