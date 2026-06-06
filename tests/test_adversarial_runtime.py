from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import sample_request
from sbp_lex.api.apk_contract import validate_runtime_status_contract
from sbp_lex.api.schema_validation import validate_runtime_request_schema
from sbp_lex.connector.envelope import build_connector_envelope
from sbp_lex.connector.fabric import process_connector_envelope
from sbp_lex.execution.controlled_outcome import verify_controlled_outcome
from sbp_lex.execution.execution_gate import evaluate_strict_execution_security
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.runtime.canonical_runtime import CANONICAL_RUNTIME
from sbp_lex.runtime.event_bus import RUNTIME_EVENTS
from sbp_lex.security.execution_attestation import verify_execution_attestation
from sbp_lex.security.master_convergence_token import verify_master_token


def test_runtime_status_contract_valid_after_traversal():
    result = CANONICAL_RUNTIME.traverse(sample_request(), request_id="adversarial-status")
    status = CANONICAL_RUNTIME.status()
    ok, failures = validate_runtime_status_contract(status)
    assert result["state"]["decision"] == "ALLOW"
    assert ok, failures


def test_replay_audit_determinism_deep_fields_match():
    replay = run_replay_check(request=sample_request(), replay_count=3)
    assert replay["matched"] is True
    assert replay["mismatches"] == []
    reference = replay["reference"]
    for run in replay["runs"]:
        assert run["audit_hash"] == reference["audit_hash"]
        assert run["controlled_outcome_hash"] == reference["controlled_outcome_hash"]
        assert run["final_outcome"] == reference["final_outcome"]


def test_connector_duplicate_replay_rejected_with_recovery_record():
    envelope = build_connector_envelope(
        request_id="adversarial-connector-duplicate",
        source="apk_test",
        request=sample_request(),
        metadata={"purpose": "duplicate-check"},
    )
    first = process_connector_envelope(envelope)
    second = process_connector_envelope(envelope)
    assert first["accepted"] is True
    assert second["accepted"] is False
    assert "duplicate_connector_request_id" in second["failures"]
    assert "rejection" in second


def test_schema_rejects_object_pollution_key():
    bad = deepcopy(sample_request())
    bad["payload"]["__proto__"] = {"polluted": True}
    ok, failures = validate_runtime_request_schema(bad)
    assert ok is False
    assert any("forbidden_key" in item or "unknown_field" in item for item in failures)


def test_tampered_master_token_rejected():
    state = CANONICAL_RUNTIME.traverse(sample_request(), request_id="adversarial-token") ["state"]
    tampered = deepcopy(state)
    tampered["tokens"]["master_convergence"]["payload"]["decision"] = "DENY"
    assert verify_master_token(tampered) is False


def test_tampered_execution_attestation_rejected():
    state = CANONICAL_RUNTIME.traverse(sample_request(), request_id="adversarial-attestation") ["state"]
    attestation = deepcopy(state["execution_attestation"])
    attestation["payload"]["decision"] = "DENY"
    assert verify_execution_attestation(state, attestation) is False


def test_controlled_outcome_tamper_rejected():
    state = CANONICAL_RUNTIME.traverse(sample_request(), request_id="adversarial-outcome") ["state"]
    outcome = deepcopy(state["controlled_outcome"])
    outcome["payload"]["decision"] = "DENY"
    assert verify_controlled_outcome(outcome) is False


def test_strict_execution_security_rejects_missing_audit_hash():
    state = CANONICAL_RUNTIME.traverse(sample_request(), request_id="adversarial-strict") ["state"]
    tampered = deepcopy(state)
    tampered["audit_hash"] = ""
    result = evaluate_strict_execution_security(tampered)
    assert result["valid"] is False


def test_event_bus_integrity_verifies():
    ok, failures = RUNTIME_EVENTS.verify()
    assert ok, failures
