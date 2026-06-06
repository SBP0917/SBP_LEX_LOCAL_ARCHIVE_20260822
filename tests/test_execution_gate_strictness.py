from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import main, sample_request
from sbp_lex.execution.controlled_outcome import verify_controlled_outcome
from sbp_lex.execution.execution_gate import evaluate_strict_execution_security
from sbp_lex.security.execution_attestation import verify_execution_attestation
from sbp_lex.security.master_convergence_token import verify_master_token
from sbp_lex.security.token_stack import verify_required_tokens


def _baseline_state():
    return main(sample_request())


def assert_rejected(label: str, state: dict) -> None:
    result = evaluate_strict_execution_security(state)
    assert not result["valid"], f"{label} was not rejected: {result}"


def test_baseline_execution_strictness_passes() -> None:
    state = _baseline_state()
    assert state["decision"] == "ALLOW"
    assert state["execution_result"] == "EXECUTE"
    assert state["token_stack_valid"] is True
    assert evaluate_strict_execution_security(state)["valid"] is True


def test_missing_master_token_rejected() -> None:
    state = _baseline_state()
    state["tokens"].pop("master_convergence", None)
    assert verify_master_token(state) is False
    assert_rejected("missing master token", state)


def test_tampered_governance_token_rejected() -> None:
    state = _baseline_state()
    state["tokens"]["governance"]["digest"] = "tampered"
    ok, failures = verify_required_tokens(state, required=["governance"])
    assert ok is False
    assert "invalid_token:governance" in failures
    assert_rejected("tampered governance token", state)


def test_tampered_execution_attestation_rejected() -> None:
    state = _baseline_state()
    state["execution_attestation"]["payload"]["decision"] = "DENY"
    assert verify_execution_attestation(state, state["execution_attestation"]) is False
    assert_rejected("tampered execution attestation", state)


def test_tampered_convergence_hash_rejected() -> None:
    state = _baseline_state()
    state["convergence_hash"] = "tampered"
    assert_rejected("tampered convergence hash", state)


def test_tampered_audit_hash_rejected() -> None:
    state = _baseline_state()
    state["audit_hash"] = "tampered"
    assert_rejected("tampered audit hash", state)


def test_tampered_controlled_outcome_rejected() -> None:
    state = _baseline_state()
    state["controlled_outcome"]["payload"]["decision"] = "DENY"
    assert verify_controlled_outcome(state["controlled_outcome"]) is False
    assert_rejected("tampered controlled outcome", state)


def test_missing_execution_attestation_token_rejected() -> None:
    state = _baseline_state()
    state["tokens"].pop("execution_attestation", None)
    assert_rejected("missing execution attestation token", state)
