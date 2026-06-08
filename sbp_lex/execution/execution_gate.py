from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.execution_attestation import build_execution_attestation, verify_execution_attestation
from sbp_lex.security.master_convergence_token import issue_master_convergence_token, verify_master_token
from sbp_lex.security.threshold_tokens import verify_threshold_bundle
from sbp_lex.security.token_stack import issue_token, issue_token_bundle, verify_required_tokens
from sbp_lex.shared.convergence_digest import build_convergence_digest, verify_convergence_digest
from sbp_lex.shared.hash_chain import append_hash_entry, verify_hash_chain

STRICT_REQUIRED_TOKENS = [
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "domain",
    "aurion",
    "execution_boundary",
    "threshold_bundle",
    "token_bundle",
    "master_convergence",
    "execution_attestation",
]


def _deterministic_execution_timestamp(state: Mapping[str, Any]) -> str:
    return f"EXECUTION_EVENT_{len(state.get('hash_chain', [])) + len(state.get('token_trace', [])) + 1:012d}"


def _apply_fail_closed(state: Dict[str, Any], failures: list[str]) -> Dict[str, Any]:
    state["execution_result"] = "HALT"
    state["decision"] = "DENY"
    state["execution_verified"] = False
    state["execution_reason"] = ",".join(str(f) for f in failures) if failures else "fail_closed"
    state["token_stack_valid"] = False
    state["token_verification_failures"] = failures
    return state


def run_execution_gate(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []

    if not verify_hash_chain(working_state):
        failures.append("hash_chain_invalid")
    if working_state.get("authority_first_result") != "PASS":
        failures.append("authority_not_pass")
    if working_state.get("procedural_truth_result") != "PASS":
        failures.append("procedural_truth_not_pass")
    if working_state.get("classification_result") != "ALLOW":
        failures.append("classification_not_allow")
    if working_state.get("licensing_result") != "ALLOW":
        failures.append("licensing_not_allow")
    if working_state.get("governance_result") != "ALLOW":
        failures.append("governance_not_allow")
    if working_state.get("domain_result") != "pass":
        failures.append("domain_not_pass")
    if working_state.get("aurion15_result") != "pass":
        failures.append("aurion_not_pass")

    threshold_ok, threshold_failures = verify_threshold_bundle(working_state)
    if not threshold_ok:
        failures.extend(threshold_failures)

    working_state = issue_token(
        working_state,
        name="execution_boundary",
        issued_at_stage="execution_gate",
        payload={"pre_gate_failures": failures},
    )
    working_state = issue_token_bundle(working_state, issued_at_stage="execution_gate")

    pre_master_required = [
        "authority",
        "procedural_truth",
        "classification",
        "licensing",
        "governance",
        "domain",
        "aurion",
        "execution_boundary",
        "threshold_bundle",
        "token_bundle",
    ]
    token_ok, token_failures = verify_required_tokens(working_state, required=pre_master_required)
    if not token_ok:
        failures.extend(token_failures)

    if failures:
        working_state = _apply_fail_closed(working_state, failures)
    else:
        working_state["execution_result"] = "EXECUTE"
        working_state["decision"] = "ALLOW"
        working_state["execution_verified"] = True
        working_state["execution_reason"] = "execution_converged"

    convergence_digest = build_convergence_digest(working_state)
    working_state["convergence_hash"] = convergence_digest.get("convergence_hash")
    working_state["execution_convergence"] = convergence_digest

    if not verify_convergence_digest(working_state, convergence_digest):
        failures.append("convergence_digest_invalid")
        working_state = _apply_fail_closed(working_state, failures)
        convergence_digest = build_convergence_digest(working_state)
        working_state["convergence_hash"] = convergence_digest.get("convergence_hash")
        working_state["execution_convergence"] = convergence_digest

    working_state = issue_master_convergence_token(working_state, issued_at_stage="execution_gate")
    if not verify_master_token(working_state):
        failures.append("master_convergence_invalid")
        working_state = _apply_fail_closed(working_state, failures)

    working_state["execution_timestamp"] = _deterministic_execution_timestamp(working_state)
    attestation = build_execution_attestation(working_state)
    working_state["execution_attestation"] = attestation

    if not attestation.get("valid") or not verify_execution_attestation(working_state, attestation):
        failures.append("execution_attestation_invalid")
        working_state = _apply_fail_closed(working_state, failures)
        working_state["execution_timestamp"] = _deterministic_execution_timestamp(working_state)
        attestation = build_execution_attestation(working_state)
        working_state["execution_attestation"] = attestation

    working_state = issue_token(
        working_state,
        name="execution_attestation",
        issued_at_stage="execution_gate",
        payload=attestation,
    )

    final_ok, final_failures = verify_required_tokens(working_state, required=STRICT_REQUIRED_TOKENS)
    if not final_ok:
        failures.extend(final_failures)
        working_state = _apply_fail_closed(working_state, failures)

    if failures:
        working_state = _apply_fail_closed(working_state, failures)
    else:
        working_state["token_stack_valid"] = True
        working_state["token_verification_failures"] = []

    return append_hash_entry(
        working_state,
        stage="execution_gate",
        payload={
            "execution_result": working_state["execution_result"],
            "decision": working_state["decision"],
            "failures": failures,
        },
    )


def evaluate_strict_execution_security(state: Mapping[str, Any]) -> Dict[str, Any]:
    failures: list[str] = []

    if state.get("decision") == "ALLOW" and state.get("execution_result") != "EXECUTE":
        failures.append("allow_without_execute")
    if state.get("execution_result") == "EXECUTE" and state.get("execution_verified") is not True:
        failures.append("execute_without_verified")
    if state.get("execution_result") == "EXECUTE" and state.get("token_stack_valid") is not True:
        failures.append("execute_without_valid_token_stack")
    if state.get("token_verification_failures"):
        failures.append("token_failures_present")

    token_ok, token_failures = verify_required_tokens(state, required=STRICT_REQUIRED_TOKENS)
    if not token_ok:
        failures.extend(token_failures)

    if not verify_master_token(state):
        failures.append("master_convergence_invalid")

    if not verify_execution_attestation(state, state.get("execution_attestation", {})):
        failures.append("execution_attestation_invalid")

    convergence_record = state.get("execution_convergence", {})
    convergence_payload = convergence_record.get("payload", {}) if isinstance(convergence_record, Mapping) else {}
    if not isinstance(convergence_payload, Mapping):
        failures.append("convergence_digest_invalid")
    else:
        from sbp_lex.security.pqc import generate_digest, verify_signature

        if convergence_record.get("convergence_hash") != generate_digest(convergence_payload):
            failures.append("convergence_digest_invalid")
        elif not verify_signature(convergence_payload, convergence_record.get("signature", {})):
            failures.append("convergence_digest_invalid")
        elif convergence_payload.get("request_fingerprint") != state.get("request_fingerprint"):
            failures.append("convergence_digest_invalid")
        elif convergence_payload.get("decision") != state.get("decision"):
            failures.append("convergence_digest_invalid")
        elif convergence_payload.get("execution_result") != state.get("execution_result"):
            failures.append("convergence_digest_invalid")

    audit_record = state.get("audit_record", {})
    if audit_record:
        from sbp_lex.audit.audit_finalisation import verify_audit_record

        if not verify_audit_record(audit_record):
            failures.append("audit_record_invalid")
        elif state.get("audit_hash") != audit_record.get("audit_hash"):
            failures.append("audit_hash_mismatch")

    controlled_outcome = state.get("controlled_outcome", {})
    if controlled_outcome:
        from sbp_lex.execution.controlled_outcome import verify_controlled_outcome

        if not verify_controlled_outcome(controlled_outcome):
            failures.append("controlled_outcome_invalid")
        else:
            outcome_payload = controlled_outcome.get("payload", {})
            if outcome_payload.get("audit_hash") != state.get("audit_hash"):
                failures.append("controlled_outcome_audit_mismatch")
            if outcome_payload.get("convergence_hash") != state.get("convergence_hash"):
                failures.append("controlled_outcome_convergence_mismatch")
            if outcome_payload.get("decision") != state.get("decision"):
                failures.append("controlled_outcome_decision_mismatch")

    return {
        "valid": len(failures) == 0,
        "allowed": len(failures) == 0 and state.get("decision") == "ALLOW",
        "failures": failures,
    }


def evaluate_execution_gate(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    state = run_execution_gate(execution_state)
    return {
        "allowed": state.get("execution_result") == "EXECUTE",
        "decision": state.get("decision"),
        "failures": state.get("token_verification_failures", []),
    }


def validate_execution_integrity(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    required = ["state_hash", "convergence_hash", "pipeline_mode"]
    failures = [field for field in required if execution_state.get(field) is None]
    return {"valid": len(failures) == 0, "failures": failures}


def enforce_execution_boundary(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    gate = evaluate_execution_gate(execution_state)
    integrity = validate_execution_integrity(execution_state)
    if not gate["allowed"] or not integrity["valid"]:
        return {"allowed": False, "decision": "DENY", "boundary_locked": True}
    return {"allowed": True, "boundary_locked": False}
