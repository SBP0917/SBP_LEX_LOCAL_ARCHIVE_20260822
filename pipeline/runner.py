from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.audit_engine import run_audit
from sbp_lex.aurion15.runtime.runner import run_aurion_runtime
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.engine import run_classification
from sbp_lex.collective.context_interface import attach_collective_signals, prepare_pre_context_signals
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.execution.controlled_outcome import build_controlled_outcome, finalise_outcome
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.governance.governance_runner import run_governance_pipeline
from sbp_lex.governance.procedural_truth_runner import run_procedural_truth_pipeline
from sbp_lex.licensing.engine import run_licensing
from sbp_lex.pipeline.hard_ingress import run_hard_ingress, validate_request_ingress
from sbp_lex.shared.state_builder import build_state


def run_pipeline(request: Mapping[str, Any], pre_context_signals: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_copy = deepcopy(dict(request))
    request_ok, request_failures = validate_request_ingress(request_copy)
    if not request_ok:
        ingress = {"accepted": False, "failures": request_failures}
        signals = None
    else:
        signals = deepcopy(dict(pre_context_signals)) if pre_context_signals else prepare_pre_context_signals(request_copy)
        ingress = run_hard_ingress(request=request_copy, pre_context_signals=signals)
    if not ingress.get("accepted"):
        state = build_state(request_copy)
        state["decision"] = "DENY"
        state["execution_result"] = "HALT"
        state["execution_verified"] = False
        state["execution_reason"] = "ingress_denied"
        state["pipeline_mode"] = "MODE_3_SINGLE_CONSTRAINED"
        state["convergence_hash"] = state.get("state_hash")
        state["ingress_failures"] = ingress.get("failures", [])
        state.setdefault("governance_feedback", {})["ingress"] = {
            "accepted": False,
            "failures": ingress.get("failures", []),
        }
        state.setdefault("audit_trace", []).append(
            {"stage": "hard_ingress", "event": "INGRESS_DENIED", "failures": ingress.get("failures", [])}
        )
        state = run_audit(state)
        outcome = build_controlled_outcome(state)
        state["controlled_outcome"] = outcome
        state["final_outcome"] = finalise_outcome(outcome)
        return state

    state = build_state(request_copy)
    state = attach_collective_signals(state, signals)
    state = run_root_of_trust(state)
    if state.get("authority_first_result") == "PASS":
        state = run_procedural_truth_pipeline(state)
    if state.get("procedural_truth_result") == "PASS":
        state = run_classification(state)
    if state.get("classification_result") == "ALLOW":
        state = run_licensing(state)
    if state.get("licensing_result") == "ALLOW":
        state = run_governance_pipeline(state)
    if state.get("governance_result") == "ALLOW":
        state = run_domain_wrap(state)
    if state.get("domain_result") == "pass":
        state = run_aurion_runtime(state)
    if state.get("aurion15_result") == "pass":
        state = run_execution_gate(state)
    else:
        state.setdefault("convergence_hash", state.get("state_hash"))
        state.setdefault("execution_verified", False)
        state.setdefault("decision", "DENY")
    state = run_audit(state)
    outcome = build_controlled_outcome(state)
    state["controlled_outcome"] = outcome
    state["final_outcome"] = finalise_outcome(outcome)
    return state
