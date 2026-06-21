from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.audit_engine import run_audit
from sbp_lex.aurion15.runtime.runner import run_aurion_runtime
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.engine import run_classification
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.collective.context_interface import attach_collective_signals, prepare_pre_context_signals
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.execution.controlled_outcome import (
    apply_terminal_control_state,
    build_controlled_outcome,
    finalise_outcome,
    record_controlled_return,
)
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.governance.governance_runner import run_governance_pipeline
from sbp_lex.governance.procedural_truth_runner import run_procedural_truth_pipeline
from sbp_lex.licensing.engine import run_licensing
from sbp_lex.pipeline.hard_ingress import run_hard_ingress, validate_request_ingress
from sbp_lex.shared.state_builder import build_state
from sbp_lex.shared.hash_chain import append_hash_entry, rebuild_state_hash


def _mark_stage(state: Dict[str, Any], stage: str) -> Dict[str, Any]:
    order = list(state.get("integration_stage_order", []))
    if stage not in order:
        order.append(stage)
    state["integration_stage_order"] = order
    state["state_hash"] = rebuild_state_hash(state)
    return state


def _finalize_pipeline(state: Dict[str, Any]) -> Dict[str, Any]:
    state = apply_terminal_control_state(state)
    state = _mark_stage(state, "audit")
    state = run_audit(state)
    outcome = build_controlled_outcome(state)
    state = record_controlled_return(state, outcome)
    state = _mark_stage(state, "controlled_return")
    state["final_outcome"] = finalise_outcome(outcome)
    return state


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
        state["hard_entry_gate"] = {
            "accepted": False,
            "failures": ingress.get("failures", []),
        }
        state = _mark_stage(state, "hard_ingress")
        state = append_hash_entry(
            state,
            stage="hard_ingress",
            payload=state["hard_entry_gate"],
        )
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
        return _finalize_pipeline(state)

    state = build_state(request_copy, admitted_pre_context=signals)
    state["hard_entry_gate"] = {
        "accepted": True,
        "failures": [],
        "request_fingerprint": state.get("request_fingerprint"),
        "signal_digest": signals.get("digest") if signals else None,
    }
    state = _mark_stage(state, "hard_ingress")
    state = append_hash_entry(
        state, stage="hard_ingress", payload=state["hard_entry_gate"]
    )
    state = _mark_stage(state, "state_construction")
    state.setdefault("audit_trace", []).append(
        {
            "stage": "state_construction",
            "request_fingerprint": state.get("request_fingerprint"),
            "pt_evidence_envelope_digest": state.get("pt_evidence_envelope_digest"),
        }
    )
    state = append_hash_entry(
        state,
        stage="state_construction",
        payload={
            "request_fingerprint": state.get("request_fingerprint"),
            "state_version": state.get("state_version"),
            "pt_evidence_envelope_digest": state.get("pt_evidence_envelope_digest"),
        },
    )
    state = attach_collective_signals(state, signals)
    state = _mark_stage(state, "collective_attach")
    if state.get("collective_signal_status") == "ATTACHED":
        state = run_ap_acf_precheck(state)
        state = _mark_stage(state, "ap_acf_precheck")
    if state.get("ap_acf_precheck_result") == "PASS":
        state = run_root_of_trust(state)
        state = _mark_stage(state, "root_of_trust")
    if state.get("authority_first_result") == "PASS":
        state = run_procedural_truth_pipeline(state)
        state = _mark_stage(state, "procedural_truth")
    if (
        state.get("procedural_truth_result") == "PASS"
        and state.get("procedural_truth_outcome") == "PT_PASS"
    ):
        state = run_classification(state)
        state = _mark_stage(state, "classification")
    if state.get("classification_result") == "ALLOW":
        state = run_licensing(state)
        state = _mark_stage(state, "licensing")
    if state.get("licensing_result") == "ALLOW":
        state = run_governance_pipeline(state)
        state = _mark_stage(state, "governance")
        state = _mark_stage(state, "grc")
    if state.get("governance_result") == "ALLOW" and state.get("grc_result") == "PASS":
        state = run_domain_wrap(state)
        state = _mark_stage(state, "domain_wrap")
    if state.get("domain_result") == "pass":
        state = run_aurion_runtime(state)
        state = _mark_stage(state, "aurion_runtime")
    if state.get("aurion15_result") == "pass":
        state = run_execution_gate(state)
        state = _mark_stage(state, "execution_gate")
    else:
        state.setdefault("convergence_hash", state.get("state_hash"))
        state.setdefault("execution_verified", False)
        state.setdefault("decision", "DENY")
    return _finalize_pipeline(state)
