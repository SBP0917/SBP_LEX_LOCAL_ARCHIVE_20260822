from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
from typing import Any, Dict, Mapping

from external_substrates.shared.canonical_json import canonical_dumps
from sbp_lex.audit.audit_engine import run_audit
from sbp_lex.aurion15.runtime.runner import run_aurion_runtime
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.engine import run_classification
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.collective.context_interface import attach_collective_signals
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.execution.controlled_outcome import (
    apply_terminal_control_state,
    build_controlled_outcome,
    finalise_outcome,
    record_controlled_return,
)
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.governance.governance_runner import run_governance_pipeline
from sbp_lex.governance.procedural_truth_runner import (
    run_procedural_truth_pipeline,
)
from sbp_lex.licensing.engine import run_licensing
from sbp_lex.pipeline.hard_ingress import run_hard_ingress
from sbp_lex.runtime.boundary_types import EIEReplayRegistry
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.state_builder import (
    build_state,
    validate_boundary_protection,
)
from sbp_lex.shared.hash_chain import append_hash_entry, rebuild_state_hash


@dataclass(frozen=True)
class PreparedPipelineBoundary:
    """Immutable attached initial state shared exactly by both pipelines."""

    schema_version: str
    state_json: str
    state_digest: str
    state_construction_hash: str
    pre_attachment_state_hash: str
    collective_attachment_hash: str
    admission_digest: str
    seal_digest: str

    def _seal_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "state_digest": self.state_digest,
            "state_construction_hash": self.state_construction_hash,
            "pre_attachment_state_hash": self.pre_attachment_state_hash,
            "collective_attachment_hash": self.collective_attachment_hash,
            "admission_digest": self.admission_digest,
        }

    def materialize(self) -> Dict[str, Any]:
        try:
            decoded = json.loads(self.state_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("prepared_boundary_state_invalid") from exc
        if not isinstance(decoded, dict):
            raise ValueError("prepared_boundary_state_invalid")
        if canonical_dumps(decoded) != self.state_json:
            raise ValueError("prepared_boundary_state_not_canonical")
        if generate_digest(decoded) != self.state_digest:
            raise ValueError("prepared_boundary_state_digest_mismatch")
        if generate_digest(self._seal_payload()) != self.seal_digest:
            raise ValueError("prepared_boundary_seal_mismatch")
        if decoded.get("state_construction_hash") != (
            self.state_construction_hash
        ):
            raise ValueError("prepared_boundary_construction_hash_mismatch")
        if decoded.get("collective_attachment", {}).get(
            "attachment_hash"
        ) != self.collective_attachment_hash:
            raise ValueError("prepared_boundary_attachment_hash_mismatch")
        if decoded.get("collective_signal_status") != "ATTACHED":
            raise ValueError("prepared_boundary_attachment_required")
        protected_valid, protected_failures = validate_boundary_protection(
            decoded
        )
        if not protected_valid:
            raise ValueError(
                "prepared_boundary_protection_invalid:"
                + ",".join(protected_failures)
            )
        return decoded


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


def _attachment_halt(state: Dict[str, Any]) -> Dict[str, Any]:
    state["decision"] = "DENY"
    state["execution_result"] = "HALT"
    state["execution_verified"] = False
    state["execution_reason"] = "collective_attachment_denied"
    state["pipeline_mode"] = "MODE_3_SINGLE_CONSTRAINED"
    state["convergence_hash"] = state.get("state_hash")
    return _finalize_pipeline(state)


def prepare_pipeline_boundary(
    request: Mapping[str, Any],
    pre_context_signals: Mapping[str, Any] | None = None,
    *,
    validation_logical_time: int | None = None,
    replay_registry: EIEReplayRegistry | None = None,
) -> PreparedPipelineBoundary | Dict[str, Any]:
    ingress = run_hard_ingress(
        request=deepcopy(dict(request)) if isinstance(request, Mapping) else request,
        pre_context_signals=(
            deepcopy(dict(pre_context_signals))
            if isinstance(pre_context_signals, Mapping)
            else pre_context_signals
        ),
        validation_logical_time=validation_logical_time,
        replay_registry=replay_registry,
    )
    if not ingress.accepted or ingress.admission is None:
        denial = ingress.evidence()
        denial["hard_entry_gate"] = {
            "accepted": False,
            "failures": denial.get("failures", []),
            "denial_evidence_digest": denial.get("denial_evidence_digest"),
        }
        denial["integration_stage_order"] = ["hard_ingress"]
        return denial

    admission = ingress.admission
    state = build_state(admission)
    state = _mark_stage(state, "hard_ingress")
    state = append_hash_entry(
        state, stage="hard_ingress", payload=state["hard_entry_gate"]
    )
    state = _mark_stage(state, "state_construction")
    state.setdefault("audit_trace", []).append({
        "stage": "state_construction",
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "state_construction_hash": state.get("state_construction_hash"),
    })
    state = append_hash_entry(
        state,
        stage="state_construction",
        payload={
            "request_fingerprint": state.get("request_fingerprint"),
            "state_version": state.get("state_version"),
            "state_schema_version": state.get("state_schema_version"),
            "eie_digest": state.get("eie_hash"),
            "state_construction_hash": state.get("state_construction_hash"),
        },
    )
    pre_attachment_state_hash = str(state["state_hash"])
    state = attach_collective_signals(
        state,
        admission.collective_signals(),
        validation_logical_time=admission.validation_logical_time,
    )
    state = _mark_stage(state, "collective_attach")
    if state.get("collective_signal_status") != "ATTACHED":
        return _attachment_halt(state)
    state_json = canonical_dumps(state)
    state_digest = generate_digest(state)
    construction_hash = str(state["state_construction_hash"])
    attachment_hash = str(
        state["collective_attachment"]["attachment_hash"]
    )
    stub = PreparedPipelineBoundary(
        schema_version="desktop-v1.prepared-pipeline-boundary.v1",
        state_json=state_json,
        state_digest=state_digest,
        state_construction_hash=construction_hash,
        pre_attachment_state_hash=pre_attachment_state_hash,
        collective_attachment_hash=attachment_hash,
        admission_digest=admission.admission_digest,
        seal_digest="",
    )
    prepared = PreparedPipelineBoundary(
        **{
            **stub.__dict__,
            "seal_digest": generate_digest(stub._seal_payload()),
        }
    )
    prepared.materialize()
    return prepared


def _run_admitted_pipeline(
    prepared: PreparedPipelineBoundary,
) -> Dict[str, Any]:
    if not isinstance(prepared, PreparedPipelineBoundary):
        raise TypeError("prepared_pipeline_boundary_required")
    state = prepared.materialize()
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
    if (
        state.get("governance_result") == "ALLOW"
        and state.get("grc_result") == "PASS"
    ):
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
    protected_valid, protected_failures = validate_boundary_protection(state)
    if not protected_valid:
        state["decision"] = "DENY"
        state["execution_result"] = "HALT"
        state["execution_verified"] = False
        state.setdefault("token_verification_failures", []).extend(
            protected_failures
        )
    return _finalize_pipeline(state)


def run_pipeline(
    request: Mapping[str, Any],
    pre_context_signals: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    prepared = prepare_pipeline_boundary(request, pre_context_signals)
    if isinstance(prepared, dict):
        return prepared
    return _run_admitted_pipeline(prepared)
