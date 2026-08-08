from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.audit_finalisation import build_audit_record, finalise_audit
from sbp_lex.audit.divergence_registry import DivergenceRegistry
from sbp_lex.execution.controlled_outcome import (
    apply_terminal_control_state,
    build_controlled_outcome,
    finalise_outcome,
    verify_controlled_outcome,
)
from sbp_lex.execution.terminal_assurance import build_terminal_state_seal
from sbp_lex.pipeline.runner import (
    PreparedPipelineBoundary,
    _run_admitted_pipeline,
    prepare_pipeline_boundary,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.runtime.traversal_receipt import (
    NON_OPERATIONAL_VALIDATION,
    OPERATIONAL_TRAVERSAL,
)
from sbp_lex.shared.convergence import (
    DOMAIN_AURION_PARITY_FIELDS,
    GOVERNED_STAGE_PARITY_FIELDS,
    ROOT_PT_PARITY_FIELDS,
    build_pipeline_convergence_proof,
)
from sbp_lex.shared.hash_chain import rebuild_state_hash


_TERMINAL_GATE_SUCCESS_TOKENS = frozenset(
    {
        "execution_boundary",
        "token_bundle",
        "master_convergence",
        "execution_attestation",
    }
)


def _remove_terminal_gate_success_material(
    state: Dict[str, Any],
) -> Dict[str, Any]:
    """Remove live Gate-success surfaces while retaining labelled history."""

    captured: Dict[str, Any] = {}
    tokens = state.get("tokens")
    if isinstance(tokens, Mapping):
        captured["tokens"] = {
            name: deepcopy(token)
            for name, token in tokens.items()
            if name in _TERMINAL_GATE_SUCCESS_TOKENS
        }
        state["tokens"] = {
            name: deepcopy(token)
            for name, token in tokens.items()
            if name not in _TERMINAL_GATE_SUCCESS_TOKENS
        }
    trace = state.get("token_trace")
    if isinstance(trace, list):
        captured["token_trace"] = [
            deepcopy(entry)
            for entry in trace
            if isinstance(entry, Mapping)
            and entry.get("name") in _TERMINAL_GATE_SUCCESS_TOKENS
        ]
        state["token_trace"] = [
            deepcopy(entry)
            for entry in trace
            if not isinstance(entry, Mapping)
            or entry.get("name") not in _TERMINAL_GATE_SUCCESS_TOKENS
        ]
    for field in (
        "master_token",
        "execution_attestation",
        "execution_timestamp",
        "execution_convergence",
        "convergence_hash",
    ):
        if field in state:
            captured[field] = deepcopy(state.pop(field))
    return captured


def _conserve_terminal_divergence(
    state: Dict[str, Any],
    *,
    initial_parity_exact: bool,
) -> Dict[str, Any]:
    """Create a signed, non-authoritative final audit for dual divergence."""

    working_state = deepcopy(state)
    convergence = working_state.get("pipeline_convergence", {})
    convergence = convergence if isinstance(convergence, Mapping) else {}
    divergence = working_state.get("divergence_record", {})
    divergence = divergence if isinstance(divergence, Mapping) else {}

    pre_convergence_evidence = {
        "authority_role": "historical_evidence_only_non_authoritative",
        "audit_record": deepcopy(working_state.pop("audit_record", {})),
        "audit_hash": working_state.pop("audit_hash", ""),
        "audit_finalisation": deepcopy(
            working_state.pop("audit_finalisation", {})
        ),
        "controlled_outcome": deepcopy(
            working_state.pop("controlled_outcome", {})
        ),
        "final_outcome": deepcopy(working_state.pop("final_outcome", {})),
        "operational_state": working_state.get("operational_state"),
        "persistent_inoperability": working_state.get(
            "persistent_inoperability"
        ),
        "terminal_gate_success_material": (
            _remove_terminal_gate_success_material(working_state)
        ),
    }
    prior_audit = pre_convergence_evidence["audit_record"]
    prior_outcome = pre_convergence_evidence["controlled_outcome"]
    prior_outcome_hash = (
        prior_outcome.get("outcome_hash")
        if isinstance(prior_outcome, Mapping)
        else None
    )
    failure_reasons = []
    if convergence.get("matched") is not True:
        failure_reasons.append("dual_pipeline_result_divergence")
    if not initial_parity_exact:
        failure_reasons.append("dual_pipeline_initial_parity_divergence")
    if not failure_reasons:
        failure_reasons.append("dual_pipeline_convergence_invalid")

    working_state["decision"] = "ESCALATE"
    working_state["execution_result"] = "HALT"
    working_state["execution_verified"] = False
    working_state["execution_reason"] = ",".join(failure_reasons)
    working_state["token_stack_valid"] = False
    token_failures = list(
        working_state.get("token_verification_failures", [])
    )
    token_failures.extend(failure_reasons)
    working_state["token_verification_failures"] = list(
        dict.fromkeys(str(item) for item in token_failures if str(item))
    )
    working_state["convergence_hash"] = convergence.get(
        "convergence_hash", generate_digest(dict(convergence))
    )
    working_state["effect_phase"] = "NOT_AUTHORISED"
    working_state["effect_confirmed_success"] = False
    working_state["effect_authority_eligible"] = False
    working_state["pre_convergence_terminal_evidence"] = (
        pre_convergence_evidence
    )
    working_state = apply_terminal_control_state(working_state)
    working_state["state_hash"] = rebuild_state_hash(working_state)

    terminal_integration_evidence = {
        "evidence_version": "PASS7_TERMINAL_CONVERGENCE_AUDIT_V1",
        "stage": "dual_pipeline_convergence",
        "authority_role": "evidence_only_non_authoritative",
        "failure_reasons": failure_reasons,
        "pipeline_convergence_hash": convergence.get("convergence_hash"),
        "pipeline_convergence_digest": generate_digest(dict(convergence)),
        "pipeline_convergence_matched": convergence.get("matched"),
        "pipeline_convergence_verified": convergence.get("verified"),
        "initial_parity_exact": initial_parity_exact,
        "divergence_hash": divergence.get("divergence_hash"),
        "divergence_digest": generate_digest(dict(divergence)),
        "pre_convergence_audit_hash": (
            prior_audit.get("audit_hash")
            if isinstance(prior_audit, Mapping)
            else None
        ),
        "pre_convergence_controlled_outcome_hash": prior_outcome_hash,
        "pre_convergence_terminal_evidence_digest": generate_digest(
            pre_convergence_evidence
        ),
        "effect_authority_eligible": False,
    }
    terminal_audit = build_audit_record(
        {
            "request_fingerprint": working_state.get(
                "request_fingerprint"
            ),
            "state_hash": working_state.get("state_hash"),
            "decision": "ESCALATE",
            "execution_result": "HALT",
            "execution_verified": False,
            "convergence_hash": working_state.get("convergence_hash"),
            "audit_chain": working_state.get("hash_chain", []),
            "pipeline_mode": working_state.get("pipeline_mode"),
            "integration_evidence": terminal_integration_evidence,
        }
    )
    terminal_finalisation = finalise_audit(terminal_audit)
    if (
        terminal_audit.get("valid") is not True
        or terminal_finalisation.get("audit_complete") is not True
    ):
        raise RuntimeError("terminal_convergence_audit_failed")
    working_state["audit_record"] = terminal_audit
    working_state["audit_hash"] = terminal_audit["audit_hash"]
    working_state["audit_finalisation"] = terminal_finalisation
    working_state["terminal_convergence_audit"] = deepcopy(terminal_audit)
    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "terminal_convergence_audit",
            "audit_hash": terminal_audit["audit_hash"],
            "audit_complete": True,
            "decision": "ESCALATE",
            "execution_result": "HALT",
        }
    )
    working_state["state_hash"] = rebuild_state_hash(working_state)
    controlled_outcome = build_controlled_outcome(working_state)
    if not verify_controlled_outcome(controlled_outcome):
        raise RuntimeError("terminal_convergence_controlled_outcome_failed")
    working_state["controlled_outcome"] = controlled_outcome
    working_state["final_outcome"] = finalise_outcome(controlled_outcome)
    return working_state


def _root_pt_parity_from_proof(proof: Mapping[str, Any]) -> Dict[str, Any]:
    pipeline_a = proof.get("pipeline_a", {})
    pipeline_b = proof.get("pipeline_b")
    if not isinstance(pipeline_a, Mapping):
        pipeline_a = {}
    if not isinstance(pipeline_b, Mapping):
        return {
            "applicable": False,
            "reason": "single_constrained_pipeline_mode",
            "field_matches": {},
            "exact_parity_result": None,
            "near_match_reconciliation_used": False,
        }
    matches = {
        field: pipeline_a.get(field) == pipeline_b.get(field)
        for field in ROOT_PT_PARITY_FIELDS
    }
    return {
        "applicable": True,
        "pipeline_a_root_digest": pipeline_a.get("root_evidence_digest"),
        "pipeline_b_root_digest": pipeline_b.get("root_evidence_digest"),
        "pipeline_a_pt_digest": pipeline_a.get("pt_evidence_digest"),
        "pipeline_b_pt_digest": pipeline_b.get("pt_evidence_digest"),
        "field_matches": matches,
        "root_parity": all(
            matches.get(field, False)
            for field in ("root_result", "root_reason", "root_evidence_digest")
        ),
        "pt_parity": all(
            matches.get(field, False)
            for field in (
                "procedural_truth_result",
                "procedural_truth_outcome",
                "pt_evidence_digest",
                "qualifying_source_count",
                "evidentiary_sufficiency_result",
            )
        ),
        "tier_parity": matches.get("computed_tier", False),
        "corroboration_parity": all(
            matches.get(field, False)
            for field in (
                "corroboration_required",
                "corroboration_observed",
            )
        ),
        "exact_parity_result": all(matches.values()),
        "near_match_reconciliation_used": False,
    }


def _governed_stage_parity_from_proof(
    proof: Mapping[str, Any]
) -> Dict[str, Any]:
    pipeline_a = proof.get("pipeline_a", {})
    pipeline_b = proof.get("pipeline_b")
    if not isinstance(pipeline_a, Mapping):
        pipeline_a = {}
    if not isinstance(pipeline_b, Mapping):
        return {
            "applicable": False,
            "reason": "single_constrained_pipeline_mode",
            "comparison_fields": GOVERNED_STAGE_PARITY_FIELDS,
            "field_matches": {},
            "exact_parity_result": None,
            "near_match_reconciliation_used": False,
        }
    matches = {
        field: pipeline_a.get(field) == pipeline_b.get(field)
        for field in GOVERNED_STAGE_PARITY_FIELDS
    }
    return {
        "applicable": True,
        "comparison_fields": GOVERNED_STAGE_PARITY_FIELDS,
        "field_matches": matches,
        "exact_parity_result": all(matches.values()),
        "near_match_reconciliation_used": False,
    }


def _domain_aurion_parity_from_proof(
    proof: Mapping[str, Any]
) -> Dict[str, Any]:
    pipeline_a = proof.get("pipeline_a", {})
    pipeline_b = proof.get("pipeline_b")
    if not isinstance(pipeline_a, Mapping):
        pipeline_a = {}
    if not isinstance(pipeline_b, Mapping):
        return {
            "applicable": False,
            "reason": "single_constrained_pipeline_mode",
            "comparison_fields": DOMAIN_AURION_PARITY_FIELDS,
            "field_matches": {},
            "exact_parity_result": None,
            "near_match_reconciliation_used": False,
        }
    matches = {
        field: pipeline_a.get(field) == pipeline_b.get(field)
        for field in DOMAIN_AURION_PARITY_FIELDS
    }
    return {
        "applicable": True,
        "comparison_fields": DOMAIN_AURION_PARITY_FIELDS,
        "field_matches": matches,
        "domain_evidence_parity": all(
            matches.get(field, False)
            for field in (
                "domain_result",
                "domain_reason",
                "domain_state_digest",
                "domain_live_state_digest",
                "domain_evidence_digest",
            )
        ),
        "aurion_pathway_parity": all(
            matches.get(field, False)
            for field in (
                "aurion15_result",
                "aurion_reason",
                "generated_candidate_set_digest",
                "ordered_candidate_set_digest",
                "selected_candidate_digest",
                "selected_pathway_digest",
            )
        ),
        "handoff_parity": all(
            matches.get(field, False)
            for field in (
                "domain_aurion_constraint_digest",
                "execution_convergence_handoff_digest",
                "execution_convergence_handoff_valid",
            )
        ),
        "exact_parity_result": all(matches.values()),
        "near_match_reconciliation_used": False,
    }


def _run_dual_prepared_pipeline(
    prepared: PreparedPipelineBoundary,
) -> Dict[str, Any]:
    if not isinstance(prepared, PreparedPipelineBoundary):
        raise TypeError("prepared_pipeline_boundary_required")
    initial_a = prepared.materialize()
    initial_b = prepared.materialize()
    parity_fields = {
        "canonical_eie": (
            initial_a.get("eie"), initial_b.get("eie")
        ),
        "validated_substrate_references": (
            initial_a.get("verified_substrate_references"),
            initial_b.get("verified_substrate_references"),
        ),
        "initial_canonical_state": (
            initial_a.get("state_construction_hash"),
            initial_b.get("state_construction_hash"),
        ),
        "collective_signal_package": (
            initial_a.get("collective_signals"),
            initial_b.get("collective_signals"),
        ),
        "state_hash_basis": (
            initial_a.get("state_hash"), initial_b.get("state_hash")
        ),
        "authority_material": (
            {
                "resolved_authority": initial_a.get("resolved_authority"),
                "jurisdiction": initial_a.get("jurisdiction"),
                "root_trust_material": initial_a.get(
                    "collective_attachment", {}
                ).get("root_trust_material", {}),
            },
            {
                "resolved_authority": initial_b.get("resolved_authority"),
                "jurisdiction": initial_b.get("jurisdiction"),
                "root_trust_material": initial_b.get(
                    "collective_attachment", {}
                ).get("root_trust_material", {}),
            },
        ),
        "source_evidence_set": (
            initial_a.get("pt_evidence_envelope", {}).get(
                "source_records", []
            ),
            initial_b.get("pt_evidence_envelope", {}).get(
                "source_records", []
            ),
        ),
        "safety_factors": (
            {
                key: initial_a.get("safety_profile", {}).get(key)
                for key in (
                    "human_safety",
                    "irreversibility",
                    "cascading_impact",
                    "financial_operational",
                )
            },
            {
                key: initial_b.get("safety_profile", {}).get(key)
                for key in (
                    "human_safety",
                    "irreversibility",
                    "cascading_impact",
                    "financial_operational",
                )
            },
        ),
        "computed_initial_tier": (
            initial_a.get("pt_evidence_envelope", {}).get(
                "threshold_tier"
            ),
            initial_b.get("pt_evidence_envelope", {}).get(
                "threshold_tier"
            ),
        ),
        "initial_corroboration_requirement": (
            initial_a.get("pt_evidence_envelope", {}).get(
                "threshold_requirement"
            ),
            initial_b.get("pt_evidence_envelope", {}).get(
                "threshold_requirement"
            ),
        ),
    }
    exact_matches = {
        field: pair[0] == pair[1] for field, pair in parity_fields.items()
    }
    initial_parity = {
        "schema_version": "desktop-v1.pipeline-initial-parity.v1",
        "pipeline_a_initial_hash": generate_digest(initial_a),
        "pipeline_b_initial_hash": generate_digest(initial_b),
        "canonical_eie_digest": initial_a.get("eie_hash"),
        "validated_substrate_references_digest": generate_digest(
            initial_a.get("verified_substrate_references", {})
        ),
        "initial_state_hash": prepared.state_construction_hash,
        "collective_signal_package_digest": initial_a.get(
            "collective_signals", {}
        ).get("digest"),
        "collective_attachment_hash": prepared.collective_attachment_hash,
        "state_hash_basis": initial_a.get("state_hash"),
        "authority_material_digest": generate_digest(
            parity_fields["authority_material"][0]
        ),
        "source_evidence_set_digest": generate_digest(
            parity_fields["source_evidence_set"][0]
        ),
        "safety_factors": parity_fields["safety_factors"][0],
        "computed_initial_tier": parity_fields[
            "computed_initial_tier"
        ][0],
        "initial_corroboration_requirement": parity_fields[
            "initial_corroboration_requirement"
        ][0],
        "field_matches": exact_matches,
        "exact_parity_result": all(exact_matches.values()),
        "near_match_reconciliation_used": False,
    }
    pipeline_a = _run_admitted_pipeline(prepared)
    pipeline_a["pipeline_initial_parity"] = initial_parity
    mode = pipeline_a.get("pipeline_mode", "MODE_3_SINGLE_CONSTRAINED")
    if mode == "MODE_3_SINGLE_CONSTRAINED":
        proof = build_pipeline_convergence_proof(pipeline_a=pipeline_a, pipeline_b=None, mode=mode)
        pipeline_a["pipeline_convergence"] = proof
        pipeline_a["pipeline_root_pt_parity"] = (
            _root_pt_parity_from_proof(proof)
        )
        pipeline_a["pipeline_governed_stage_parity"] = (
            _governed_stage_parity_from_proof(proof)
        )
        pipeline_a["pipeline_domain_aurion_parity"] = (
            _domain_aurion_parity_from_proof(proof)
        )
        return _seal_terminal_convergence(pipeline_a)

    pipeline_b = _run_admitted_pipeline(prepared)
    proof = build_pipeline_convergence_proof(pipeline_a=pipeline_a, pipeline_b=pipeline_b, mode=mode)
    pipeline_a["pipeline_convergence"] = proof
    pipeline_a["pipeline_b_summary"] = proof.get("pipeline_b")
    pipeline_a["pipeline_root_pt_parity"] = _root_pt_parity_from_proof(
        proof
    )
    pipeline_a["pipeline_governed_stage_parity"] = (
        _governed_stage_parity_from_proof(proof)
    )
    pipeline_a["pipeline_domain_aurion_parity"] = (
        _domain_aurion_parity_from_proof(proof)
    )
    if not proof.get("matched") or not initial_parity["exact_parity_result"]:
        registry = DivergenceRegistry()
        pipeline_a["divergence_record"] = registry.register_parity_divergence(
            stage="dual_pipeline_convergence",
            expected=proof.get("pipeline_a"),
            actual=proof.get("pipeline_b"),
            request_fingerprint=pipeline_a.get("request_fingerprint"),
            severity="HIGH",
        )
        pipeline_a = _conserve_terminal_divergence(
            pipeline_a,
            initial_parity_exact=bool(
                initial_parity["exact_parity_result"]
            ),
        )
    return _seal_terminal_convergence(pipeline_a)


def _seal_terminal_convergence(state: Dict[str, Any]) -> Dict[str, Any]:
    receipt = state.get("runtime_traversal_receipt", {})
    purpose = (
        receipt.get("payload", {}).get("purpose")
        if isinstance(receipt, Mapping)
        and isinstance(receipt.get("payload"), Mapping)
        else None
    )
    convergence = state.get("pipeline_convergence", {})
    converged = (
        isinstance(convergence, Mapping)
        and convergence.get("matched") is True
        and convergence.get("verified") is True
    )
    authorised = (
        state.get("decision") == "ALLOW"
        and state.get("execution_result") == "EXECUTE"
        and state.get("execution_verified") is True
        and converged
    )
    operationally_authorised = bool(
        authorised and purpose == OPERATIONAL_TRAVERSAL
    )
    state["effect_phase"] = (
        "AUTHORISED_TO_ATTEMPT"
        if operationally_authorised
        else "NOT_AUTHORISED"
    )
    state["effect_confirmed_success"] = False
    state["effect_authority_eligible"] = operationally_authorised
    state["terminal_state_seal"] = build_terminal_state_seal(
        state,
        runtime_receipt=receipt,
        expected_receipt_purpose=str(purpose),
    )
    return state


def run_dual_pipeline(
    request: Mapping[str, Any],
    pre_context_signals: Mapping[str, Any] | None = None,
    *,
    runtime_traversal_receipt: Mapping[str, Any] | None = None,
    runtime_receipt_purpose: str = NON_OPERATIONAL_VALIDATION,
) -> Dict[str, Any]:
    prepared = prepare_pipeline_boundary(
        deepcopy(dict(request)) if isinstance(request, Mapping) else request,
        deepcopy(dict(pre_context_signals)) if pre_context_signals else None,
        runtime_traversal_receipt=runtime_traversal_receipt,
        runtime_receipt_purpose=runtime_receipt_purpose,
    )
    if isinstance(prepared, dict):
        return prepared
    return _run_dual_prepared_pipeline(prepared)
