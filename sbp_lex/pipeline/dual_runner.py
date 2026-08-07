from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.divergence_registry import DivergenceRegistry
from sbp_lex.pipeline.runner import (
    _run_admitted_pipeline,
    prepare_pipeline_boundary,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.convergence import build_pipeline_convergence_proof


def run_dual_pipeline(request: Mapping[str, Any], pre_context_signals: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    prepared = prepare_pipeline_boundary(
        deepcopy(dict(request)) if isinstance(request, Mapping) else request,
        deepcopy(dict(pre_context_signals)) if pre_context_signals else None,
    )
    if isinstance(prepared, dict):
        return prepared
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
        return pipeline_a

    pipeline_b = _run_admitted_pipeline(prepared)
    proof = build_pipeline_convergence_proof(pipeline_a=pipeline_a, pipeline_b=pipeline_b, mode=mode)
    pipeline_a["pipeline_convergence"] = proof
    pipeline_a["pipeline_b_summary"] = proof.get("pipeline_b")
    if not proof.get("matched") or not initial_parity["exact_parity_result"]:
        registry = DivergenceRegistry()
        pipeline_a["divergence_record"] = registry.register_parity_divergence(
            stage="dual_pipeline_convergence",
            expected=proof.get("pipeline_a"),
            actual=proof.get("pipeline_b"),
            request_fingerprint=pipeline_a.get("request_fingerprint"),
            severity="HIGH",
        )
        pipeline_a["decision"] = "ESCALATE"
        pipeline_a["execution_result"] = "HALT"
        pipeline_a["execution_verified"] = False
    return pipeline_a
