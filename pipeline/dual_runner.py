from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.divergence_registry import DivergenceRegistry
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.shared.convergence import build_pipeline_convergence_proof


def run_dual_pipeline(request: Mapping[str, Any], pre_context_signals: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    pipeline_a = run_pipeline(deepcopy(dict(request)), deepcopy(dict(pre_context_signals)) if pre_context_signals else None)
    mode = pipeline_a.get("pipeline_mode", "MODE_3_SINGLE_CONSTRAINED")
    if mode == "MODE_3_SINGLE_CONSTRAINED":
        proof = build_pipeline_convergence_proof(pipeline_a=pipeline_a, pipeline_b=None, mode=mode)
        pipeline_a["pipeline_convergence"] = proof
        return pipeline_a

    pipeline_b = run_pipeline(deepcopy(dict(request)), deepcopy(dict(pre_context_signals)) if pre_context_signals else None)
    proof = build_pipeline_convergence_proof(pipeline_a=pipeline_a, pipeline_b=pipeline_b, mode=mode)
    pipeline_a["pipeline_convergence"] = proof
    pipeline_a["pipeline_b_summary"] = proof.get("pipeline_b")
    if not proof.get("matched"):
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
