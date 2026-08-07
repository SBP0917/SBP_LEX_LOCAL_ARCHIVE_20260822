from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.divergence_registry import DivergenceRegistry
from sbp_lex.pipeline.runner import (
    _run_admitted_pipeline,
    prepare_pipeline_boundary,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.convergence import (
    ROOT_PT_PARITY_FIELDS,
    build_pipeline_convergence_proof,
)


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
        return pipeline_a

    pipeline_b = _run_admitted_pipeline(prepared)
    proof = build_pipeline_convergence_proof(pipeline_a=pipeline_a, pipeline_b=pipeline_b, mode=mode)
    pipeline_a["pipeline_convergence"] = proof
    pipeline_a["pipeline_b_summary"] = proof.get("pipeline_b")
    pipeline_a["pipeline_root_pt_parity"] = _root_pt_parity_from_proof(
        proof
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
        pipeline_a["decision"] = "ESCALATE"
        pipeline_a["execution_result"] = "HALT"
        pipeline_a["execution_verified"] = False
    return pipeline_a
