from __future__ import annotations

from typing import Any, Iterable, Mapping

from sbp_lex.phase19a.fixtures import PHASE19A_FAILURE_MODE_CASES


def build_detached_evidence_summary(
    *,
    translator_outcomes: Iterable[Mapping[str, Any]] = (),
    fixture_cases: Iterable[str] = PHASE19A_FAILURE_MODE_CASES,
) -> dict[str, Any]:
    cases = tuple(fixture_cases)
    outcomes = [dict(item) for item in translator_outcomes]
    accepted = sum(1 for item in outcomes if item.get("accepted") is True)
    rejected = sum(1 for item in outcomes if item.get("accepted") is False)
    return {
        "summary_type": "PHASE19A_DETACHED_EVIDENCE_SUMMARY",
        "runtime_attached": False,
        "publication_active": False,
        "network_publication_active": False,
        "blockchain_publication_active": False,
        "hosted_runtime_active": False,
        "runtime_authority": "NONE",
        "decision_authority": "NONE",
        "execution_authority": "NONE",
        "pipeline_mutation_allowed": False,
        "audit_mutation_allowed": False,
        "token_mutation_allowed": False,
        "hash_chain_mutation_allowed": False,
        "support_layers": {
            "oda_readable": True,
            "pvpl_readable": True,
            "sim_readable": True,
            "support_only": True,
        },
        "failure_mode_count": len(cases),
        "failure_modes": list(cases),
        "translator_outcome_count": len(outcomes),
        "translator_accepted_count": accepted,
        "translator_rejected_count": rejected,
        "translator_outcomes": outcomes,
        "boundary": {
            "desktop_v1_only": True,
            "local_private": True,
            "node_surface_active": False,
            "coordination_quorum_active": False,
            "distributed_governance_surface_active": False,
            "domain_wrap_order": "Governance -> GRC -> Domain Wrap -> Aurion -> Execution Gate -> Audit",
        },
    }
