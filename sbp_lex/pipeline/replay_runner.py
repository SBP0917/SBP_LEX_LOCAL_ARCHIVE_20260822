from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.collective.context_interface import prepare_pre_context_signals
from sbp_lex.pipeline.dual_runner import _run_dual_prepared_pipeline
from sbp_lex.pipeline.runner import prepare_pipeline_boundary
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.convergence import (
    DOMAIN_AURION_PARITY_FIELDS,
    GOVERNED_STAGE_PARITY_FIELDS,
    domain_aurion_summary,
    governed_stage_summary,
)

REPLAY_COMPARISON_FIELDS = [
    "request_fingerprint",
    "eie_digest",
    "state_construction_hash",
    "collective_attachment_hash",
    "pipeline_a_initial_hash",
    "pipeline_b_initial_hash",
    "pipeline_initial_exact_parity",
    "state_hash",
    "audit_hash",
    "pipeline_mode",
    "authority_first_result",
    "authority_first_reason",
    "root_evidence_digest",
    "root_stage_results_digest",
    "procedural_truth_result",
    "procedural_truth_outcome",
    "procedural_truth_reason",
    "pt_evidence_digest",
    "qualifying_source_count",
    "evidentiary_sufficiency_result",
    "computed_tier",
    "corroboration_required",
    "corroboration_observed",
    "pt_evidence_envelope_digest",
    "pt_bound_metadata",
    *GOVERNED_STAGE_PARITY_FIELDS,
    *DOMAIN_AURION_PARITY_FIELDS,
    "decision",
    "execution_result",
    "execution_verified",
    "convergence_hash",
    "convergence_matched",
    "root_pt_parity",
    "governed_stage_parity",
    "domain_aurion_parity",
    "token_failures",
    "audit_finalisation",
    "controlled_outcome_hash",
    "final_outcome",
]


def run_replay_check(*, request: Mapping[str, Any], pre_context_signals: Mapping[str, Any] | None = None, replay_count: int = 2) -> Dict[str, Any]:
    replay_count = max(2, int(replay_count))
    request_copy = deepcopy(dict(request))
    stable_signals = deepcopy(dict(pre_context_signals)) if pre_context_signals else prepare_pre_context_signals(request_copy)
    prepared = prepare_pipeline_boundary(
        deepcopy(request_copy), deepcopy(stable_signals)
    )
    runs = (
        [deepcopy(prepared) for _ in range(replay_count)]
        if isinstance(prepared, dict)
        else [
            _run_dual_prepared_pipeline(prepared)
            for _ in range(replay_count)
        ]
    )
    summaries = [build_replay_summary(run) for run in runs]
    reference = summaries[0]
    mismatches: list[Dict[str, Any]] = []

    for index, summary in enumerate(summaries[1:], start=1):
        for field in REPLAY_COMPARISON_FIELDS:
            if summary.get(field) != reference.get(field):
                mismatches.append({"run": index, "field": field, "expected": reference.get(field), "actual": summary.get(field)})

    replay_payload = {
        "replay_count": replay_count,
        "matched": len(mismatches) == 0,
        "comparison_fields": REPLAY_COMPARISON_FIELDS,
        "reference": reference,
        "runs": summaries,
        "mismatches": mismatches,
    }
    replay_hash = generate_digest(replay_payload)
    signature_payload = {**replay_payload, "replay_hash": replay_hash}
    return {**signature_payload, "replay_signature": sign_payload(signature_payload)}


def verify_replay_result(result: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if result.get("comparison_fields") != REPLAY_COMPARISON_FIELDS:
        failures.append("REPLAY_MISMATCH")
    payload = {
        key: deepcopy(value)
        for key, value in dict(result).items()
        if key not in {"replay_hash", "replay_signature"}
    }
    replay_hash = result.get("replay_hash")
    signature_payload = {**payload, "replay_hash": replay_hash}
    if replay_hash != generate_digest(payload):
        failures.append("REPLAY_MISMATCH")
    if not verify_signature(signature_payload, result.get("replay_signature", {})):
        failures.append("REPLAY_MISMATCH")
    runs = result.get("runs", [])
    reference = result.get("reference", {})
    if not isinstance(runs, list) or len(runs) < 2 or reference != runs[0]:
        failures.append("REPLAY_MISMATCH")
    else:
        mismatches: list[Dict[str, Any]] = []
        for index, summary in enumerate(runs[1:], start=1):
            for field in REPLAY_COMPARISON_FIELDS:
                if summary.get(field) != reference.get(field):
                    mismatches.append(
                        {
                            "run": index,
                            "field": field,
                            "expected": reference.get(field),
                            "actual": summary.get(field),
                        }
                    )
        if mismatches != result.get("mismatches") or result.get("matched") is not (not mismatches):
            failures.append("REPLAY_MISMATCH")
    return not failures, sorted(set(failures))


def build_replay_summary(state: Mapping[str, Any]) -> Dict[str, Any]:
    convergence = state.get("pipeline_convergence", {})
    envelope = state.get("pt_evidence_envelope", {})
    root_evidence = state.get("root_of_trust_evidence", {})
    root_payload = (
        root_evidence.get("payload", {})
        if isinstance(root_evidence, Mapping)
        else {}
    )
    root_payload = root_payload if isinstance(root_payload, Mapping) else {}
    pt_evidence = state.get("procedural_truth_evidence", {})
    pt_payload = (
        pt_evidence.get("payload", {})
        if isinstance(pt_evidence, Mapping)
        else {}
    )
    pt_payload = pt_payload if isinstance(pt_payload, Mapping) else {}
    certification = state.get("procedural_truth_certification", {})
    certification = (
        certification if isinstance(certification, Mapping) else {}
    )
    threshold_snapshot = state.get("governance_feedback", {}).get(
        "threshold_snapshot", {}
    )
    threshold_snapshot = (
        threshold_snapshot
        if isinstance(threshold_snapshot, Mapping)
        else {}
    )

    def record_digest(record: object, *names: str) -> object:
        if not isinstance(record, Mapping):
            return None
        for name in names:
            if record.get(name) not in (None, ""):
                return record.get(name)
        return None

    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "state_construction_hash": state.get("state_construction_hash"),
        "collective_attachment_hash": state.get(
            "collective_attachment", {}
        ).get("attachment_hash"),
        "pipeline_a_initial_hash": state.get(
            "pipeline_initial_parity", {}
        ).get("pipeline_a_initial_hash"),
        "pipeline_b_initial_hash": state.get(
            "pipeline_initial_parity", {}
        ).get("pipeline_b_initial_hash"),
        "pipeline_initial_exact_parity": state.get(
            "pipeline_initial_parity", {}
        ).get("exact_parity_result"),
        "state_hash": state.get("state_hash"),
        "audit_hash": state.get("audit_hash"),
        "pipeline_mode": state.get("pipeline_mode"),
        "authority_first_result": state.get("authority_first_result"),
        "authority_first_reason": state.get("authority_first_reason"),
        "root_evidence_digest": record_digest(
            root_evidence, "root_evidence_digest", "evidence_digest"
        )
        or state.get("root_of_trust_evidence_anchor", {}).get(
            "anchor_digest"
        ),
        "root_stage_results_digest": generate_digest(
            root_payload.get(
                "stage_results",
                root_evidence.get(
                    "stage_results",
                    state.get("governance_feedback", {}).get(
                        "root_of_trust_stage_results", {}
                    ),
                )
                if isinstance(root_evidence, Mapping)
                else {},
            )
        ),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "procedural_truth_outcome": state.get("procedural_truth_outcome"),
        "procedural_truth_reason": state.get("procedural_truth_reason"),
        "pt_evidence_digest": record_digest(
            pt_evidence,
            "pt_evidence_digest",
            "procedural_truth_evidence_digest",
            "evidence_digest",
        ),
        "qualifying_source_count": pt_payload.get(
            "source_count_qualifying",
            pt_payload.get(
                "qualifying_source_count",
                envelope.get("qualifying_source_count"),
            ),
        ),
        "evidentiary_sufficiency_result": pt_payload.get(
            "evidentiary_sufficiency_result",
            certification.get("certification_status"),
        ),
        "computed_tier": pt_payload.get(
            "computed_tier",
            pt_payload.get(
                "tier",
                state.get("safety_profile", {}).get("computed_tier"),
            ),
        ),
        "corroboration_required": pt_payload.get(
            "corroboration_required", state.get("corroboration_required")
        ),
        "corroboration_observed": pt_payload.get(
            "corroboration_observed",
            threshold_snapshot.get(
                "qualified_evidence_count",
                envelope.get("qualifying_source_count"),
            ),
        ),
        "pt_evidence_envelope_digest": state.get("pt_evidence_envelope_digest"),
        "pt_bound_metadata": {
            "request_fingerprint": envelope.get("request_fingerprint"),
            "eie_hash": state.get("eie_hash"),
            "traversal_id": state.get("traversal_id"),
            "source_payload_hash": state.get("source_payload_hash"),
            "skg_digest": envelope.get("skg_digest"),
            "dtn_digest": envelope.get("dtn_digest"),
            "pre_context_digest": envelope.get("pre_context_digest"),
            "pt_evidence_envelope_digest": state.get("pt_evidence_envelope_digest"),
            "skg_enrichment_hash": envelope.get("skg_truth_foundation_metadata", {}).get("skg_enrichment_hash")
            if isinstance(envelope.get("skg_truth_foundation_metadata"), Mapping)
            else None,
            "dtn_enrichment_hash": envelope.get("dtn_contextual_verification_metadata", {}).get("dtn_enrichment_hash")
            if isinstance(envelope.get("dtn_contextual_verification_metadata"), Mapping)
            else None,
            "root_anchor_digest": state.get("root_of_trust_evidence_anchor", {}).get("anchor_digest"),
            "token_chain_reference": state.get("root_of_trust_evidence_anchor", {}).get("payload", {}).get("token_chain_reference"),
        },
        **governed_stage_summary(state),
        **domain_aurion_summary(state),
        "decision": state.get("decision"),
        "execution_result": state.get("execution_result"),
        "execution_verified": state.get("execution_verified"),
        "convergence_hash": convergence.get("convergence_hash"),
        "convergence_matched": convergence.get("matched"),
        "root_pt_parity": state.get("pipeline_root_pt_parity", {}),
        "governed_stage_parity": state.get(
            "pipeline_governed_stage_parity", {}
        ),
        "domain_aurion_parity": state.get(
            "pipeline_domain_aurion_parity", {}
        ),
        "token_failures": state.get("token_verification_failures", []),
        "audit_finalisation": state.get("audit_finalisation", {}),
        "controlled_outcome_hash": state.get("controlled_outcome", {}).get("outcome_hash"),
        "final_outcome": state.get("final_outcome", {}),
    }
