from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.collective.context_interface import prepare_pre_context_signals
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

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
    "procedural_truth_result",
    "procedural_truth_outcome",
    "pt_evidence_envelope_digest",
    "pt_bound_metadata",
    "classification_result",
    "licensing_result",
    "governance_result",
    "domain_result",
    "aurion15_result",
    "decision",
    "execution_result",
    "execution_verified",
    "convergence_hash",
    "convergence_matched",
    "token_failures",
    "audit_finalisation",
    "controlled_outcome_hash",
    "final_outcome",
]


def run_replay_check(*, request: Mapping[str, Any], pre_context_signals: Mapping[str, Any] | None = None, replay_count: int = 2) -> Dict[str, Any]:
    replay_count = max(2, int(replay_count))
    request_copy = deepcopy(dict(request))
    stable_signals = deepcopy(dict(pre_context_signals)) if pre_context_signals else prepare_pre_context_signals(request_copy)
    runs = [run_dual_pipeline(deepcopy(request_copy), deepcopy(stable_signals)) for _ in range(replay_count)]
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
        "procedural_truth_result": state.get("procedural_truth_result"),
        "procedural_truth_outcome": state.get("procedural_truth_outcome"),
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
        "classification_result": state.get("classification_result"),
        "licensing_result": state.get("licensing_result"),
        "governance_result": state.get("governance_result"),
        "domain_result": state.get("domain_result"),
        "aurion15_result": state.get("aurion15_result"),
        "decision": state.get("decision"),
        "execution_result": state.get("execution_result"),
        "execution_verified": state.get("execution_verified"),
        "convergence_hash": convergence.get("convergence_hash"),
        "convergence_matched": convergence.get("matched"),
        "token_failures": state.get("token_verification_failures", []),
        "audit_finalisation": state.get("audit_finalisation", {}),
        "controlled_outcome_hash": state.get("controlled_outcome", {}).get("outcome_hash"),
        "final_outcome": state.get("final_outcome", {}),
    }
