from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.collective.context_interface import prepare_pre_context_signals
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.security.pqc import generate_digest

REPLAY_COMPARISON_FIELDS = [
    "request_fingerprint",
    "state_hash",
    "audit_hash",
    "pipeline_mode",
    "authority_first_result",
    "procedural_truth_result",
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
    return {**replay_payload, "replay_hash": generate_digest(replay_payload)}


def build_replay_summary(state: Mapping[str, Any]) -> Dict[str, Any]:
    convergence = state.get("pipeline_convergence", {})
    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash"),
        "audit_hash": state.get("audit_hash"),
        "pipeline_mode": state.get("pipeline_mode"),
        "authority_first_result": state.get("authority_first_result"),
        "procedural_truth_result": state.get("procedural_truth_result"),
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
