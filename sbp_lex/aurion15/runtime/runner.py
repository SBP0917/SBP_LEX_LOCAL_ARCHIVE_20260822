from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.aurion15.candidate.generator import generate_candidates
from sbp_lex.aurion15.candidate.queue import CandidateQueue
from sbp_lex.aurion15.candidate.ranker import rank_candidates
from sbp_lex.aurion15.runtime.constraint_validator import validate_candidate_constraints
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry

MAX_CANDIDATE_ATTEMPTS = 5


def run_aurion_runtime(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    if working_state.get("domain_result") != "pass":
        working_state["aurion15_result"] = "fail"
        working_state["decision"] = working_state.get("decision", "DENY")
        working_state["execution_result"] = "HALT"
        return append_hash_entry(working_state, stage="aurion_runtime", payload={"aurion15_result": "fail", "reason": "domain_not_passed"})

    queue = CandidateQueue(rank_candidates(working_state, generate_candidates(working_state)))
    attempts = 0
    selected_candidate = None
    rejected_candidates: list[Dict[str, Any]] = []

    while queue.has_next() and attempts < MAX_CANDIDATE_ATTEMPTS:
        candidate = queue.next()
        attempts += 1
        if candidate is None:
            break
        validation = validate_candidate_constraints(working_state, candidate)
        if validation.get("valid"):
            selected_candidate = candidate
            break
        rejected = deepcopy(candidate)
        rejected["rejection_reasons"] = validation.get("failures", [])
        rejected_candidates.append(rejected)

    working_state["candidate_attempt_count"] = attempts
    if selected_candidate is None:
        working_state["aurion15_result"] = "fail"
        working_state["current_candidate"] = {}
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        reason = "no_valid_candidate_pathway"
    else:
        working_state["aurion15_result"] = "pass"
        working_state["current_candidate"] = selected_candidate
        reason = "aurion_pathway_resolved"
        working_state = issue_token(
            working_state,
            name="aurion",
            issued_at_stage="aurion_runtime",
            payload={"aurion15_result": "pass", "candidate_id": selected_candidate.get("candidate_id"), "candidate_attempt_count": attempts},
        )

    working_state.setdefault("governance_feedback", {})["aurion"] = {
        "result": working_state["aurion15_result"],
        "reason": reason,
        "candidate_attempt_count": attempts,
        "current_candidate": selected_candidate or {},
        "rejected_candidates": rejected_candidates,
    }
    working_state.setdefault("audit_trace", []).append({"stage": "aurion_runtime", "result": working_state["aurion15_result"], "reason": reason, "candidate_attempt_count": attempts})
    return append_hash_entry(
        working_state,
        stage="aurion_runtime",
        payload={"aurion15_result": working_state["aurion15_result"], "reason": reason, "candidate_attempt_count": attempts, "current_candidate": selected_candidate or {}},
    )
