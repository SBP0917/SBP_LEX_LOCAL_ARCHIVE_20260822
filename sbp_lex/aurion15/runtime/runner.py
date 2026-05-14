from __future__ import annotations
        working_state["decision"] = working_state.get("decision", "DENY")
        working_state["execution_result"] = "HALT"
        return append_hash_entry(
            working_state,
            stage="aurion_runtime",
            payload={"aurion15_result": "fail", "reason": "domain_not_passed"},
        )

    candidates = generate_candidates(working_state)
    ranked_candidates = rank_candidates(working_state, candidates)
    queue = CandidateQueue(ranked_candidates)

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
            payload={
                "aurion15_result": "pass",
                "candidate_id": selected_candidate.get("candidate_id"),
                "candidate_attempt_count": attempts,
                "rejected_candidate_count": len(rejected_candidates),
            },
        )

    working_state.setdefault("governance_feedback", {})["aurion"] = {
        "result": working_state["aurion15_result"],
        "reason": reason,
        "candidate_attempt_count": attempts,
        "current_candidate": selected_candidate or {},
        "rejected_candidates": rejected_candidates,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "aurion_runtime",
            "result": working_state["aurion15_result"],
            "reason": reason,
            "candidate_attempt_count": attempts,
        }
    )

    return append_hash_entry(
        working_state,
        stage="aurion_runtime",
        payload={
            "aurion15_result": working_state["aurion15_result"],
            "reason": reason,
            "candidate_attempt_count": attempts,
            "current_candidate": selected_candidate or {},
            "rejected_candidate_count": len(rejected_candidates),
        },
      )
