from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.aurion15.candidate.generator import generate_candidates
from sbp_lex.aurion15.candidate.ranker import (
    candidate_rank_score,
    rank_candidates,
)
from sbp_lex.aurion15.runtime.constraint_validator import (
    validate_candidate_constraints,
)
from sbp_lex.security.authority_boundary import (
    validate_domain_handoff_to_aurion,
)
from sbp_lex.security.domain_aurion_evidence import (
    append_stage_finalisation,
    append_stage_history,
    build_stage_evidence,
    invalidate_from_stage,
    live_state_hash_valid,
    neutralize_denied_execution_state,
    stage_already_completed,
    stage_token_payload,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import rebuild_state_hash


MAX_CANDIDATE_ATTEMPTS = 5
CANONICAL_CANDIDATE_GENERATOR = generate_candidates


def _invalid_aurion_input_state() -> Dict[str, Any]:
    failure = "aurion_input_not_canonical"
    denied: Dict[str, Any] = {
        "decision": "DENY",
        "execution_result": "HALT",
        "aurion15_result": "fail",
        "aurion_reason": failure,
        "candidate_attempt_count": 0,
        "current_candidate": {},
        "tokens": {},
        "governance_feedback": {
            "aurion": {
                "result": "fail",
                "reason": failure,
                "failures": [failure],
                "candidate_attempt_count": 0,
                "generated_candidates": [],
                "candidate_validations": [],
                "ranked_candidate_validations": [],
                "admissible_candidates": [],
                "ranked_candidates": [],
                "rejected_candidates": [],
            }
        },
        "audit_trace": [
            {
                "stage": "aurion_runtime",
                "result": "fail",
                "reason": failure,
                "failures": [failure],
            }
        ],
        "integration_stage_order": [],
        "hash_chain": [],
    }
    denied["state_hash"] = rebuild_state_hash(denied)
    return denied


def _candidate_set_failures(candidates: object) -> list[str]:
    if not isinstance(candidates, list) or not candidates:
        return ["aurion_candidate_set_missing"]
    failures: list[str] = []
    ids: list[object] = []
    digests: list[str] = []
    for index, candidate in enumerate(candidates, start=1):
        if not isinstance(candidate, Mapping):
            failures.append(f"aurion_candidate_not_mapping:{index}")
            continue
        candidate_id = candidate.get("candidate_id")
        ids.append(candidate_id)
        if not isinstance(candidate_id, str) or not candidate_id:
            failures.append(f"aurion_candidate_id_invalid:{index}")
        try:
            digests.append(generate_digest(dict(candidate)))
        except Exception:
            failures.append(f"aurion_candidate_not_canonical:{index}")
    string_ids = [item for item in ids if isinstance(item, str)]
    if len(string_ids) != len(set(string_ids)):
        failures.append("aurion_candidate_id_duplicate")
    if len(digests) != len(set(digests)):
        failures.append("aurion_candidate_duplicate")
    if len(candidates) > MAX_CANDIDATE_ATTEMPTS:
        failures.append("aurion_candidate_set_exceeds_bound")
    return sorted(set(failures))


def _expected_ranked_candidates(
    state: Mapping[str, Any], candidates: list[Dict[str, Any]]
) -> list[Dict[str, Any]]:
    expected: list[Dict[str, Any]] = []
    for candidate in candidates:
        item = deepcopy(dict(candidate))
        item["rank_score"] = candidate_rank_score(state, item)
        expected.append(item)
    return sorted(
        expected,
        key=lambda item: (
            -int(item.get("rank_score", 0)),
            str(item.get("candidate_id", "")),
            generate_digest(item),
        ),
    )


def _validate_candidate_fail_closed(
    state: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    phase: str,
) -> Dict[str, Any]:
    failure = f"{phase}_candidate_validation_record_invalid"
    candidate_id = candidate.get("candidate_id")
    candidate_digest = generate_digest(dict(candidate))
    try:
        raw_validation = validate_candidate_constraints(state, candidate)
        if not isinstance(raw_validation, Mapping):
            raise TypeError("candidate_validation_record_not_mapping")
        validation = deepcopy(dict(raw_validation))
        generate_digest(validation)
        validation_failures = validation.get("failures")
        if set(validation) != {
            "valid",
            "failures",
            "candidate_id",
            "candidate_digest",
        }:
            raise ValueError("candidate_validation_record_schema_invalid")
        if not isinstance(validation.get("valid"), bool):
            raise ValueError("candidate_validation_validity_invalid")
        if not isinstance(validation_failures, list) or any(
            not isinstance(item, str) or not item
            for item in validation_failures
        ):
            raise ValueError("candidate_validation_failures_invalid")
        if validation.get("valid") is True and validation_failures:
            raise ValueError("candidate_validation_contradictory")
        if validation.get("candidate_id") != candidate_id:
            raise ValueError("candidate_validation_identity_mismatch")
        if validation.get("candidate_digest") != candidate_digest:
            raise ValueError("candidate_validation_digest_mismatch")
        return validation
    except Exception:
        return {
            "valid": False,
            "failures": [failure],
            "candidate_id": candidate_id,
            "candidate_digest": candidate_digest,
        }


def run_aurion_runtime(state: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        working_state = (
            deepcopy(dict(state)) if isinstance(state, Mapping) else {}
        )
        generate_digest(working_state)
    except Exception:
        return _invalid_aurion_input_state()
    audit_trace_valid = isinstance(working_state.get("audit_trace"), list)
    if not audit_trace_valid:
        working_state["audit_trace"] = []
    state_hash_entering_stage = working_state.get("state_hash")
    failures: list[str] = []
    if not audit_trace_valid:
        failures.append("aurion_audit_trace_invalid")
    already_completed = stage_already_completed(working_state, "aurion")
    if not live_state_hash_valid(working_state):
        failures.append("aurion_entry_state_hash_invalid")
    upstream_valid, upstream_failures = validate_domain_handoff_to_aurion(
        working_state
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    working_state = invalidate_from_stage(working_state, "aurion")
    if already_completed:
        failures.append("aurion_reentry_requires_full_retraversal")

    generated_candidates: list[Dict[str, Any]] = []
    ranked_candidates: list[Dict[str, Any]] = []
    admissible_candidates: list[Dict[str, Any]] = []
    rejected_candidates: list[Dict[str, Any]] = []
    candidate_validations: list[Dict[str, Any]] = []
    ranked_candidate_validations: list[Dict[str, Any]] = []
    attempts = 0
    if not failures:
        try:
            generated = generate_candidates(working_state)
        except Exception:  # Candidate providers fail closed at this boundary.
            generated = []
            failures.append("aurion_candidate_generation_failed")
        try:
            canonical_generated = CANONICAL_CANDIDATE_GENERATOR(
                working_state
            )
        except Exception:
            canonical_generated = []
            failures.append("aurion_canonical_candidate_generation_failed")
        failures.extend(_candidate_set_failures(generated))
        canonical_failures = _candidate_set_failures(canonical_generated)
        if canonical_failures:
            failures.append("aurion_canonical_candidate_set_invalid")
        try:
            if generate_digest(generated) != generate_digest(
                canonical_generated
            ):
                failures.append("aurion_generated_candidate_set_mismatch")
        except Exception:
            failures.append("aurion_generated_candidate_set_not_canonical")
        if isinstance(generated, list):
            for candidate in generated:
                if not isinstance(candidate, Mapping):
                    continue
                try:
                    generate_digest(dict(candidate))
                except Exception:
                    continue
                generated_candidates.append(deepcopy(dict(candidate)))
        if not failures:
            for candidate in generated_candidates:
                attempts += 1
                validation = _validate_candidate_fail_closed(
                    working_state, candidate, phase="generated"
                )
                candidate_validations.append(deepcopy(dict(validation)))
                if validation.get("valid") is True:
                    admissible_candidates.append(candidate)
                else:
                    rejected = deepcopy(candidate)
                    rejected["rejection_reasons"] = sorted(
                        set(
                            str(item)
                            for item in validation.get("failures", [])
                        )
                    )
                    rejected_candidates.append(rejected)
            try:
                ranked_output: object = rank_candidates(
                    working_state, admissible_candidates
                )
            except Exception:
                failures.append("aurion_candidate_ranking_failed")
                ranked_output = []
            if not isinstance(ranked_output, list):
                failures.append("aurion_ranked_candidate_set_invalid")
                ranked_output = []
            if ranked_output or admissible_candidates:
                failures.extend(_candidate_set_failures(ranked_output))
                for candidate in ranked_output:
                    if not isinstance(candidate, Mapping):
                        continue
                    try:
                        generate_digest(dict(candidate))
                    except Exception:
                        continue
                    ranked_candidates.append(deepcopy(dict(candidate)))
                try:
                    expected_ranked = _expected_ranked_candidates(
                        working_state, admissible_candidates
                    )
                    if generate_digest(ranked_candidates) != generate_digest(
                        expected_ranked
                    ):
                        failures.append("aurion_ranked_candidate_output_mismatch")
                except Exception:
                    failures.append("aurion_ranked_candidate_output_invalid")
                for candidate in ranked_candidates:
                    validation = _validate_candidate_fail_closed(
                        working_state, candidate, phase="ranked"
                    )
                    ranked_candidate_validations.append(
                        deepcopy(dict(validation))
                    )
                    if validation.get("valid") is not True:
                        failures.append(
                            "aurion_ranked_candidate_validation_failed"
                        )
                        failures.extend(
                            str(item)
                            for item in validation.get("failures", [])
                        )

    ordered_candidate_set_digest = generate_digest(ranked_candidates)
    selected_candidate: Dict[str, Any] | None = (
        ranked_candidates[0] if ranked_candidates and not failures else None
    )

    working_state["candidate_attempt_count"] = attempts
    if selected_candidate is None:
        working_state["aurion15_result"] = "fail"
        working_state["current_candidate"] = {}
        working_state = neutralize_denied_execution_state(
            working_state,
            permitted_stage_tokens=(
                "authority",
                "procedural_truth",
                "classification",
                "licensing",
                "governance",
                "grc",
                "domain",
            ),
        )
        reason = (
            "aurion_reentry_rejected"
            if "aurion_reentry_requires_full_retraversal" in failures
            else "confused_deputy_rejected"
            if not upstream_valid
            else "no_valid_candidate_pathway"
        )
    else:
        working_state["aurion15_result"] = "pass"
        working_state["current_candidate"] = selected_candidate
        reason = "aurion_pathway_resolved"

    failures = sorted(set(failures))
    working_state["aurion_reason"] = reason
    working_state.setdefault("governance_feedback", {})["aurion"] = {
        "result": working_state["aurion15_result"],
        "reason": reason,
        "failures": failures,
        "candidate_attempt_count": attempts,
        "generated_candidates": generated_candidates,
        "generated_candidate_set_digest": generate_digest(
            generated_candidates
        ),
        "candidate_validations": candidate_validations,
        "ranked_candidate_validations": ranked_candidate_validations,
        "admissible_candidates": admissible_candidates,
        "admissible_candidate_set_digest": generate_digest(
            admissible_candidates
        ),
        "ranked_candidates": ranked_candidates,
        "ordered_candidate_set_digest": ordered_candidate_set_digest,
        "current_candidate": selected_candidate or {},
        "selected_candidate_digest": generate_digest(
            selected_candidate or {}
        ),
        "selected_pathway_digest": generate_digest(
            dict(
                selected_candidate.get("pathway", {})
                if isinstance(selected_candidate, Mapping)
                and isinstance(selected_candidate.get("pathway", {}), Mapping)
                else {}
            )
        ),
        "rejected_candidates": rejected_candidates,
    }
    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "aurion_runtime",
            "result": working_state["aurion15_result"],
            "reason": reason,
            "candidate_attempt_count": attempts,
            "ordered_candidate_set_digest": ordered_candidate_set_digest,
            "failures": failures,
        }
    )
    working_state = append_stage_history(
        working_state,
        stage="aurion",
        result=working_state["aurion15_result"],
        reason=reason,
        failures=failures,
    )
    working_state["state_hash"] = rebuild_state_hash(working_state)
    working_state["aurion_evidence"] = build_stage_evidence(
        working_state,
        stage="aurion",
        state_hash_entering_stage=state_hash_entering_stage,
    )
    if selected_candidate is not None:
        working_state = issue_token(
            working_state,
            name="aurion",
            issued_at_stage="aurion_runtime",
            payload=stage_token_payload(working_state, "aurion"),
        )
    return append_stage_finalisation(working_state, stage="aurion")
