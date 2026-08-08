from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.domains.base_domain import (
    DOMAIN_ESCALATE,
    DOMAIN_PASS,
    DOMAIN_REDEFINE_CANDIDATE,
    DOMAIN_REFINE_CANDIDATE,
    DOMAIN_REQUIRE_NEXT_CANDIDATE,
    DOMAIN_RESULTS,
)
from sbp_lex.domains.legal_domain import LegalDomain
from sbp_lex.domains.operational_domain import OperationalDomain
from sbp_lex.domains.risk_domain import RiskDomain
from sbp_lex.domains.sovereign_domain import SovereignDomain
from sbp_lex.security.token_stack import issue_token
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.authority_boundary import validate_governed_domain_handoff
from sbp_lex.security.domain_aurion_evidence import (
    append_stage_finalisation,
    append_stage_history,
    build_stage_evidence,
    constraint_snapshot,
    invalidate_from_stage,
    live_state_hash_valid,
    neutralize_denied_execution_state,
    stage_already_completed,
    stage_token_payload,
)
from sbp_lex.shared.hash_chain import rebuild_state_hash

DOMAIN_ENGINES = [
    LegalDomain(),
    SovereignDomain(),
    OperationalDomain(),
    RiskDomain(),
]
REQUIRED_DOMAIN_ENGINE_ORDER = (
    "legal_domain",
    "sovereign_domain",
    "operational_domain",
    "risk_domain",
)
REQUIRED_DOMAIN_ENGINE_TYPES = (
    LegalDomain,
    SovereignDomain,
    OperationalDomain,
    RiskDomain,
)

DEFAULT_MAX_DOMAIN_ATTEMPTS = 5


def _invalid_domain_input_state() -> Dict[str, Any]:
    failure = "domain_input_not_canonical"
    denied: Dict[str, Any] = {
        "decision": "DENY",
        "execution_result": "HALT",
        "domain_result": DOMAIN_ESCALATE,
        "domain_reason": failure,
        "tokens": {},
        "governance_feedback": {
            "domain_wrap": {
                "result": DOMAIN_ESCALATE,
                "reason": failure,
                "domain_results": [],
                "attempts": [],
                "attempt_count": 0,
                "max_attempts": 0,
                "failures": [failure],
            }
        },
        "audit_trace": [
            {
                "stage": "domain_wrap",
                "result": DOMAIN_ESCALATE,
                "reason": failure,
                "failures": [failure],
            }
        ],
        "integration_stage_order": [],
        "hash_chain": [],
    }
    denied["state_hash"] = rebuild_state_hash(denied)
    return denied


def domain_max_attempts(state: Mapping[str, Any]) -> int:
    context = state.get("context", {}) or {}
    context = context if isinstance(context, Mapping) else {}
    profile = str(context.get("deployment_profile", "")).strip().lower()
    if profile == "physical-critical":
        return 3
    if profile == "industrial":
        return 5
    if profile in {"software", "software-systems", "software systems"}:
        return 7
    if profile in {"non-critical", "noncritical"}:
        return 10 if context.get("domain_fallback_safe") is True else DEFAULT_MAX_DOMAIN_ATTEMPTS
    return DEFAULT_MAX_DOMAIN_ATTEMPTS


def build_domain_fallback_candidate(
    state: Mapping[str, Any],
    *,
    attempt: int,
    max_attempts: int,
) -> Dict[str, Any]:
    context = state.get("context", {}) or {}
    context = context if isinstance(context, Mapping) else {}
    objective = state.get("action") or "governed_objective"
    if attempt == 1:
        adjustments: Dict[str, Any] = {}
        candidate_type = "requested_candidate"
    else:
        original_scope = str(context.get("operational_scope") or "bounded_scope")
        adjustments = {
            "operational_scope": f"{original_scope}:bounded:{attempt - 1}",
            "environment": context.get("environment") or "controlled_fallback",
            "human_proximity": "low",
            "operational_containment": "bounded",
            "emergency_stop_available": True,
        }
        candidate_type = "bounded_domain_fallback"
    constraints = constraint_snapshot(state)
    constraints["domain_result"] = None
    constraints["domain_operational_scope"] = adjustments.get(
        "operational_scope", constraints.get("classification_operational_scope")
    )
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    grc_evidence = state.get("grc_evidence", {})
    grc_evidence = grc_evidence if isinstance(grc_evidence, Mapping) else {}
    grc_token = tokens.get("grc", {})
    grc_token = grc_token if isinstance(grc_token, Mapping) else {}
    return {
        "candidate_id": f"domain_candidate_{attempt:03d}",
        "candidate_type": candidate_type,
        "governed_objective": objective,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "search_space_remaining": max_attempts - attempt,
        "risk_direction": "lower",
        "scope_direction": "narrower",
        "compliance_direction": "stronger",
        "invasiveness_direction": "lower",
        "context_adjustments": adjustments,
        "constraints": constraints,
        "bindings": {
            "request_fingerprint": state.get("request_fingerprint"),
            "eie_digest": state.get("eie_hash"),
            "collective_signal_digest": (
                state.get("collective_signals", {}).get("digest")
                if isinstance(state.get("collective_signals"), Mapping)
                else None
            ),
            "traversal_id": state.get("traversal_id"),
            "state_hash_entering_domain": state.get("state_hash"),
            "grc_evidence_digest": grc_evidence.get("evidence_digest"),
            "grc_token_digest": grc_token.get("digest"),
            "upstream_constraint_digest": generate_digest(
                constraint_snapshot(state)
            ),
        },
    }


def _state_for_domain_candidate(
    state: Mapping[str, Any], candidate: Mapping[str, Any]
) -> Dict[str, Any]:
    candidate_state = deepcopy(dict(state))
    candidate_state["current_candidate"] = deepcopy(dict(candidate))
    live_context = candidate_state.get("context", {}) or {}
    live_context = live_context if isinstance(live_context, Mapping) else {}
    context = deepcopy(dict(live_context))
    adjustments = candidate.get("context_adjustments", {}) or {}
    adjustments = adjustments if isinstance(adjustments, Mapping) else {}
    context.update(deepcopy(dict(adjustments)))
    candidate_state["context"] = context
    live_classification = candidate_state.get("classification", {}) or {}
    live_classification = (
        live_classification
        if isinstance(live_classification, Mapping)
        else {}
    )
    classification = deepcopy(dict(live_classification))
    if "operational_scope" in adjustments:
        classification["operational_scope"] = context["operational_scope"]
    candidate_state["classification"] = classification
    return candidate_state


def _domain_engine_configuration_failures() -> list[str]:
    if not isinstance(DOMAIN_ENGINES, (list, tuple)):
        return ["domain_rule_set_invalid"]
    failures: list[str] = []
    names: list[object] = []
    for index, domain in enumerate(DOMAIN_ENGINES, start=1):
        try:
            names.append(getattr(domain, "name", None))
        except Exception:
            names.append(None)
            failures.append(f"domain_rule_name_unreadable:{index}")
    if tuple(names) != REQUIRED_DOMAIN_ENGINE_ORDER:
        failures.append("domain_rule_set_missing_or_reordered")
    if len(DOMAIN_ENGINES) != len(REQUIRED_DOMAIN_ENGINE_TYPES) or any(
        type(engine) is not expected_type
        for engine, expected_type in zip(
            DOMAIN_ENGINES, REQUIRED_DOMAIN_ENGINE_TYPES
        )
    ):
        failures.append("domain_rule_implementation_mismatch")
    if any(not isinstance(name, str) or not name for name in names):
        failures.append("domain_rule_name_invalid")
    if all(isinstance(name, str) for name in names) and len(set(names)) != len(
        names
    ):
        failures.append("duplicate_domain_rule")
    return sorted(set(failures))


def _evaluate_domains(
    state: Mapping[str, Any],
) -> tuple[list[Dict[str, Any]], list[str]]:
    results: list[Dict[str, Any]] = []
    failures: list[str] = []
    for index, engine in enumerate(DOMAIN_ENGINES, start=1):
        try:
            name = getattr(engine, "name", "unknown_domain")
        except Exception:
            failures.append(f"domain_rule_name_unreadable:{index}")
            continue
        try:
            raw_result = engine.evaluate(state)
        except Exception:  # Domain plugins are an enforcement boundary.
            failures.append(f"domain_rule_exception:{name}")
            continue
        if not isinstance(raw_result, Mapping):
            failures.append(f"domain_rule_result_invalid:{name}")
            continue
        try:
            result = dict(raw_result)
            generate_digest(result)
            if set(result) != {
                "domain",
                "result",
                "reason",
                "failures",
                "evidence",
            }:
                failures.append(f"domain_rule_result_schema_invalid:{name}")
                continue
            if result.get("domain") != name:
                failures.append(f"domain_rule_identity_mismatch:{name}")
            if result.get("result") not in DOMAIN_RESULTS:
                failures.append(f"domain_rule_outcome_invalid:{name}")
            if not isinstance(result.get("reason"), str) or not result.get("reason"):
                failures.append(f"domain_rule_reason_invalid:{name}")
            result_failures = result.get("failures")
            if not isinstance(result_failures, list) or any(
                not isinstance(item, str) or not item for item in result_failures
            ):
                failures.append(f"domain_rule_failures_invalid:{name}")
            elif result.get("result") == DOMAIN_PASS and result_failures:
                failures.append(f"domain_rule_contradictory_pass:{name}")
            if not isinstance(result.get("evidence"), Mapping):
                failures.append(f"domain_rule_evidence_invalid:{name}")
        except Exception:
            failures.append(f"domain_rule_result_not_canonical:{name}")
            continue
        results.append(result)
    return results, sorted(set(failures))


def run_domain_wrap(state: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        working_state = (
            deepcopy(dict(state)) if isinstance(state, Mapping) else {}
        )
        generate_digest(working_state)
    except Exception:
        return _invalid_domain_input_state()
    audit_trace_valid = isinstance(working_state.get("audit_trace"), list)
    if not audit_trace_valid:
        working_state["audit_trace"] = []
    state_hash_entering_stage = working_state.get("state_hash")
    failures: list[str] = []
    if not audit_trace_valid:
        failures.append("domain_audit_trace_invalid")
    already_completed = stage_already_completed(working_state, "domain")
    if not live_state_hash_valid(working_state):
        failures.append("domain_entry_state_hash_invalid")
    upstream_valid, upstream_failures = validate_governed_domain_handoff(
        working_state
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    working_state = invalidate_from_stage(working_state, "domain")
    if already_completed:
        failures.append("domain_reentry_requires_full_retraversal")
    failures.extend(_domain_engine_configuration_failures())

    max_attempts = domain_max_attempts(working_state)
    attempts: list[Dict[str, Any]] = []
    seen_candidate_hashes: set[str] = set()
    domain_results: list[Dict[str, Any]] = []
    final_result = DOMAIN_ESCALATE
    reason = "domain_fallback_exhausted"

    if failures:
        reason = (
            "domain_reentry_rejected"
            if "domain_reentry_requires_full_retraversal" in failures
            else "confused_deputy_rejected"
            if not upstream_valid
            else "domain_rule_set_invalid"
        )

    for attempt in range(1, max_attempts + 1) if not failures else ():
        candidate = build_domain_fallback_candidate(
            working_state, attempt=attempt, max_attempts=max_attempts
        )
        candidate_hash = generate_digest(candidate)
        if candidate_hash in seen_candidate_hashes:
            final_result = DOMAIN_ESCALATE
            reason = "identical_domain_candidate_rejected"
            break
        seen_candidate_hashes.add(candidate_hash)
        candidate_state = _state_for_domain_candidate(working_state, candidate)
        domain_results, evaluation_failures = _evaluate_domains(candidate_state)
        if evaluation_failures:
            failures.extend(evaluation_failures)
            attempts.append(
                {
                    "attempt": attempt,
                    "candidate": candidate,
                    "candidate_hash": candidate_hash,
                    "result": DOMAIN_ESCALATE,
                    "domain_results": domain_results,
                    "failures": evaluation_failures,
                }
            )
            final_result = DOMAIN_ESCALATE
            reason = "domain_evaluation_invalid"
            break
        result_values = [str(item.get("result")) for item in domain_results]
        attempt_result = DOMAIN_PASS if domain_results and all(value == DOMAIN_PASS for value in result_values) else (
            DOMAIN_ESCALATE if DOMAIN_ESCALATE in result_values else (
                DOMAIN_REDEFINE_CANDIDATE if DOMAIN_REDEFINE_CANDIDATE in result_values else (
                    DOMAIN_REQUIRE_NEXT_CANDIDATE
                    if DOMAIN_REQUIRE_NEXT_CANDIDATE in result_values
                    else DOMAIN_REFINE_CANDIDATE
                )
            )
        )
        attempt_record = {
            "attempt": attempt,
            "candidate": candidate,
            "candidate_hash": candidate_hash,
            "result": attempt_result,
            "domain_results": domain_results,
            "failures": [],
        }
        attempts.append(attempt_record)
        working_state.setdefault("audit_trace", []).append(
            {
                "stage": "domain_wrap_attempt",
                "attempt": attempt,
                "candidate_id": candidate["candidate_id"],
                "candidate_hash": candidate_hash,
                "result": attempt_result,
            }
        )

        if attempt_result == DOMAIN_PASS:
            final_result = DOMAIN_PASS
            reason = "domain_wrap_passed"
            working_state["domain_candidate"] = candidate
            working_state["current_candidate"] = candidate
            break
        if attempt_result == DOMAIN_ESCALATE:
            final_result = DOMAIN_ESCALATE
            reason = "terminal_domain_escalation"
            break

    failures = sorted(set(failures))
    if final_result != DOMAIN_PASS:
        working_state = neutralize_denied_execution_state(
            working_state,
            permitted_stage_tokens=(
                "authority",
                "procedural_truth",
                "classification",
                "licensing",
                "governance",
                "grc",
            ),
            decision=(
                "DENY" if failures or not upstream_valid else "ESCALATE"
            ),
        )
        working_state.pop("domain_candidate", None)
        working_state.pop("current_candidate", None)

    working_state["domain_result"] = final_result
    working_state["domain_reason"] = reason

    working_state.setdefault("governance_feedback", {})["domain_wrap"] = {
        "result": final_result,
        "reason": reason,
        "domain_results": domain_results,
        "attempts": attempts,
        "attempt_count": len(attempts),
        "max_attempts": max_attempts,
        "failures": failures,
    }

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "domain_wrap",
            "result": final_result,
            "reason": reason,
            "attempt_count": len(attempts),
            "max_attempts": max_attempts,
            "failures": failures,
        }
    )
    working_state = append_stage_history(
        working_state,
        stage="domain",
        result=final_result,
        reason=reason,
        failures=failures,
    )
    working_state["state_hash"] = rebuild_state_hash(working_state)
    working_state["domain_evidence"] = build_stage_evidence(
        working_state,
        stage="domain",
        state_hash_entering_stage=state_hash_entering_stage,
    )
    if final_result == DOMAIN_PASS:
        working_state = issue_token(
            working_state,
            name="domain",
            issued_at_stage="domain_wrap",
            payload=stage_token_payload(working_state, "domain"),
        )
    return append_stage_finalisation(working_state, stage="domain")
