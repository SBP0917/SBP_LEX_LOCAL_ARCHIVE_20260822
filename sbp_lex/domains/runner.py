from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.domains.base_domain import (
    DOMAIN_ESCALATE,
    DOMAIN_PASS,
    DOMAIN_REDEFINE_CANDIDATE,
    DOMAIN_REFINE_CANDIDATE,
    DOMAIN_REQUIRE_NEXT_CANDIDATE,
)
from sbp_lex.domains.legal_domain import LegalDomain
from sbp_lex.domains.operational_domain import OperationalDomain
from sbp_lex.domains.risk_domain import RiskDomain
from sbp_lex.domains.sovereign_domain import SovereignDomain
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry
from sbp_lex.security.pqc import generate_digest

DOMAIN_ENGINES = [
    LegalDomain(),
    SovereignDomain(),
    OperationalDomain(),
    RiskDomain(),
]

DEFAULT_MAX_DOMAIN_ATTEMPTS = 5


def domain_max_attempts(state: Mapping[str, Any]) -> int:
    context = state.get("context", {}) or {}
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
    }


def _state_for_domain_candidate(
    state: Mapping[str, Any], candidate: Mapping[str, Any]
) -> Dict[str, Any]:
    candidate_state = deepcopy(dict(state))
    candidate_state["current_candidate"] = deepcopy(dict(candidate))
    context = deepcopy(dict(candidate_state.get("context", {}) or {}))
    context.update(deepcopy(dict(candidate.get("context_adjustments", {}) or {})))
    candidate_state["context"] = context
    classification = deepcopy(dict(candidate_state.get("classification", {}) or {}))
    if "operational_scope" in candidate.get("context_adjustments", {}):
        classification["operational_scope"] = context["operational_scope"]
    candidate_state["classification"] = classification
    return candidate_state


def _evaluate_domains(state: Mapping[str, Any]) -> list[Dict[str, Any]]:
    return [domain.evaluate(state) for domain in DOMAIN_ENGINES]


def run_domain_wrap(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))

    if working_state.get("governance_result") != "ALLOW":
        working_state["domain_result"] = DOMAIN_ESCALATE
        working_state["decision"] = "ESCALATE"
        working_state["execution_result"] = "HALT"
        working_state.setdefault("governance_feedback", {})["domain_wrap"] = {
            "result": DOMAIN_ESCALATE,
            "reason": "governance_not_allowed",
            "domain_results": [],
            "attempts": [],
        }
        return append_hash_entry(
            working_state,
            stage="domain_wrap",
            payload={"domain_result": DOMAIN_ESCALATE, "reason": "governance_not_allowed"},
        )

    max_attempts = domain_max_attempts(working_state)
    attempts: list[Dict[str, Any]] = []
    seen_candidate_hashes: set[str] = set()
    domain_results: list[Dict[str, Any]] = []
    final_result = DOMAIN_ESCALATE
    reason = "domain_fallback_exhausted"

    for attempt in range(1, max_attempts + 1):
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
        domain_results = _evaluate_domains(candidate_state)
        result_values = [str(item.get("result")) for item in domain_results]
        attempt_result = DOMAIN_PASS if all(value == DOMAIN_PASS for value in result_values) else (
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
            working_state["current_candidate"] = candidate
            break
        if attempt_result == DOMAIN_ESCALATE:
            final_result = DOMAIN_ESCALATE
            reason = "terminal_domain_escalation"
            break

    if final_result != DOMAIN_PASS:
        working_state["decision"] = "ESCALATE"
        working_state["execution_result"] = "HALT"

    working_state["domain_result"] = final_result

    working_state.setdefault("governance_feedback", {})["domain_wrap"] = {
        "result": final_result,
        "reason": reason,
        "domain_results": domain_results,
        "attempts": attempts,
        "attempt_count": len(attempts),
        "max_attempts": max_attempts,
    }

    if final_result == DOMAIN_PASS:
        working_state = issue_token(
            working_state,
            name="domain",
            issued_at_stage="domain_wrap",
            payload={
                "domain_result": final_result,
                "domain_results": domain_results,
            },
        )

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "domain_wrap",
            "result": final_result,
            "reason": reason,
            "attempt_count": len(attempts),
            "max_attempts": max_attempts,
        }
    )

    return append_hash_entry(
        working_state,
        stage="domain_wrap",
        payload={
            "domain_result": final_result,
            "reason": reason,
            "domain_results": domain_results,
            "attempt_count": len(attempts),
            "max_attempts": max_attempts,
        },
      )
