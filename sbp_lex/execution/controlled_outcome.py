from __future__ import annotations

from typing import Any, Dict, Mapping
from copy import deepcopy

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.hash_chain import append_hash_entry

VALID_OUTCOMES = {"ALLOW", "DENY", "ESCALATE", "PERSISTENT_INOPERABILITY"}


def apply_terminal_control_state(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    state = deepcopy(dict(execution_state))
    executable = (
        state.get("decision") == "ALLOW"
        and state.get("execution_result") == "EXECUTE"
        and state.get("execution_verified") is True
        and state.get("token_stack_valid") is True
    )
    reentry = state.get("governed_reentry", {}) or {}
    if executable:
        state["operational_state"] = "OPERABLE"
        state["persistent_inoperability"] = False
        state["controlled_return_required"] = False
        if reentry.get("reentry_permitted") is True:
            reentry = {**reentry, "reentry_completed": True}
            state["governed_reentry"] = reentry
    else:
        state["operational_state"] = "PERSISTENT_INOPERABILITY"
        state["persistent_inoperability"] = True
        state["controlled_return_required"] = True
        state["execution_result"] = "HALT"
        state["execution_verified"] = False
        if state.get("decision") not in {"DENY", "ESCALATE"}:
            state["decision"] = "DENY"
        state["last_denied_fingerprint"] = state.get("request_fingerprint")
    state.setdefault("audit_trace", []).append(
        {
            "stage": "terminal_control",
            "operational_state": state["operational_state"],
            "controlled_return_required": state["controlled_return_required"],
        }
    )
    return state


def build_controlled_outcome(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    decision = execution_state.get("decision", "DENY")
    if decision not in VALID_OUTCOMES:
        decision = "DENY"

    payload = {
        "request_fingerprint": execution_state.get("request_fingerprint"),
        "decision": decision,
        "execution_verified": execution_state.get("execution_verified", False),
        "audit_hash": execution_state.get("audit_hash"),
        "convergence_hash": execution_state.get("convergence_hash"),
        "pipeline_mode": execution_state.get("pipeline_mode"),
        "state_hash": execution_state.get("state_hash"),
        "operational_state": execution_state.get("operational_state"),
        "persistent_inoperability": execution_state.get("persistent_inoperability", False),
        "governed_reentry": execution_state.get("governed_reentry", {}),
    }
    signature = sign_payload(payload)

    return {
        "valid": verify_signature(payload, signature),
        "outcome_hash": generate_digest(payload),
        "signature": signature,
        "payload": payload,
    }


def verify_controlled_outcome(outcome_record: Mapping[str, Any]) -> bool:
    if not isinstance(outcome_record, Mapping):
        return False

    payload = outcome_record.get("payload")
    if not isinstance(payload, Mapping):
        return False

    if outcome_record.get("outcome_hash") != generate_digest(payload):
        return False

    if not verify_signature(payload, outcome_record.get("signature", {})):
        return False

    if payload.get("decision") not in VALID_OUTCOMES:
        return False

    if payload.get("decision") == "ALLOW":
        if payload.get("execution_verified") is not True:
            return False
        if not payload.get("audit_hash"):
            return False
        if not payload.get("convergence_hash"):
            return False
        if payload.get("persistent_inoperability") is True:
            return False
    elif payload.get("persistent_inoperability") is not True:
        return False

    return True


def finalise_outcome(outcome_record: Mapping[str, Any]) -> Dict[str, Any]:
    if not verify_controlled_outcome(outcome_record):
        return {"allowed": False, "decision": "DENY", "reason": "OUTCOME_INVALID"}

    payload = outcome_record.get("payload", {})
    return {
        "allowed": payload.get("decision") == "ALLOW",
        "decision": payload.get("decision"),
        "outcome_locked": True,
    }


def record_controlled_return(
    state: Mapping[str, Any], outcome_record: Mapping[str, Any]
) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    working_state["controlled_outcome"] = deepcopy(dict(outcome_record))
    return append_hash_entry(
        working_state,
        stage="controlled_return",
        payload={
            "outcome_hash": outcome_record.get("outcome_hash"),
            "decision": outcome_record.get("payload", {}).get("decision"),
            "operational_state": working_state.get("operational_state"),
        },
    )
