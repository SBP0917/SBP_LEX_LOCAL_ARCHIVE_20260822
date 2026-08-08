from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.config.pipeline_config import HASH_CHAIN_STAGES
from sbp_lex.config.security_config import HASH_CHAIN_VERSION
from sbp_lex.security.pqc import generate_digest


HASH_ENTRY_FIELDS = {
    "version",
    "stage",
    "previous_hash",
    "payload_hash",
    "request_fingerprint",
    "hash",
}

# Major stages may have multiple canonical substage entries.  This profile is
# deliberately used only for a successful terminal outcome; truncated denial
# chains continue to use the prefix-safe structural verifier below.
SUCCESS_TERMINAL_STAGE_PROFILE = (
    "hard_ingress",
    "state_construction",
    "collective_attach",
    "ap_acf_precheck",
    "root_of_trust",
    "root_of_trust",
    "root_of_trust",
    "root_of_trust",
    "root_of_trust",
    "root_of_trust",
    "root_of_trust",
    "root_of_trust",
    "procedural_truth",
    "procedural_truth",
    "procedural_truth",
    "procedural_truth",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "governance",
    "grc",
    "domain_wrap",
    "aurion_runtime",
    "execution_gate",
    "audit",
    "controlled_return",
)


def _is_digest(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def current_chain_hash(state: Mapping[str, Any]) -> str:
    chain = state.get("hash_chain", [])
    if not chain:
        return "GENESIS"
    return str(chain[-1].get("hash"))


def append_hash_entry(state: Mapping[str, Any], *, stage: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    if stage not in HASH_CHAIN_STAGES:
        raise ValueError(f"Invalid hash-chain stage: {stage}")

    working_state = deepcopy(dict(state))
    chain = list(working_state.get("hash_chain", []))
    previous_hash = current_chain_hash(working_state)
    payload_hash = generate_digest(payload)
    entry_payload = {
        "version": HASH_CHAIN_VERSION,
        "stage": stage,
        "previous_hash": previous_hash,
        "payload_hash": payload_hash,
        "request_fingerprint": working_state.get("request_fingerprint"),
    }
    entry_hash = generate_digest(entry_payload)
    chain.append({**entry_payload, "hash": entry_hash})
    working_state["hash_chain"] = chain
    working_state["state_hash"] = generate_digest(_state_for_hashing(working_state))
    return working_state


def _state_for_hashing(state: Mapping[str, Any]) -> Dict[str, Any]:
    excluded = {"state_hash", "audit_hash"}
    return {key: value for key, value in dict(state).items() if key not in excluded}


def rebuild_state_hash(state: Mapping[str, Any]) -> str:
    return generate_digest(_state_for_hashing(state))


def verify_hash_chain(state: Mapping[str, Any]) -> bool:
    if not isinstance(state, Mapping):
        return False
    chain = state.get("hash_chain", [])
    if not isinstance(chain, list) or not chain:
        return False

    previous_hash = "GENESIS"
    previous_stage_position = -1
    expected_request_fingerprint = state.get("request_fingerprint")
    if expected_request_fingerprint is None:
        first = chain[0]
        expected_request_fingerprint = (
            first.get("request_fingerprint")
            if isinstance(first, Mapping)
            else None
        )
    if (
        not isinstance(expected_request_fingerprint, str)
        or not expected_request_fingerprint
    ):
        return False
    for entry in chain:
        if not isinstance(entry, Mapping):
            return False
        if set(entry) != HASH_ENTRY_FIELDS:
            return False
        if entry.get("version") != HASH_CHAIN_VERSION:
            return False
        stage = entry.get("stage")
        if stage not in HASH_CHAIN_STAGES:
            return False
        stage_position = HASH_CHAIN_STAGES.index(stage)
        if stage_position < previous_stage_position:
            return False
        previous_stage_position = stage_position
        if entry.get("previous_hash") != previous_hash:
            return False
        if entry.get("request_fingerprint") != expected_request_fingerprint:
            return False
        if not _is_digest(entry.get("payload_hash")) or not _is_digest(
            entry.get("hash")
        ):
            return False
        expected_payload = {
            "version": entry.get("version"),
            "stage": stage,
            "previous_hash": entry.get("previous_hash"),
            "payload_hash": entry.get("payload_hash"),
            "request_fingerprint": entry.get("request_fingerprint"),
        }
        expected_hash = generate_digest(expected_payload)
        if entry.get("hash") != expected_hash:
            return False
        previous_hash = str(entry.get("hash"))
    final_outcome = state.get("final_outcome")
    if (
        isinstance(final_outcome, Mapping)
        and final_outcome.get("allowed") is True
        and tuple(entry.get("stage") for entry in chain)
        != SUCCESS_TERMINAL_STAGE_PROFILE
    ):
        return False
    return True


def verify_success_terminal_hash_chain(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Verify the exact successful Desktop V1 chain and terminal payload links."""

    failures: list[str] = []
    if not isinstance(state, Mapping):
        return False, ["terminal_hash_chain_state_invalid"]
    if not verify_hash_chain(state):
        return False, ["terminal_hash_chain_invalid"]
    if (
        state.get("decision") != "ALLOW"
        or state.get("execution_result") != "EXECUTE"
        or state.get("execution_verified") is not True
        or state.get("token_stack_valid") is not True
    ):
        failures.append("terminal_hash_chain_success_state_invalid")

    chain = state.get("hash_chain", [])
    stages = tuple(entry.get("stage") for entry in chain)
    if stages != SUCCESS_TERMINAL_STAGE_PROFILE:
        failures.append("terminal_hash_chain_stage_profile_invalid")

    integration_order = state.get("integration_stage_order")
    if integration_order != list(HASH_CHAIN_STAGES):
        failures.append("terminal_hash_chain_integration_order_invalid")

    if len(chain) < 3:
        return False, sorted(
            set(failures + ["terminal_hash_chain_truncated"])
        )
    gate_entry, audit_entry, return_entry = chain[-3:]

    gate_payload = {
        "execution_result": state.get("execution_result"),
        "decision": state.get("decision"),
        "failures": state.get("token_verification_failures", []),
    }
    if gate_entry.get("payload_hash") != generate_digest(gate_payload):
        failures.append("terminal_hash_chain_execution_gate_payload_mismatch")

    audit_record = state.get("audit_record")
    audit_payload = (
        audit_record.get("payload")
        if isinstance(audit_record, Mapping)
        else None
    )
    if not isinstance(audit_payload, Mapping):
        failures.append("terminal_hash_chain_audit_record_missing")
    else:
        audit_chain = audit_payload.get("audit_chain")
        if audit_chain != chain[:-2]:
            failures.append("terminal_hash_chain_audit_snapshot_mismatch")
    audit_complete = (
        state.get("audit_finalisation", {}).get("audit_complete")
        if isinstance(state.get("audit_finalisation"), Mapping)
        else None
    )
    audit_entry_payload = {
        "audit_hash": state.get("audit_hash"),
        "audit_complete": audit_complete,
    }
    if (
        audit_complete is not True
        or audit_entry.get("payload_hash")
        != generate_digest(audit_entry_payload)
    ):
        failures.append("terminal_hash_chain_audit_payload_mismatch")

    controlled_outcome = state.get("controlled_outcome")
    controlled_payload = (
        controlled_outcome.get("payload")
        if isinstance(controlled_outcome, Mapping)
        else None
    )
    if not isinstance(controlled_payload, Mapping):
        failures.append("terminal_hash_chain_controlled_outcome_missing")
        controlled_payload = {}
    if controlled_payload.get("audit_hash") != state.get("audit_hash"):
        failures.append("terminal_hash_chain_controlled_audit_mismatch")
    if controlled_payload.get("decision") != state.get("decision"):
        failures.append("terminal_hash_chain_controlled_decision_mismatch")
    return_payload = {
        "outcome_hash": (
            controlled_outcome.get("outcome_hash")
            if isinstance(controlled_outcome, Mapping)
            else None
        ),
        "decision": controlled_payload.get("decision"),
        "operational_state": state.get("operational_state"),
    }
    if return_entry.get("payload_hash") != generate_digest(return_payload):
        failures.append("terminal_hash_chain_controlled_payload_mismatch")
    return not failures, sorted(set(failures))
