from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.config.pipeline_config import HASH_CHAIN_STAGES
from sbp_lex.config.security_config import HASH_CHAIN_VERSION
from sbp_lex.security.pqc import generate_digest


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
    chain = state.get("hash_chain", [])
    if not isinstance(chain, list):
        return False

    previous_hash = "GENESIS"
    for entry in chain:
        if not isinstance(entry, Mapping):
            return False
        if entry.get("previous_hash") != previous_hash:
            return False
        expected_payload = {
            "version": entry.get("version"),
            "stage": entry.get("stage"),
            "previous_hash": entry.get("previous_hash"),
            "payload_hash": entry.get("payload_hash"),
            "request_fingerprint": entry.get("request_fingerprint"),
        }
        expected_hash = generate_digest(expected_payload)
        if entry.get("hash") != expected_hash:
            return False
        previous_hash = str(entry.get("hash"))
    return True
