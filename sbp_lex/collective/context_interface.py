from __future__ import annotations

import time
from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.collective.sovereign_knowledge_graph_engine import prepare_skg_context, sign_skg_context
from sbp_lex.collective.digital_twin_network_engine import prepare_dtn_context, sign_dtn_context
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.hash_chain import append_hash_entry, rebuild_state_hash

COLLECTIVE_SIGNAL_STATUS_ATTACHED = "ATTACHED"
COLLECTIVE_SIGNAL_STATUS_EMPTY = "EMPTY"
COLLECTIVE_SIGNAL_STATUS_REJECTED = "REJECTED"


def prepare_pre_context_signals(request: Mapping[str, Any]) -> Dict[str, Any]:
    request_fingerprint = generate_digest(dict(request))

    skg_context = sign_skg_context(prepare_skg_context(request))
    dtn_context = sign_dtn_context(prepare_dtn_context(request, skg_context))

    signal_payload = {
        "request_fingerprint": request_fingerprint,
        "intent_signal": str(request.get("action", "")),
        "risk_potential_signal": dtn_context.get("risk_potential_signal"),
        "authority_link_signal": skg_context.get("authority_link_signal"),
        "jurisdiction_signal": skg_context.get("jurisdiction_signal"),
        "dependency_signal": dtn_context.get("dependency_signal"),
        "policy_conflict_signal": skg_context.get("policy_conflict_signal"),
        "operational_context_signal": dtn_context.get("operational_context_signal"),
        "precedence_signal": skg_context.get("precedence_signal"),
        "ap_acf_declaration": request.get("classification", {}),
        "manufacturer_declaration": request.get("manufacturer_declaration", {}),
        "skg_digest": skg_context.get("skg_digest"),
        "dtn_digest": dtn_context.get("dtn_digest"),
        "timestamp": int(time.time()),
        "nonce": generate_digest({"request_fingerprint": request_fingerprint, "time": int(time.time())})[:32],
    }
    digest = generate_digest(signal_payload)
    signature = sign_payload(signal_payload)

    return {
        **signal_payload,
        "digest": digest,
        "signature": signature,
    }


def validate_collective_signal_package(
    *,
    signals: Mapping[str, Any],
    request_fingerprint: str,
) -> tuple[bool, list[str]]:
    failures: list[str] = []

    if not isinstance(signals, Mapping):
        return False, ["collective_signals_not_mapping"]

    if signals.get("request_fingerprint") != request_fingerprint:
        failures.append("collective_signal_request_fingerprint_mismatch")

    payload = _signal_payload_for_digest(signals)
    if signals.get("digest") != generate_digest(payload):
        failures.append("collective_signal_digest_mismatch")

    if not verify_signature(payload, signals.get("signature", {})):
        failures.append("collective_signal_signature_invalid")

    if not signals.get("nonce"):
        failures.append("collective_signal_nonce_missing")

    if not isinstance(signals.get("timestamp"), int):
        failures.append("collective_signal_timestamp_invalid")
    return {key: deepcopy(value) for key, value in dict(signals).items() if key not in excluded}
