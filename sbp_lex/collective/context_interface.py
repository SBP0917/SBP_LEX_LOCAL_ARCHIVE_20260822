from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.collective.digital_twin_network_engine import (
    prepare_dtn_context,
    sign_dtn_context,
    verify_dtn_context,
)
from sbp_lex.collective.sovereign_knowledge_graph_engine import (
    prepare_skg_context,
    sign_skg_context,
    verify_skg_context,
)
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.control_chain_validation import canonical_eie_digest
from sbp_lex.shared.hash_chain import append_hash_entry, rebuild_state_hash

COLLECTIVE_SIGNAL_STATUS_ATTACHED = "ATTACHED"
COLLECTIVE_SIGNAL_STATUS_EMPTY = "EMPTY"
COLLECTIVE_SIGNAL_STATUS_REJECTED = "REJECTED"
CANONICAL_SIGNAL_AUTHORITY = "CANONICAL_RUNTIME"


def _canonical_signal_timestamp(request_fingerprint: str) -> int:
    return int(request_fingerprint[:12], 16)


def prepare_pre_context_signals(request: Mapping[str, Any]) -> Dict[str, Any]:
    request_fingerprint = generate_digest(dict(request))
    skg_context = sign_skg_context(prepare_skg_context(request))
    dtn_context = sign_dtn_context(prepare_dtn_context(request, skg_context))
    timestamp = _canonical_signal_timestamp(request_fingerprint)
    payload = {
        "request_fingerprint": request_fingerprint,
        "intent_signal": str(request.get("action", "")),
        "risk_potential_signal": dtn_context.get("risk_potential_signal"),
        "authority_link_signal": skg_context.get("authority_link_signal"),
        "jurisdiction_signal": skg_context.get("jurisdiction_signal"),
        "dependency_signal": dtn_context.get("dependency_signal"),
        "policy_conflict_signal": skg_context.get("policy_conflict_signal"),
        "operational_context_signal": dtn_context.get("operational_context_signal"),
        "precedence_signal": skg_context.get("precedence_signal"),
        "ap_acf_declaration": request.get("payload", {}).get("classification", request.get("classification", {})),
        "manufacturer_declaration": request.get("manufacturer_declaration", {}),
        "skg_digest": skg_context.get("skg_digest"),
        "dtn_digest": dtn_context.get("dtn_digest"),
        "skg_context": skg_context,
        "dtn_context": dtn_context,
        "timestamp": timestamp,
        "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
        "nonce": generate_digest(
            {
                "request_fingerprint": request_fingerprint,
                "timestamp": timestamp,
                "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
            }
        )[:32],
    }
    return {**payload, "digest": generate_digest(payload), "signature": sign_payload(payload)}


def _signal_payload_for_digest(signals: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: deepcopy(value) for key, value in dict(signals).items() if key not in {"digest", "signature"}}


def validate_collective_signal_package(*, signals: Mapping[str, Any], request_fingerprint: str) -> tuple[bool, list[str]]:
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
    skg_context = signals.get("skg_context", {})
    dtn_context = signals.get("dtn_context", {})
    skg_valid, skg_failures = verify_skg_context(skg_context)
    if not skg_valid:
        failures.extend(skg_failures)
    dtn_valid, dtn_failures = verify_dtn_context(
        dtn_context, expected_skg_digest=signals.get("skg_digest")
    )
    if not dtn_valid:
        failures.extend(dtn_failures)
    if signals.get("skg_digest") != skg_context.get("skg_digest"):
        failures.append("collective_skg_digest_mismatch")
    if signals.get("dtn_digest") != dtn_context.get("dtn_digest"):
        failures.append("collective_dtn_digest_mismatch")
    return len(failures) == 0, failures


def attach_collective_signals(state: Mapping[str, Any], pre_context_signals: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    if pre_context_signals is None:
        working_state["collective_signals"] = {}
        working_state["collective_signal_status"] = COLLECTIVE_SIGNAL_STATUS_EMPTY
        working_state.setdefault("audit_trace", []).append({"stage": "collective_attach", "event": "NO_PRE_CONTEXT_SIGNALS_PROVIDED"})
        return append_hash_entry(working_state, stage="collective_attach", payload={"status": COLLECTIVE_SIGNAL_STATUS_EMPTY})

    valid, failures = validate_collective_signal_package(signals=pre_context_signals, request_fingerprint=working_state.get("request_fingerprint", ""))
    authority_signal = pre_context_signals.get("authority_link_signal", {})
    jurisdiction_signal = pre_context_signals.get("jurisdiction_signal", {})
    if authority_signal.get("resolved_authority") != working_state.get("resolved_authority"):
        failures.append("collective_authority_context_mismatch")
        valid = False
    if jurisdiction_signal.get("jurisdiction") != working_state.get("jurisdiction"):
        failures.append("collective_jurisdiction_context_mismatch")
        valid = False
    if not valid:
        working_state["collective_signals"] = {}
        working_state["collective_signal_status"] = COLLECTIVE_SIGNAL_STATUS_REJECTED
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state.setdefault("governance_feedback", {})["collective_signal_failures"] = failures
        working_state.setdefault("audit_trace", []).append({"stage": "collective_attach", "event": "COLLECTIVE_SIGNAL_REJECTED", "failures": failures})
        return append_hash_entry(working_state, stage="collective_attach", payload={"status": COLLECTIVE_SIGNAL_STATUS_REJECTED, "failures": failures})

    working_state["collective_signals"] = deepcopy(dict(pre_context_signals))
    working_state["collective_signal_status"] = COLLECTIVE_SIGNAL_STATUS_ATTACHED
    working_state["collective_signal_evidence"] = {
        "role": "context_only_non_authoritative",
        "request_bound": True,
        "skg_verified": True,
        "dtn_verified": True,
        "skg_dtn_relation_verified": True,
        "provenance": {
            "skg_digest": pre_context_signals.get("skg_digest"),
            "dtn_digest": pre_context_signals.get("dtn_digest"),
            "timestamp_authority": pre_context_signals.get("timestamp_authority"),
        },
    }
    envelope = working_state.get("pt_evidence_envelope", {})
    eie = working_state.get("eie", {})
    if isinstance(envelope, Mapping) and isinstance(eie, Mapping):
        eie = deepcopy(dict(eie))
        eie["skg_truth_foundation"] = deepcopy(
            dict(envelope.get("skg_truth_foundation_metadata", {}))
        )
        eie["dtn_contextual_verification"] = deepcopy(
            dict(envelope.get("dtn_contextual_verification_metadata", {}))
        )
        eie["eie_hash"] = canonical_eie_digest(eie)
        working_state["eie"] = eie
        working_state["eie_hash"] = eie["eie_hash"]
        envelope = deepcopy(dict(envelope))
        envelope["eie_hash"] = eie["eie_hash"]
        working_state["pt_evidence_envelope"] = envelope
        working_state["pt_evidence_envelope_digest"] = generate_digest(envelope)
    working_state.setdefault("audit_trace", []).append({"stage": "collective_attach", "event": "COLLECTIVE_SIGNAL_ATTACHED", "digest": pre_context_signals.get("digest")})
    working_state = append_hash_entry(working_state, stage="collective_attach", payload={"status": COLLECTIVE_SIGNAL_STATUS_ATTACHED, "digest": pre_context_signals.get("digest")})
    working_state["state_hash"] = rebuild_state_hash(working_state)
    return working_state
