from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


def prepare_skg_context(request: Mapping[str, Any]) -> Dict[str, Any]:
    context = deepcopy(dict(request.get("context", {}))) if isinstance(request.get("context", {}), Mapping) else {}
    authority_link_signal = {
        "resolved_authority": request.get("resolved_authority", context.get("resolved_authority", "UNRESOLVED")),
        "authority_declared": bool(request.get("resolved_authority") or context.get("resolved_authority")),
        "authority_source": context.get("authority_source", "request_or_context"),
    }
    jurisdiction_signal = {
        "jurisdiction": request.get("jurisdiction", context.get("jurisdiction", "UNRESOLVED")),
        "jurisdiction_declared": bool(request.get("jurisdiction") or context.get("jurisdiction")),
        "jurisdiction_source": context.get("jurisdiction_source", "request_or_context"),
    }
    policy_conflict_signal = {
        "conflict_detected": bool(context.get("policy_conflict_detected", False)),
        "conflict_reference": context.get("policy_conflict_reference"),
        "precedence_required": bool(context.get("policy_conflict_detected", False)),
    }
    precedence_signal = {
        "precedence_available": bool(context.get("precedence_available", False)),
        "precedence_reference": context.get("precedence_reference"),
        "temporal_rule_lineage": context.get("temporal_rule_lineage", []),
    }
    payload = {
        "authority_link_signal": authority_link_signal,
        "jurisdiction_signal": jurisdiction_signal,
        "policy_conflict_signal": policy_conflict_signal,
        "precedence_signal": precedence_signal,
    }
    return {**payload, "skg_digest": generate_digest(payload)}


def sign_skg_context(skg_context: Mapping[str, Any]) -> Dict[str, Any]:
    payload = dict(skg_context)
    return {**payload, "skg_signature": sign_payload(payload)}


def verify_skg_context(skg_context: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(skg_context, Mapping):
        return False, ["skg_context_not_mapping"]
    payload = {
        key: deepcopy(value)
        for key, value in dict(skg_context).items()
        if key not in {"skg_digest", "skg_signature"}
    }
    if skg_context.get("skg_digest") != generate_digest(payload):
        failures.append("skg_digest_mismatch")
    signed_payload = {**payload, "skg_digest": skg_context.get("skg_digest")}
    if not verify_signature(signed_payload, skg_context.get("skg_signature", {})):
        failures.append("skg_signature_invalid")
    authority = payload.get("authority_link_signal", {})
    jurisdiction = payload.get("jurisdiction_signal", {})
    if not authority.get("authority_declared"):
        failures.append("skg_authority_unresolved")
    if not jurisdiction.get("jurisdiction_declared"):
        failures.append("skg_jurisdiction_unresolved")
    return len(failures) == 0, failures
