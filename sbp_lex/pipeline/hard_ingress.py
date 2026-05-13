from __future__ import annotations

import time
from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, verify_signature

REQUIRED_REQUEST_FIELDS = [
    "action",
    "payload",
]

OPTIONAL_DECLARATION_FIELDS = [
    "resolved_authority",
    "jurisdiction",
    "context",
    "safety_profile",
    "classification",
    "manufacturer_declaration",
]

REQUIRED_SIGNAL_FIELDS = [
    "request_fingerprint",
    "intent_signal",
    "risk_potential_signal",
    "authority_link_signal",
    "jurisdiction_signal",
    "dependency_signal",
    "policy_conflict_signal",
    "operational_context_signal",
    "precedence_signal",
    "digest",
    "signature",
    "timestamp",
    "nonce",
]

MAX_SIGNAL_AGE_SECONDS = 300


def validate_request_ingress(request: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []

    if not isinstance(request, Mapping):
        return False, ["request_not_mapping"]

    for field in REQUIRED_REQUEST_FIELDS:
        if field not in request:
            failures.append(f"missing_request_field:{field}")

    action = request.get("action")
    if not isinstance(action, str) or not action.strip():
        failures.append("invalid_action")

    payload = request.get("payload")
    if payload is None or not isinstance(payload, Mapping):
        failures.append("invalid_payload")

    safety_profile = request.get("safety_profile", {})
    if safety_profile and not isinstance(safety_profile, Mapping):
        failures.append("invalid_safety_profile")

    context = request.get("context", {})
    if context and not isinstance(context, Mapping):
        failures.append("invalid_context")
}
