from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, verify_signature
from sbp_lex.api.schema_validation import validate_runtime_request_schema

REQUIRED_REQUEST_FIELDS = ["action", "payload"]
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
    "timestamp_authority",
    "nonce",
]
CANONICAL_SIGNAL_AUTHORITY = "CANONICAL_RUNTIME"


def _canonical_signal_timestamp(request_fingerprint: str) -> int:
    return int(str(request_fingerprint)[:12], 16)


def _canonical_signal_nonce(request_fingerprint: str, timestamp: int) -> str:
    return generate_digest(
        {
            "request_fingerprint": request_fingerprint,
            "timestamp": timestamp,
            "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
        }
    )[:32]


def validate_request_ingress(request: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(request, Mapping):
        return False, ["request_not_mapping"]
    for field in REQUIRED_REQUEST_FIELDS:
        if field not in request:
            failures.append(f"missing_request_field:{field}")
    schema_ok, schema_failures = validate_runtime_request_schema(request)
    if not schema_ok:
        failures.extend(schema_failures)
    return len(failures) == 0, failures


def _signal_payload_for_digest(signals: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: deepcopy(value) for key, value in dict(signals).items() if key not in {"digest", "signature"}}


def validate_pre_context_signal_package(
    *,
    signals: Mapping[str, Any] | None,
    request_fingerprint: str,
    require_signature: bool = True,
) -> tuple[bool, list[str]]:
    if signals is None:
        return True, []
    failures: list[str] = []
    if not isinstance(signals, Mapping):
        return False, ["signals_not_mapping"]
    for field in REQUIRED_SIGNAL_FIELDS:
        if field not in signals:
            failures.append(f"missing_signal_field:{field}")
    if failures:
        return False, failures
    if signals.get("request_fingerprint") != request_fingerprint:
        failures.append("signal_request_fingerprint_mismatch")
    timestamp = signals.get("timestamp")
    if not isinstance(timestamp, int):
        failures.append("invalid_signal_timestamp")
    else:
        expected_timestamp = _canonical_signal_timestamp(request_fingerprint)
        if timestamp != expected_timestamp:
            failures.append("signal_timestamp_not_canonical")
    if signals.get("timestamp_authority") != CANONICAL_SIGNAL_AUTHORITY:
        failures.append("signal_timestamp_authority_invalid")
    expected_nonce = _canonical_signal_nonce(request_fingerprint, timestamp) if isinstance(timestamp, int) else None
    if not isinstance(signals.get("nonce"), str) or not signals.get("nonce", "").strip():
        failures.append("invalid_signal_nonce")
    elif expected_nonce is not None and signals.get("nonce") != expected_nonce:
        failures.append("signal_nonce_not_canonical")
    payload = _signal_payload_for_digest(signals)
    if signals.get("digest") != generate_digest(payload):
        failures.append("signal_digest_mismatch")
    if require_signature and not verify_signature(payload, signals.get("signature", {})):
        failures.append("signal_signature_invalid")
    return len(failures) == 0, failures


def run_hard_ingress(*, request: Mapping[str, Any], pre_context_signals: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_ok, request_failures = validate_request_ingress(request)
    request_fingerprint = generate_digest(dict(request)) if request_ok else ""
    signal_ok, signal_failures = validate_pre_context_signal_package(
        signals=pre_context_signals,
        request_fingerprint=request_fingerprint,
        require_signature=True,
    )
    return {
        "accepted": request_ok and signal_ok,
        "request_fingerprint": request_fingerprint,
        "request_failures": request_failures,
        "signal_failures": signal_failures,
        "failures": request_failures + signal_failures,
    }
