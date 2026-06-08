from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.api.schema_validation import validate_connector_envelope_schema

REQUIRED_ENVELOPE_FIELDS = ["request_id", "source", "request"]
MAX_REQUEST_ID_LENGTH = 128
MAX_SOURCE_LENGTH = 128


def build_connector_envelope(
    *,
    request_id: str,
    source: str,
    request: Mapping[str, Any],
    metadata: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = {
        "request_id": request_id,
        "source": source,
        "request": deepcopy(dict(request)),
        "metadata": deepcopy(dict(metadata or {})),
    }
    return {**payload, "digest": generate_digest(payload), "signature": sign_payload(payload)}


def validate_connector_envelope(envelope: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    schema_ok, schema_failures = validate_connector_envelope_schema(envelope)
    if not schema_ok:
        failures.extend(schema_failures)
    if not isinstance(envelope, Mapping):
        return False, failures or ["envelope_not_mapping"]
    for field in REQUIRED_ENVELOPE_FIELDS:
        if envelope.get(field) in (None, ""):
            failures.append(f"missing_envelope_field:{field}")
    if not isinstance(envelope.get("request_id"), str) or len(envelope.get("request_id", "")) > MAX_REQUEST_ID_LENGTH:
        failures.append("invalid_request_id")
    if not isinstance(envelope.get("source"), str) or len(envelope.get("source", "")) > MAX_SOURCE_LENGTH:
        failures.append("invalid_source")
    if not isinstance(envelope.get("request"), Mapping):
        failures.append("invalid_envelope_request")
    payload = {key: deepcopy(value) for key, value in dict(envelope).items() if key not in {"digest", "signature"}}
    if envelope.get("digest") != generate_digest(payload):
        failures.append("envelope_digest_mismatch")
    if not verify_signature(payload, envelope.get("signature", {})):
        failures.append("envelope_signature_invalid")
    return len(failures) == 0, failures
