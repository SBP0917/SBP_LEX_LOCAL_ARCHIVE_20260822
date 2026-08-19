from __future__ import annotations

import re
from copy import deepcopy
from threading import RLock
from typing import Any, Mapping

from sbp_lex.runtime.measured_startup import ensure_measured_startup
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature


TRAVERSAL_RECEIPT_VERSION = "PASS7_RUNTIME_TRAVERSAL_RECEIPT_V1"
TRAVERSAL_RECEIPT_DOMAIN = "SBP_LEX_DESKTOP_V1_RUNTIME_TRAVERSAL_RECEIPT"
CANONICAL_RUNTIME_ID = "SBP_LEX_V1_CANONICAL_RUNTIME"

OPERATIONAL_TRAVERSAL = "OPERATIONAL_TRAVERSAL"
NON_OPERATIONAL_REPLAY = "NON_OPERATIONAL_REPLAY"
NON_OPERATIONAL_VALIDATION = "NON_OPERATIONAL_VALIDATION"
TRAVERSAL_RECEIPT_PURPOSES = frozenset(
    {
        OPERATIONAL_TRAVERSAL,
        NON_OPERATIONAL_REPLAY,
        NON_OPERATIONAL_VALIDATION,
    }
)
MEASURED_STARTUP_BINDING_FIELDS = (
    "runtime_identity",
    "approved_baseline_identifier",
    "measurement_digest",
    "startup_attestation_digest",
    "startup_sequence",
)

_COMMON_PAYLOAD_FIELDS = frozenset(
    {
        "receipt_version",
        "purpose",
        "runtime_id",
        "request_fingerprint",
        *MEASURED_STARTUP_BINDING_FIELDS,
    }
)
_OPERATIONAL_PAYLOAD_FIELDS = _COMMON_PAYLOAD_FIELDS | {
    "traversal_started_event_hash",
    "traversal_started_sequence",
    "request_id",
    "action",
}
_RECEIPT_FIELDS = frozenset({"payload", "receipt_digest", "signature"})
_RUNTIME_EVENT_FIELDS = frozenset(
    {
        "sequence",
        "timestamp",
        "timestamp_authority",
        "event_type",
        "payload",
        "previous_hash",
        "event_hash",
        "signature",
    }
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_OPERATIONAL_RECEIPT_CLAIMS = 4096
_OPERATIONAL_RECEIPT_CLAIMS: set[str] = set()
_OPERATIONAL_RECEIPT_CLAIMS_LOCK = RLock()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _valid_text(value: Any, *, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= maximum
    )


def _measurement_failures(measurement: object) -> list[str]:
    if not isinstance(measurement, Mapping):
        return ["measured_startup_record_invalid"]
    failures: list[str] = []
    if measurement.get("status") != "MEASURED_STARTUP_APPROVED":
        failures.append("measured_startup_not_approved")
    for field in (
        "runtime_identity",
        "measurement_digest",
        "startup_attestation_digest",
    ):
        if not _is_digest(measurement.get(field)):
            failures.append(f"measured_startup_binding_invalid:{field}")
    if not _valid_text(
        measurement.get("approved_baseline_identifier"), maximum=128
    ):
        failures.append(
            "measured_startup_binding_invalid:approved_baseline_identifier"
        )
    sequence = measurement.get("startup_sequence")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence <= 0
    ):
        failures.append("measured_startup_binding_invalid:startup_sequence")
    return failures


def _measurement_projection(measurement: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: deepcopy(measurement[field])
        for field in MEASURED_STARTUP_BINDING_FIELDS
    }


def _runtime_event_failures(
    event: object,
    *,
    request_id: str,
    request_fingerprint: str,
    action: str,
    measurement: Mapping[str, Any],
) -> list[str]:
    if not isinstance(event, Mapping) or set(event) != _RUNTIME_EVENT_FIELDS:
        return ["traversal_started_event_schema_invalid"]
    event_payload = event.get("payload")
    if not isinstance(event_payload, Mapping):
        return ["traversal_started_event_payload_invalid"]
    sequence = event.get("sequence")
    failures: list[str] = []
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence <= 0
    ):
        failures.append("traversal_started_event_sequence_invalid")
    expected_timestamp = (
        f"CHRONOLOGY_EVENT_{sequence:012d}"
        if isinstance(sequence, int) and not isinstance(sequence, bool)
        else None
    )
    if event.get("timestamp") != expected_timestamp:
        failures.append("traversal_started_event_timestamp_invalid")
    if event.get("timestamp_authority") != "CANONICAL_RUNTIME":
        failures.append("traversal_started_event_authority_invalid")
    if event.get("event_type") != "traversal_started":
        failures.append("traversal_started_event_type_invalid")
    expected_payload = {
        "request_id": request_id,
        "request_fingerprint": request_fingerprint,
        "action": action,
        **_measurement_projection(measurement),
    }
    if dict(event_payload) != expected_payload:
        failures.append("traversal_started_event_payload_mismatch")
    body = {
        key: deepcopy(value)
        for key, value in event.items()
        if key not in {"event_hash", "signature"}
    }
    if not _is_digest(event.get("event_hash")):
        failures.append("traversal_started_event_hash_invalid")
    elif event.get("event_hash") != generate_digest(body):
        failures.append("traversal_started_event_hash_mismatch")
    if not verify_signature(body, event.get("signature", {})):
        failures.append("traversal_started_event_signature_invalid")
    return failures


def _bound_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "integrity_domain": TRAVERSAL_RECEIPT_DOMAIN,
        "payload": deepcopy(dict(payload)),
    }


def build_traversal_receipt(
    *,
    purpose: str,
    request_fingerprint: str,
    measurement: Mapping[str, Any] | None = None,
    traversal_started_event: Mapping[str, Any] | None = None,
    request_id: str | None = None,
    action: str | None = None,
    runtime_id: str = CANONICAL_RUNTIME_ID,
) -> dict[str, Any]:
    """Build an exact signed operational or non-operational receipt.

    Operational receipts prove the canonical ``traversal_started`` event.
    Replay and validation receipts are deliberately non-operational and carry
    no request-specific event material that could be confused with authority.
    """

    if purpose not in TRAVERSAL_RECEIPT_PURPOSES:
        raise ValueError("runtime_traversal_receipt_purpose_invalid")
    if runtime_id != CANONICAL_RUNTIME_ID:
        raise ValueError("runtime_traversal_receipt_runtime_invalid")
    if not _is_digest(request_fingerprint):
        raise ValueError(
            "runtime_traversal_receipt_request_fingerprint_invalid"
        )
    current = measurement if measurement is not None else ensure_measured_startup()
    measurement_failures = _measurement_failures(current)
    if measurement_failures:
        raise ValueError(";".join(measurement_failures))
    if not isinstance(current, Mapping):
        raise ValueError("runtime_traversal_receipt_measurement_invalid")

    payload: dict[str, Any] = {
        "receipt_version": TRAVERSAL_RECEIPT_VERSION,
        "purpose": purpose,
        "runtime_id": runtime_id,
        "request_fingerprint": request_fingerprint,
        **_measurement_projection(current),
    }
    if purpose == OPERATIONAL_TRAVERSAL:
        if not _valid_text(request_id, maximum=256):
            raise ValueError("runtime_traversal_receipt_request_id_invalid")
        if not _valid_text(action, maximum=4096):
            raise ValueError("runtime_traversal_receipt_action_invalid")
        event_failures = _runtime_event_failures(
            traversal_started_event,
            request_id=str(request_id),
            request_fingerprint=request_fingerprint,
            action=str(action),
            measurement=current,
        )
        if event_failures:
            raise ValueError(";".join(event_failures))
        if not isinstance(traversal_started_event, Mapping):
            raise ValueError("runtime_traversal_receipt_event_invalid")
        payload.update(
            {
                "traversal_started_event_hash": traversal_started_event[
                    "event_hash"
                ],
                "traversal_started_sequence": traversal_started_event[
                    "sequence"
                ],
                "request_id": request_id,
                "action": action,
            }
        )
    elif any(
        value is not None
        for value in (traversal_started_event, request_id, action)
    ):
        raise ValueError("non_operational_receipt_event_material_forbidden")

    bound = _bound_payload(payload)
    return {
        "payload": payload,
        "receipt_digest": generate_digest(bound),
        "signature": sign_payload(bound),
    }


def verify_traversal_receipt(
    receipt: object,
    *,
    expected_purpose: str,
    expected_request_fingerprint: str | None = None,
    current_measurement: Mapping[str, Any] | None = None,
    traversal_started_event: Mapping[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Verify exact schema, signature, digest, purpose and live measurement."""

    try:
        failures: list[str] = []
        if expected_purpose not in TRAVERSAL_RECEIPT_PURPOSES:
            return False, ["runtime_traversal_receipt_expected_purpose_invalid"]
        if not isinstance(receipt, Mapping) or set(receipt) != _RECEIPT_FIELDS:
            return False, ["runtime_traversal_receipt_schema_invalid"]
        payload = receipt.get("payload")
        if not isinstance(payload, Mapping):
            return False, ["runtime_traversal_receipt_payload_invalid"]
        purpose = payload.get("purpose")
        expected_fields = (
            _OPERATIONAL_PAYLOAD_FIELDS
            if purpose == OPERATIONAL_TRAVERSAL
            else _COMMON_PAYLOAD_FIELDS
        )
        if set(payload) != expected_fields:
            failures.append("runtime_traversal_receipt_payload_schema_invalid")
        if payload.get("receipt_version") != TRAVERSAL_RECEIPT_VERSION:
            failures.append("runtime_traversal_receipt_version_invalid")
        if purpose != expected_purpose or purpose not in TRAVERSAL_RECEIPT_PURPOSES:
            failures.append("runtime_traversal_receipt_purpose_mismatch")
        if payload.get("runtime_id") != CANONICAL_RUNTIME_ID:
            failures.append("runtime_traversal_receipt_runtime_mismatch")
        request_fingerprint = payload.get("request_fingerprint")
        if not _is_digest(request_fingerprint):
            failures.append(
                "runtime_traversal_receipt_request_fingerprint_invalid"
            )
        if (
            expected_request_fingerprint is not None
            and request_fingerprint != expected_request_fingerprint
        ):
            failures.append(
                "runtime_traversal_receipt_request_fingerprint_mismatch"
            )

        bound = _bound_payload(payload)
        if not _is_digest(receipt.get("receipt_digest")):
            failures.append("runtime_traversal_receipt_digest_invalid")
        elif receipt.get("receipt_digest") != generate_digest(bound):
            failures.append("runtime_traversal_receipt_digest_mismatch")
        if not verify_signature(bound, receipt.get("signature", {})):
            failures.append("runtime_traversal_receipt_signature_invalid")

        measurement = (
            current_measurement
            if current_measurement is not None
            else ensure_measured_startup()
        )
        measurement_failures = _measurement_failures(measurement)
        failures.extend(measurement_failures)
        if isinstance(measurement, Mapping) and not measurement_failures:
            for field, expected in _measurement_projection(measurement).items():
                if payload.get(field) != expected:
                    failures.append(
                        f"runtime_traversal_receipt_measurement_mismatch:{field}"
                    )

        if purpose == OPERATIONAL_TRAVERSAL:
            sequence = payload.get("traversal_started_sequence")
            if (
                not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or sequence <= 0
            ):
                failures.append(
                    "runtime_traversal_receipt_event_sequence_invalid"
                )
            if not _is_digest(payload.get("traversal_started_event_hash")):
                failures.append("runtime_traversal_receipt_event_hash_invalid")
            if not _valid_text(payload.get("request_id"), maximum=256):
                failures.append("runtime_traversal_receipt_request_id_invalid")
            if not _valid_text(payload.get("action"), maximum=4096):
                failures.append("runtime_traversal_receipt_action_invalid")
            if traversal_started_event is not None and isinstance(
                measurement, Mapping
            ):
                event_failures = _runtime_event_failures(
                    traversal_started_event,
                    request_id=str(payload.get("request_id", "")),
                    request_fingerprint=str(request_fingerprint or ""),
                    action=str(payload.get("action", "")),
                    measurement=measurement,
                )
                failures.extend(event_failures)
                if (
                    traversal_started_event.get("event_hash")
                    != payload.get("traversal_started_event_hash")
                    or traversal_started_event.get("sequence")
                    != payload.get("traversal_started_sequence")
                ):
                    failures.append(
                        "runtime_traversal_receipt_event_binding_mismatch"
                    )
        elif traversal_started_event is not None:
            failures.append("non_operational_receipt_event_material_forbidden")
        return not failures, sorted(set(failures))
    except Exception:
        return False, ["runtime_traversal_receipt_structure_invalid"]


def claim_operational_traversal_receipt(
    receipt: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Atomically admit one operational receipt to one pipeline boundary."""

    payload = receipt.get("payload") if isinstance(receipt, Mapping) else None
    digest = receipt.get("receipt_digest") if isinstance(receipt, Mapping) else None
    if (
        not isinstance(payload, Mapping)
        or payload.get("purpose") != OPERATIONAL_TRAVERSAL
        or not _is_digest(digest)
    ):
        return False, ["operational_traversal_receipt_invalid"]
    with _OPERATIONAL_RECEIPT_CLAIMS_LOCK:
        if digest in _OPERATIONAL_RECEIPT_CLAIMS:
            return False, ["operational_traversal_receipt_replay_detected"]
        if len(_OPERATIONAL_RECEIPT_CLAIMS) >= (
            _MAX_OPERATIONAL_RECEIPT_CLAIMS
        ):
            return False, ["operational_traversal_receipt_capacity_exhausted"]
        _OPERATIONAL_RECEIPT_CLAIMS.add(str(digest))
    return True, []


__all__ = [
    "CANONICAL_RUNTIME_ID",
    "MEASURED_STARTUP_BINDING_FIELDS",
    "NON_OPERATIONAL_REPLAY",
    "NON_OPERATIONAL_VALIDATION",
    "OPERATIONAL_TRAVERSAL",
    "TRAVERSAL_RECEIPT_DOMAIN",
    "TRAVERSAL_RECEIPT_PURPOSES",
    "TRAVERSAL_RECEIPT_VERSION",
    "build_traversal_receipt",
    "claim_operational_traversal_receipt",
    "verify_traversal_receipt",
]
