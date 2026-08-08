from __future__ import annotations

import json
import math
import re
import unicodedata
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Callable, Mapping, Sequence

from sbp_lex.api.schema_validation import loads_strict_json
from sbp_lex.execution.capability_store import CapabilityLifecycleStore, CapabilityStoreError
from sbp_lex.execution.execution_gate import evaluate_strict_execution_security
from sbp_lex.runtime.measured_startup import ensure_measured_startup
from sbp_lex.runtime.terminal_custody import terminal_custody_bindings
from sbp_lex.runtime.traversal_receipt import OPERATIONAL_TRAVERSAL
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.convergence import verify_convergence_proof

CAPABILITY_VERSION = "H7_EXECUTION_CAPABILITY_V2"
ATTESTATION_VERSION = "H7_POST_EXECUTION_ATTESTATION_V2"
TRAVERSAL_AUTHORITY_VERSION = "H7_EXECUTION_TRAVERSAL_AUTHORITY_V2"
COMPLETION_EVIDENCE_VERSION = "H7_ADAPTER_COMPLETION_EVIDENCE_V2"
ISSUER = "SBP_LEX_DESKTOP_V1_EXECUTION_INTEGRITY"
CANONICAL_RUNTIME_ID = "SBP_LEX_V1_CANONICAL_RUNTIME"
LOCAL_EXECUTION_CONSUMER_ID = "SBP_LEX_DESKTOP_V1_LOCAL_EXECUTION_SERVICE"
CAPABILITY_DOMAIN = "SBP_LEX_DESKTOP_V1_SINGLE_USE_EXECUTION_CAPABILITY"
ATTESTATION_DOMAIN = "SBP_LEX_DESKTOP_V1_POST_EXECUTION_ATTESTATION"
CONTROL_DOMAIN = "SBP_LEX_DESKTOP_V1_EXECUTION_CAPABILITY_CONTROL"
TRAVERSAL_AUTHORITY_DOMAIN = "SBP_LEX_DESKTOP_V1_EXECUTION_TRAVERSAL_AUTHORITY"
COMPLETION_EVIDENCE_DOMAIN = "SBP_LEX_DESKTOP_V1_ADAPTER_COMPLETION_EVIDENCE"
CONFIRMED_LOCAL_EFFECT_STATUSES = frozenset({
    "DONE",
    "OK",
    "SUCCESS",
    "SUCCEEDED",
    "COMPLETED",
    "CONFIRMED",
    "CONFIRMED_SUCCESS",
})
STATES = frozenset({
    "PENDING", "ACTIVE", "RESERVED", "EXECUTING", "COMPLETED", "CANCELLED",
    "EXPIRED", "REVOKED", "FAILED", "AMBIGUOUS", "RETIRED",
})
TERMINAL_STATES = frozenset({"COMPLETED", "CANCELLED", "EXPIRED", "REVOKED", "FAILED", "AMBIGUOUS", "RETIRED"})
TRANSITIONS = {
    "PENDING": frozenset({"ACTIVE", "CANCELLED"}),
    "ACTIVE": frozenset({"RESERVED", "CANCELLED", "EXPIRED", "REVOKED"}),
    "RESERVED": frozenset({"EXECUTING", "CANCELLED", "REVOKED", "EXPIRED"}),
    "EXECUTING": frozenset({"EXECUTING", "COMPLETED", "FAILED", "AMBIGUOUS", "CANCELLED"}),
    "COMPLETED": frozenset({"RETIRED"}),
    "CANCELLED": frozenset({"RETIRED"}),
    "EXPIRED": frozenset({"RETIRED"}),
    "REVOKED": frozenset({"RETIRED"}),
    "FAILED": frozenset({"RETIRED"}),
    "AMBIGUOUS": frozenset({"RETIRED"}),
    "RETIRED": frozenset(),
}
MAX_PARAMETER_BYTES = 65_536
MAX_PARAMETER_DEPTH = 16
MAX_PARAMETER_ITEMS = 2_048
PIPELINE_MODES = frozenset({
    "MODE_1_FULL_MIRRORED",
    "MODE_2_SPLIT_VALIDATOR",
    "MODE_3_SINGLE_CONSTRAINED",
})
MEASURED_STARTUP_BINDING_FIELDS = frozenset({
    "runtime_identity",
    "approved_baseline_identifier",
    "measurement_digest",
    "startup_attestation_digest",
    "startup_sequence",
})
CAPABILITY_FIELDS = frozenset({
    "capability_version", "capability_id", "request_id", "request_fingerprint",
    "traversal_authority_digest", "issuance_authority_key",
    "eie_identifier", "eie_digest", "canonical_state_hash", "pipeline_mode",
    "pipeline_a_result_digest", "pipeline_b_result_digest", "convergence_result",
    "procedural_truth_token", "classification_token", "licensing_token",
    "governance_token", "grc_token", "domain_token", "aurion_result",
    "target_identity", "target_type", "operation_identity", "canonical_parameter_digest",
    "execution_specification_id", "execution_specification_digest",
    "constraint_digest", "constraint_snapshot", "issued_at", "not_before", "expires_at",
    "reservation_timeout_seconds", "execution_start_deadline", "maximum_execution_seconds",
    "completion_report_deadline", "maximum_attempts", "consumption_state",
    "cancellation_state", "safe_cancellation_supported", "issuer_identity",
    "runtime_identity", "approved_baseline_identifier", "measurement_digest",
    "startup_attestation_digest", "startup_sequence",
    "execution_adapter_identity", "execution_consumer_identity", "audit_lineage_identifier",
    "capability_digest", "integrity_binding",
})
ATTESTATION_PAYLOAD_FIELDS = frozenset({
    "attestation_version", "attestation_id", "capability_id", "request_id",
    "request_fingerprint", "traversal_authority_digest", "capability_digest",
    "eie_digest", "canonical_state_hash", "target_identity", "operation_identity",
    "parameter_digest", "constraint_digest", "pipeline_mode", "convergence_digest",
    "execution_start", "execution_finish", "completion_classification", "result_digest",
    "adapter_identity", "runtime_identity", "approved_baseline_identifier",
    "measurement_digest", "startup_attestation_digest", "startup_sequence",
    "audit_lineage_identifier", "completion_evidence", "completion_evidence_digest",
    "completion_evidence_valid",
    "previous_attestation_hash",
})
ATTESTATION_CLASSIFICATIONS = frozenset({"COMPLETED", "FAILED", "CANCELLED", "AMBIGUOUS"})
CONTROL_FIELDS = frozenset({
    "authorization_version", "capability_id", "action", "actor_id", "reason_digest",
    "authorized_at", "expires_at",
})
TRAVERSAL_AUTHORITY_FIELDS = frozenset({
    "authority_version", "runtime_id", "request_id", "request_fingerprint",
    "eie_identifier", "eie_digest", "canonical_state_hash", "pipeline_mode",
    "convergence_result", "audit_lineage_identifier",
    "runtime_identity", "approved_baseline_identifier", "measurement_digest",
    "startup_attestation_digest", "startup_sequence",
    "traversal_started_event_hash", "traversal_started_sequence",
    "traversal_completed_event_hash", "traversal_completed_sequence",
    "terminal_custody_version", "terminal_state_digest",
    "terminal_seal_digest",
})
COMPLETION_EVIDENCE_FIELDS = frozenset({
    "evidence_version", "capability_id", "request_fingerprint",
    "traversal_authority_digest", "capability_digest", "eie_digest",
    "canonical_state_hash", "target_identity", "operation_identity",
    "parameter_digest", "result_digest", "adapter_identity", "observed_at",
    "runtime_identity", "approved_baseline_identifier", "measurement_digest",
    "startup_attestation_digest", "startup_sequence", "audit_lineage_identifier",
    "completion_status",
})
_CONTEXT_FIELDS = (
    "request_id", "request_fingerprint", "eie_identifier", "eie_digest",
    "canonical_state_hash", "pipeline_mode", "pipeline_a_result_digest",
    "pipeline_b_result_digest", "convergence_result", "procedural_truth_token",
    "classification_token", "licensing_token", "governance_token", "grc_token",
    "domain_token", "aurion_result", "target_identity", "target_type",
    "operation_identity", "canonical_parameter_digest", "constraint_digest",
    "constraint_snapshot", "runtime_identity", "approved_baseline_identifier",
    "measurement_digest", "startup_attestation_digest", "startup_sequence",
    "execution_adapter_identity", "audit_lineage_identifier",
)
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SECRET_KEY = re.compile(
    r"(?:password|secret|api[_-]?key|authorization|credential|private[_-]?key|key[_-]?material)",
    re.IGNORECASE,
)
EXECUTION_SPECIFICATION_DOMAIN = "SBP_LEX_DESKTOP_V1_EXECUTION_SPECIFICATION"


class ExecutionIntegrityError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = str(reason)
        payload = {
            "evidence_version": "H7_EXECUTION_DENIAL_EVIDENCE_V1",
            "decision": "DENY",
            "execution_result": "HALT",
            "reason": self.reason,
        }
        self.evidence = {**payload, "evidence_hash": generate_digest(payload)}
        super().__init__(self.reason)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ExecutionIntegrityError("timezone_aware_timestamp_required")
    return value.astimezone(timezone.utc)


def _text(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        current = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return current.astimezone(timezone.utc) if current.tzinfo else None


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _valid_request_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= 256
    )


def _valid_baseline_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= 128
    )


def _require_measured_startup_binding(
    measurement: Mapping[str, Any],
) -> dict[str, Any]:
    validators = {
        "runtime_identity": _is_digest,
        "approved_baseline_identifier": _valid_baseline_identifier,
        "measurement_digest": _is_digest,
        "startup_attestation_digest": _is_digest,
        "startup_sequence": lambda value: (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value > 0
        ),
    }
    for field in MEASURED_STARTUP_BINDING_FIELDS:
        if not validators[field](measurement.get(field)):
            raise ExecutionIntegrityError(
                f"measured_startup_binding_missing:{field}"
            )
    return {
        field: deepcopy(measurement[field])
        for field in MEASURED_STARTUP_BINDING_FIELDS
    }


def _measure(value: Any, depth: int = 1) -> int:
    if depth > MAX_PARAMETER_DEPTH:
        raise ExecutionIntegrityError("parameter_nesting_limit_exceeded")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ExecutionIntegrityError("parameter_key_must_be_string")
        count = len(value) + sum(_measure(item, depth + 1) for item in value.values())
    elif isinstance(value, list):
        count = len(value) + sum(_measure(item, depth + 1) for item in value)
    elif value is None or isinstance(value, (str, bool, int)):
        count = 1
    elif isinstance(value, float) and math.isfinite(value):
        count = 1
    else:
        raise ExecutionIntegrityError("unsupported_parameter_type")
    if count > MAX_PARAMETER_ITEMS:
        raise ExecutionIntegrityError("parameter_item_limit_exceeded")
    return count


def _normalise_parameter_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise ExecutionIntegrityError("parameter_key_must_be_string")
            key = unicodedata.normalize("NFC", raw_key)
            if key in result:
                raise ExecutionIntegrityError("parameter_key_collision_after_normalization")
            result[key] = _normalise_parameter_value(item)
        return result
    if isinstance(value, list):
        return [_normalise_parameter_value(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ExecutionIntegrityError("unsupported_parameter_type")


def _reject_secret_bearing_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_KEY.search(key):
                raise ExecutionIntegrityError("secret_bearing_execution_field_denied")
            _reject_secret_bearing_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_bearing_keys(item)


def canonical_parameters(
    value: str | Mapping[str, Any], *, allowed_fields: Sequence[str],
    required_fields: Sequence[str] = (),
) -> dict[str, Any]:
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="strict")) > MAX_PARAMETER_BYTES:
            raise ExecutionIntegrityError("parameter_package_oversized")
        try:
            parsed = loads_strict_json(value)
        except Exception as exc:
            raise ExecutionIntegrityError("parameter_json_invalid") from exc
    elif isinstance(value, Mapping):
        parsed = deepcopy(dict(value))
    else:
        raise ExecutionIntegrityError("parameters_not_object")
    if not isinstance(parsed, dict):
        raise ExecutionIntegrityError("parameters_not_object")
    parsed = _normalise_parameter_value(parsed)
    allowed = tuple(unicodedata.normalize("NFC", field) if isinstance(field, str) else field for field in allowed_fields)
    required = tuple(unicodedata.normalize("NFC", field) if isinstance(field, str) else field for field in required_fields)
    if not allowed or any(not isinstance(field, str) or not field for field in allowed):
        raise ExecutionIntegrityError("parameter_allowlist_required")
    if len(set(allowed)) != len(allowed):
        raise ExecutionIntegrityError("parameter_allowlist_duplicate")
    if any(not isinstance(field, str) or not field for field in required):
        raise ExecutionIntegrityError("required_parameter_field_invalid")
    if not set(required).issubset(allowed):
        raise ExecutionIntegrityError("required_parameter_not_allowed")
    unknown = set(parsed) - set(allowed)
    if unknown:
        raise ExecutionIntegrityError("unknown_parameter:" + ",".join(sorted(unknown)))
    missing = set(required) - set(parsed)
    if missing:
        raise ExecutionIntegrityError("missing_required_parameter:" + ",".join(sorted(missing)))
    _measure(parsed)
    encoded = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_PARAMETER_BYTES:
        raise ExecutionIntegrityError("parameter_package_oversized")
    return json.loads(encoded)


def validate_target(target_identity: Any, target_type: Any) -> tuple[str, str]:
    if (
        not isinstance(target_identity, str)
        or target_identity != target_identity.strip()
        or _IDENTITY.fullmatch(target_identity) is None
    ):
        raise ExecutionIntegrityError("target_identity_invalid")
    if (
        not isinstance(target_type, str)
        or target_type != target_type.strip()
        or _IDENTITY.fullmatch(target_type) is None
    ):
        raise ExecutionIntegrityError("target_type_invalid")
    return target_identity, target_type


def _terminal_state_binding(state: Mapping[str, Any]) -> str | None:
    """Return the signed digest of the complete terminal pre-seal state."""

    try:
        custody = terminal_custody_bindings(state, require=True)
    except (TypeError, ValueError):
        return None
    digest = custody.get("terminal_state_digest") if custody else None
    return str(digest) if _is_digest(digest) else None


def _operational_receipt_payload(
    state: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    receipt = state.get("runtime_traversal_receipt")
    payload = receipt.get("payload") if isinstance(receipt, Mapping) else None
    return (
        payload
        if isinstance(payload, Mapping)
        and payload.get("purpose") == OPERATIONAL_TRAVERSAL
        else None
    )


def build_execution_traversal_authority(
    state: Mapping[str, Any], *, runtime_id: str, request_id: str,
    traversal_started_event: Mapping[str, Any],
    traversal_completed_event: Mapping[str, Any],
) -> dict[str, Any]:
    security = evaluate_strict_execution_security(state)
    if not security["valid"] or not security["allowed"]:
        raise ExecutionIntegrityError("canonical_execution_authority_invalid")
    if not isinstance(state.get("audit_record"), Mapping) or not state.get("audit_hash"):
        raise ExecutionIntegrityError("final_audit_lineage_required")
    if not isinstance(state.get("controlled_outcome"), Mapping):
        raise ExecutionIntegrityError("controlled_outcome_required")
    convergence = state.get("pipeline_convergence")
    if not isinstance(convergence, Mapping) or not verify_convergence_proof(convergence):
        raise ExecutionIntegrityError("pipeline_convergence_integrity_invalid")
    if convergence.get("matched") is not True or convergence.get("verified") is not True:
        raise ExecutionIntegrityError("pipeline_convergence_not_valid")
    if runtime_id != CANONICAL_RUNTIME_ID:
        raise ExecutionIntegrityError("canonical_runtime_identity_invalid")
    if (
        not isinstance(request_id, str)
        or not request_id
        or request_id != request_id.strip()
        or len(request_id) > 256
    ):
        raise ExecutionIntegrityError("request_id_required")
    measurement = ensure_measured_startup()
    if measurement.get("status") != "MEASURED_STARTUP_APPROVED":
        raise ExecutionIntegrityError("measured_startup_not_approved")
    measured_binding = _require_measured_startup_binding(measurement)
    try:
        custody_bindings = terminal_custody_bindings(state, require=True)
    except (TypeError, ValueError) as exc:
        raise ExecutionIntegrityError(
            "terminal_state_custody_invalid"
        ) from exc
    if custody_bindings is None:  # pragma: no cover - require=True
        raise ExecutionIntegrityError("terminal_state_custody_invalid")
    if not _verify_runtime_event(
        traversal_started_event, event_type="traversal_started",
        required_payload={
            "request_id": request_id,
            "request_fingerprint": state.get("request_fingerprint"),
            "action": state.get("action"),
            **measured_binding,
        },
    ):
        raise ExecutionIntegrityError("traversal_started_evidence_invalid")
    if not _verify_runtime_event(
        traversal_completed_event, event_type="traversal_completed",
        required_payload={
            "request_id": request_id,
            "request_fingerprint": state.get("request_fingerprint"),
            "decision": state.get("decision"),
            "execution_result": state.get("execution_result"),
            "pipeline_mode": state.get("pipeline_mode"),
            "audit_hash": state.get("audit_hash"),
            "traversal_started_event_hash": traversal_started_event.get("event_hash"),
            **custody_bindings,
        },
    ):
        raise ExecutionIntegrityError("traversal_completed_evidence_invalid")
    completed_payload = traversal_completed_event.get("payload")
    if (
        not isinstance(completed_payload, Mapping)
        or any(
            not _is_digest(completed_payload.get(field))
            for field in (
                "replay_ledger_hash", "persistence_record_hash",
                "terminal_state_digest", "terminal_seal_digest",
            )
        )
    ):
        raise ExecutionIntegrityError("traversal_completed_evidence_invalid")
    if int(traversal_completed_event["sequence"]) <= int(traversal_started_event["sequence"]):
        raise ExecutionIntegrityError("traversal_event_order_invalid")
    receipt_payload = _operational_receipt_payload(state)
    if receipt_payload is None:
        raise ExecutionIntegrityError(
            "operational_runtime_traversal_receipt_required"
        )
    expected_receipt = {
        "runtime_id": runtime_id,
        "request_id": request_id,
        "request_fingerprint": state.get("request_fingerprint"),
        "action": state.get("action"),
        "traversal_started_event_hash": traversal_started_event.get(
            "event_hash"
        ),
        "traversal_started_sequence": traversal_started_event.get(
            "sequence"
        ),
        **measured_binding,
    }
    if any(
        receipt_payload.get(field) != value
        for field, value in expected_receipt.items()
    ):
        raise ExecutionIntegrityError(
            "operational_runtime_traversal_receipt_mismatch"
        )
    payload = {
        "authority_version": TRAVERSAL_AUTHORITY_VERSION,
        "runtime_id": runtime_id,
        "request_id": request_id,
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_identifier": state.get("traversal_id"),
        "eie_digest": state.get("eie_hash"),
        "canonical_state_hash": custody_bindings[
            "terminal_state_digest"
        ],
        "pipeline_mode": state.get("pipeline_mode"),
        "convergence_result": convergence.get("convergence_hash"),
        "audit_lineage_identifier": state.get("audit_hash"),
        "runtime_identity": measurement["runtime_identity"],
        "approved_baseline_identifier": measurement["approved_baseline_identifier"],
        "measurement_digest": measurement["measurement_digest"],
        "startup_attestation_digest": measurement[
            "startup_attestation_digest"
        ],
        "startup_sequence": measurement["startup_sequence"],
        "traversal_started_event_hash": traversal_started_event.get("event_hash"),
        "traversal_started_sequence": traversal_started_event.get("sequence"),
        "traversal_completed_event_hash": traversal_completed_event.get("event_hash"),
        "traversal_completed_sequence": traversal_completed_event.get("sequence"),
        **custody_bindings,
    }
    string_fields = TRAVERSAL_AUTHORITY_FIELDS - {
        "authority_version", "startup_sequence",
        "traversal_started_sequence", "traversal_completed_sequence",
    }
    if any(not isinstance(payload[field], str) or not payload[field] for field in string_fields):
        raise ExecutionIntegrityError("execution_traversal_authority_incomplete")
    bound = {"integrity_domain": TRAVERSAL_AUTHORITY_DOMAIN, "payload": payload}
    return {
        "payload": payload,
        "authority_digest": generate_digest(bound),
        "integrity_binding": sign_payload(bound),
    }


def _verify_runtime_event(
    event: Mapping[str, Any], *, event_type: str,
    required_payload: Mapping[str, Any],
) -> bool:
    if not isinstance(event, Mapping) or not isinstance(event.get("payload"), Mapping):
        return False
    body = {key: deepcopy(value) for key, value in event.items() if key not in {"event_hash", "signature"}}
    payload = event["payload"]
    return (
        isinstance(event.get("sequence"), int)
        and not isinstance(event.get("sequence"), bool)
        and event["sequence"] > 0
        and event.get("event_type") == event_type
        and all(payload.get(key) == value for key, value in required_payload.items())
        and _is_digest(event.get("event_hash"))
        and event.get("event_hash") == generate_digest(body)
        and verify_signature(body, event.get("signature", {}))
    )


def verify_execution_traversal_authority(
    authority: Mapping[str, Any], state: Mapping[str, Any],
) -> bool:
    if not isinstance(authority, Mapping) or set(authority) != {"payload", "authority_digest", "integrity_binding"}:
        return False
    payload = authority.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != TRAVERSAL_AUTHORITY_FIELDS:
        return False
    try:
        custody_bindings = terminal_custody_bindings(state, require=True)
    except (TypeError, ValueError):
        return False
    if custody_bindings is None:  # pragma: no cover - require=True
        return False
    expected = {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_identifier": state.get("traversal_id"),
        "eie_digest": state.get("eie_hash"),
        "canonical_state_hash": custody_bindings[
            "terminal_state_digest"
        ],
        "pipeline_mode": state.get("pipeline_mode"),
        "convergence_result": state.get("pipeline_convergence", {}).get("convergence_hash"),
        "audit_lineage_identifier": state.get("audit_hash"),
        **custody_bindings,
    }
    receipt_payload = _operational_receipt_payload(state)
    if receipt_payload is None:
        return False
    expected.update(
        {
            "runtime_id": receipt_payload.get("runtime_id"),
            "request_id": receipt_payload.get("request_id"),
            "runtime_identity": receipt_payload.get("runtime_identity"),
            "approved_baseline_identifier": receipt_payload.get(
                "approved_baseline_identifier"
            ),
            "measurement_digest": receipt_payload.get(
                "measurement_digest"
            ),
            "startup_attestation_digest": receipt_payload.get(
                "startup_attestation_digest"
            ),
            "startup_sequence": receipt_payload.get("startup_sequence"),
            "traversal_started_event_hash": receipt_payload.get(
                "traversal_started_event_hash"
            ),
            "traversal_started_sequence": receipt_payload.get(
                "traversal_started_sequence"
            ),
        }
    )
    if payload.get("authority_version") != TRAVERSAL_AUTHORITY_VERSION:
        return False
    if payload.get("runtime_id") != CANONICAL_RUNTIME_ID:
        return False
    if (
        not isinstance(payload.get("traversal_started_sequence"), int)
        or isinstance(payload.get("traversal_started_sequence"), bool)
        or not isinstance(payload.get("traversal_completed_sequence"), int)
        or isinstance(payload.get("traversal_completed_sequence"), bool)
        or payload["traversal_started_sequence"] <= 0
        or payload["traversal_completed_sequence"] <= payload["traversal_started_sequence"]
    ):
        return False
    if (
        not _valid_request_id(payload.get("request_id"))
        or not isinstance(payload.get("eie_identifier"), str)
        or not payload.get("eie_identifier")
        or payload.get("eie_identifier") != payload.get("eie_identifier").strip()
        or payload.get("pipeline_mode") not in PIPELINE_MODES
        or not _valid_baseline_identifier(
            payload.get("approved_baseline_identifier")
        )
        or not isinstance(payload.get("startup_sequence"), int)
        or isinstance(payload.get("startup_sequence"), bool)
        or payload.get("startup_sequence", 0) <= 0
    ):
        return False
    digest_fields = (
        "request_fingerprint", "eie_digest", "canonical_state_hash",
        "convergence_result", "audit_lineage_identifier", "runtime_identity",
        "measurement_digest", "startup_attestation_digest",
        "traversal_started_event_hash", "traversal_completed_event_hash",
        "terminal_state_digest", "terminal_seal_digest",
    )
    if any(not _is_digest(payload.get(field)) for field in digest_fields):
        return False
    if any(payload.get(field) != value for field, value in expected.items()):
        return False
    bound = {"integrity_domain": TRAVERSAL_AUTHORITY_DOMAIN, "payload": dict(payload)}
    return (
        _is_digest(authority.get("authority_digest"))
        and authority.get("authority_digest") == generate_digest(bound)
        and verify_signature(bound, authority.get("integrity_binding", {}))
    )


def _token_digest(state: Mapping[str, Any], name: str) -> str:
    tokens = state.get("tokens", {})
    if not isinstance(tokens, Mapping):
        raise ExecutionIntegrityError("required_token_store_invalid")
    value = tokens.get(name, {})
    digest = value.get("digest") if isinstance(value, Mapping) else None
    if not isinstance(digest, str) or not digest:
        raise ExecutionIntegrityError(f"required_token_missing:{name}")
    return digest


def binding_context(
    state: Mapping[str, Any], *, request_id: str, target_identity: str, target_type: str,
    operation_identity: str, parameters: str | Mapping[str, Any],
    allowed_parameter_fields: Sequence[str], required_parameter_fields: Sequence[str] = (),
    constraints: Mapping[str, Any],
    adapter_identity: str,
) -> dict[str, Any]:
    security = evaluate_strict_execution_security(state)
    if not security["valid"] or not security["allowed"]:
        raise ExecutionIntegrityError("canonical_execution_authority_invalid")
    target, kind = validate_target(target_identity, target_type)
    if (
        not isinstance(request_id, str)
        or not request_id
        or request_id != request_id.strip()
        or len(request_id) > 256
    ):
        raise ExecutionIntegrityError("request_id_required")
    if not isinstance(operation_identity, str) or _IDENTITY.fullmatch(operation_identity) is None:
        raise ExecutionIntegrityError("operation_identity_invalid")
    if not isinstance(adapter_identity, str) or _IDENTITY.fullmatch(adapter_identity) is None:
        raise ExecutionIntegrityError("adapter_identity_invalid")
    canonical = canonical_parameters(
        parameters, allowed_fields=allowed_parameter_fields,
        required_fields=required_parameter_fields,
    )
    constraint_copy = deepcopy(dict(constraints)) if isinstance(constraints, Mapping) else None
    if constraint_copy is None or not constraint_copy:
        raise ExecutionIntegrityError("execution_constraints_required")
    _measure(constraint_copy)
    _reject_secret_bearing_keys(constraint_copy)
    convergence = state.get("pipeline_convergence", {})
    if (
        not isinstance(convergence, Mapping)
        or convergence.get("matched") is not True
        or convergence.get("verified") is not True
        or not verify_convergence_proof(convergence)
    ):
        raise ExecutionIntegrityError("pipeline_convergence_not_valid")
    pipeline_a = convergence.get("pipeline_a")
    pipeline_b = convergence.get("pipeline_b")
    mode = state.get("pipeline_mode")
    if convergence.get("mode") != mode:
        raise ExecutionIntegrityError("pipeline_mode_convergence_mismatch")
    if not isinstance(pipeline_a, Mapping):
        raise ExecutionIntegrityError("pipeline_a_result_missing")
    for field in ("request_fingerprint", "state_hash", "pipeline_mode", "audit_hash"):
        if pipeline_a.get(field) != state.get(field):
            raise ExecutionIntegrityError(f"pipeline_a_state_mismatch:{field}")
    if mode != "MODE_3_SINGLE_CONSTRAINED" and not isinstance(pipeline_b, Mapping):
        raise ExecutionIntegrityError("pipeline_b_result_missing")
    measurement = ensure_measured_startup()
    if measurement.get("status") != "MEASURED_STARTUP_APPROVED":
        raise ExecutionIntegrityError("measured_startup_not_approved")
    measured_binding = _require_measured_startup_binding(measurement)
    critical = {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_identifier": state.get("traversal_id"),
        "eie_digest": state.get("eie_hash"),
        "canonical_state_hash": _terminal_state_binding(state),
        "audit_lineage_identifier": state.get("audit_hash"),
    }
    if any(not isinstance(value, str) or not value for value in critical.values()):
        raise ExecutionIntegrityError("canonical_execution_binding_incomplete")
    return {
        "request_id": request_id,
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_identifier": state.get("traversal_id"),
        "eie_digest": state.get("eie_hash"),
        "canonical_state_hash": _terminal_state_binding(state),
        "pipeline_mode": mode,
        "pipeline_a_result_digest": generate_digest(pipeline_a),
        "pipeline_b_result_digest": generate_digest(pipeline_b) if pipeline_b is not None else None,
        "convergence_result": convergence.get("convergence_hash"),
        "procedural_truth_token": _token_digest(state, "procedural_truth"),
        "classification_token": _token_digest(state, "classification"),
        "licensing_token": _token_digest(state, "licensing"),
        "governance_token": _token_digest(state, "governance"),
        "grc_token": _token_digest(state, "grc"),
        "domain_token": _token_digest(state, "domain"),
        "aurion_result": generate_digest({
            "aurion_result": state.get("aurion15_result"),
            "aurion_token": _token_digest(state, "aurion"),
            "candidate": state.get("current_candidate", {}),
        }),
        "target_identity": target,
        "target_type": kind,
        "operation_identity": operation_identity,
        "canonical_parameter_digest": generate_digest(canonical),
        "constraint_digest": generate_digest(constraint_copy),
        "constraint_snapshot": constraint_copy,
        **measured_binding,
        "execution_adapter_identity": adapter_identity,
        "audit_lineage_identifier": state.get("audit_hash"),
    }


def constraints_preserved(original: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    if not isinstance(current, Mapping) or set(original) != set(current):
        return False
    for key, expected in original.items():
        actual = current.get(key)
        if key.startswith("max_") and isinstance(expected, (int, float)) and not isinstance(expected, bool):
            if not isinstance(actual, (int, float)) or isinstance(actual, bool) or actual > expected:
                return False
        elif key.startswith("min_") and isinstance(expected, (int, float)) and not isinstance(expected, bool):
            if not isinstance(actual, (int, float)) or isinstance(actual, bool) or actual < expected:
                return False
        elif key.startswith("allowed_") and isinstance(expected, list):
            if not isinstance(actual, list):
                return False
            try:
                expected_values = {json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False) for item in expected}
                actual_values = {json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False) for item in actual}
            except (TypeError, ValueError):
                return False
            if not actual_values.issubset(expected_values):
                return False
        elif isinstance(expected, bool):
            if actual is not expected:
                return False
        elif actual != expected:
            return False
    return True


class ExecutionSpecification:
    def __init__(
        self, *, specification_id: str, target_identity: str, target_type: str,
        operation_identity: str, allowed_parameter_fields: Sequence[str],
        required_parameter_fields: Sequence[str], constraints: Mapping[str, Any],
        adapter_identity: str, safe_cancellation_supported: bool = False,
    ) -> None:
        target, kind = validate_target(target_identity, target_type)
        if not isinstance(specification_id, str) or _IDENTITY.fullmatch(specification_id) is None:
            raise ExecutionIntegrityError("execution_specification_id_invalid")
        if not isinstance(operation_identity, str) or _IDENTITY.fullmatch(operation_identity) is None:
            raise ExecutionIntegrityError("operation_identity_invalid")
        if not isinstance(adapter_identity, str) or _IDENTITY.fullmatch(adapter_identity) is None:
            raise ExecutionIntegrityError("adapter_identity_invalid")
        allowed = tuple(allowed_parameter_fields)
        required = tuple(required_parameter_fields)
        if (
            not allowed
            or any(not isinstance(field, str) or not field for field in allowed)
            or len(set(allowed)) != len(allowed)
            or any(not isinstance(field, str) or not field for field in required)
            or not set(required).issubset(allowed)
            or not isinstance(safe_cancellation_supported, bool)
        ):
            raise ExecutionIntegrityError("execution_parameter_policy_invalid")
        constraint_copy = deepcopy(dict(constraints)) if isinstance(constraints, Mapping) else None
        if not constraint_copy:
            raise ExecutionIntegrityError("execution_constraints_required")
        _measure(constraint_copy)
        _reject_secret_bearing_keys(constraint_copy)
        self._payload = {
            "specification_version": "H7_EXECUTION_SPECIFICATION_V1",
            "specification_id": specification_id,
            "target_identity": target,
            "target_type": kind,
            "operation_identity": operation_identity,
            "allowed_parameter_fields": list(allowed),
            "required_parameter_fields": list(required),
            "constraints": constraint_copy,
            "adapter_identity": adapter_identity,
            "safe_cancellation_supported": safe_cancellation_supported,
        }
        self.digest = generate_digest({
            "integrity_domain": EXECUTION_SPECIFICATION_DOMAIN,
            "payload": self._payload,
        })

    @property
    def specification_id(self) -> str:
        return str(self._payload["specification_id"])

    def payload(self) -> dict[str, Any]:
        return deepcopy(self._payload)


def verify_capability(capability: Mapping[str, Any]) -> bool:
    if not isinstance(capability, Mapping) or set(capability) != CAPABILITY_FIELDS:
        return False
    if (
        capability.get("capability_version") != CAPABILITY_VERSION
        or capability.get("issuer_identity") != ISSUER
        or capability.get("execution_consumer_identity")
        != LOCAL_EXECUTION_CONSUMER_ID
        or capability.get("maximum_attempts") != 1
        or capability.get("consumption_state") != "UNCONSUMED"
        or capability.get("cancellation_state") != "NOT_CANCELLED"
        or not isinstance(capability.get("safe_cancellation_supported"), bool)
        or not _valid_request_id(capability.get("request_id"))
        or not isinstance(capability.get("eie_identifier"), str)
        or not capability.get("eie_identifier")
        or capability.get("eie_identifier")
        != capability.get("eie_identifier").strip()
        or capability.get("pipeline_mode") not in PIPELINE_MODES
        or not _valid_baseline_identifier(
            capability.get("approved_baseline_identifier")
        )
        or not isinstance(capability.get("startup_sequence"), int)
        or isinstance(capability.get("startup_sequence"), bool)
        or capability.get("startup_sequence", 0) <= 0
    ):
        return False
    identity_fields = (
        "target_identity", "target_type", "operation_identity",
        "execution_specification_id", "execution_adapter_identity",
        "execution_consumer_identity", "issuer_identity",
    )
    if any(
        not isinstance(capability.get(field), str)
        or _IDENTITY.fullmatch(str(capability[field])) is None
        for field in identity_fields
    ):
        return False
    digest_fields = (
        "capability_id", "request_fingerprint", "traversal_authority_digest",
        "issuance_authority_key", "eie_digest", "canonical_state_hash",
        "pipeline_a_result_digest", "convergence_result",
        "procedural_truth_token", "classification_token", "licensing_token",
        "governance_token", "grc_token", "domain_token", "aurion_result",
        "canonical_parameter_digest", "execution_specification_digest",
        "constraint_digest", "runtime_identity", "measurement_digest",
        "startup_attestation_digest", "audit_lineage_identifier",
        "capability_digest",
    )
    if any(not _is_digest(capability.get(field)) for field in digest_fields):
        return False
    pipeline_b = capability.get("pipeline_b_result_digest")
    if (
        capability.get("pipeline_mode") == "MODE_3_SINGLE_CONSTRAINED"
        and pipeline_b is not None
    ) or (
        capability.get("pipeline_mode") != "MODE_3_SINGLE_CONSTRAINED"
        and not _is_digest(pipeline_b)
    ):
        return False
    constraints = capability.get("constraint_snapshot")
    if not isinstance(constraints, Mapping) or not constraints:
        return False
    try:
        _measure(constraints)
        _reject_secret_bearing_keys(constraints)
    except ExecutionIntegrityError:
        return False
    if capability.get("constraint_digest") != generate_digest(dict(constraints)):
        return False
    temporal_integer_fields = (
        "reservation_timeout_seconds", "maximum_execution_seconds",
    )
    if any(
        not isinstance(capability.get(field), int)
        or isinstance(capability.get(field), bool)
        or capability.get(field, 0) <= 0
        for field in temporal_integer_fields
    ):
        return False
    issued = _parse(capability.get("issued_at"))
    not_before = _parse(capability.get("not_before"))
    expires = _parse(capability.get("expires_at"))
    start_deadline = _parse(capability.get("execution_start_deadline"))
    completion_deadline = _parse(capability.get("completion_report_deadline"))
    if (
        issued is None
        or not_before is None
        or expires is None
        or start_deadline is None
        or completion_deadline is None
        or not_before != issued
        or start_deadline <= issued
        or completion_deadline > expires
        or completion_deadline
        < start_deadline
        + timedelta(seconds=int(capability["maximum_execution_seconds"]))
        or int(capability["reservation_timeout_seconds"])
        > int((start_deadline - issued).total_seconds())
    ):
        return False
    expected_authority_key = generate_digest({
        "domain": "H7_SINGLE_CAPABILITY_PER_CANONICAL_TRAVERSAL",
        "traversal_authority_digest": capability[
            "traversal_authority_digest"
        ],
    })
    if capability.get("issuance_authority_key") != expected_authority_key:
        return False
    seed = {
        **{
            key: deepcopy(capability[key])
            for key in _CONTEXT_FIELDS
        },
        "traversal_authority_digest": capability[
            "traversal_authority_digest"
        ],
        "issuance_authority_key": capability["issuance_authority_key"],
        "execution_specification_id": capability[
            "execution_specification_id"
        ],
        "execution_specification_digest": capability[
            "execution_specification_digest"
        ],
        "issued_at": capability["issued_at"],
        "audit_lineage_identifier": capability[
            "audit_lineage_identifier"
        ],
    }
    if capability.get("capability_id") != generate_digest({
        "domain": CAPABILITY_DOMAIN,
        "seed": seed,
    }):
        return False
    body = {
        key: deepcopy(value)
        for key, value in capability.items()
        if key not in {"capability_digest", "integrity_binding"}
    }
    bound = {"integrity_domain": CAPABILITY_DOMAIN, "payload": body}
    return (
        capability.get("capability_digest") == generate_digest(bound)
        and verify_signature(
            bound,
            capability.get("integrity_binding", {}),
        )
    )


def authorize_control(
    *, capability_id: str, action: str, actor_id: str, reason: str,
    now: datetime, lifetime_seconds: int = 30,
) -> dict[str, Any]:
    current = _utc(now)
    if action not in {"CANCEL", "REVOKE"}:
        raise ExecutionIntegrityError("execution_control_action_invalid")
    if any(not isinstance(value, str) or not value.strip() for value in (capability_id, actor_id, reason)):
        raise ExecutionIntegrityError("execution_control_authorization_invalid")
    if lifetime_seconds <= 0:
        raise ExecutionIntegrityError("execution_control_lifetime_invalid")
    payload = {
        "authorization_version": "H7_EXECUTION_CONTROL_AUTHORIZATION_V1",
        "capability_id": capability_id,
        "action": action,
        "actor_id": actor_id,
        "reason_digest": generate_digest({
            "domain": "H7_EXECUTION_CONTROL_REASON", "reason": reason,
        }),
        "authorized_at": _text(current),
        "expires_at": _text(current + timedelta(seconds=lifetime_seconds)),
    }
    return {"payload": payload, "integrity_binding": sign_payload({"integrity_domain": CONTROL_DOMAIN, "payload": payload})}


def _verify_control(
    value: Any, *, capability_id: str, action: str, now: datetime,
    allowed_actors: frozenset[str],
) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"payload", "integrity_binding"}
        or not isinstance(value.get("payload"), Mapping)
    ):
        return False
    payload = dict(value["payload"])
    not_before = _parse(payload.get("authorized_at"))
    expires = _parse(payload.get("expires_at"))
    current = _utc(now)
    return (
        set(payload) == CONTROL_FIELDS
        and payload.get("authorization_version") == "H7_EXECUTION_CONTROL_AUTHORIZATION_V1"
        and payload.get("capability_id") == capability_id
        and payload.get("action") == action
        and payload.get("actor_id") in allowed_actors
        and isinstance(payload.get("reason_digest"), str)
        and len(payload.get("reason_digest", "")) == 64
        and not_before is not None
        and expires is not None
        and not_before <= current < expires
        and verify_signature(
            {"integrity_domain": CONTROL_DOMAIN, "payload": payload},
            value.get("integrity_binding", {}),
        )
    )


def verify_post_execution_attestation(
    attestation: Mapping[str, Any], *, capability: Mapping[str, Any] | None = None,
    expected_result: Mapping[str, Any] | None = None,
) -> bool:
    if not isinstance(attestation, Mapping) or set(attestation) != {"payload", "attestation_hash", "integrity_binding"}:
        return False
    payload = attestation.get("payload")
    if (
        not isinstance(payload, Mapping)
        or set(payload) != ATTESTATION_PAYLOAD_FIELDS
        or payload.get("attestation_version") != ATTESTATION_VERSION
        or payload.get("completion_classification") not in ATTESTATION_CLASSIFICATIONS
    ):
        return False
    started = _parse(payload.get("execution_start"))
    finished = _parse(payload.get("execution_finish"))
    if (
        started is None
        or finished is None
        or finished < started
        or not _valid_request_id(payload.get("request_id"))
        or payload.get("pipeline_mode") not in PIPELINE_MODES
        or not _valid_baseline_identifier(
            payload.get("approved_baseline_identifier")
        )
        or not isinstance(payload.get("startup_sequence"), int)
        or isinstance(payload.get("startup_sequence"), bool)
        or payload.get("startup_sequence", 0) <= 0
        or not isinstance(payload.get("completion_evidence_valid"), bool)
        or not isinstance(payload.get("completion_evidence"), Mapping)
    ):
        return False
    digest_fields = (
        "attestation_id", "capability_id", "request_fingerprint",
        "traversal_authority_digest", "capability_digest", "eie_digest",
        "canonical_state_hash", "parameter_digest", "constraint_digest",
        "convergence_digest", "result_digest", "runtime_identity",
        "measurement_digest", "startup_attestation_digest",
        "audit_lineage_identifier", "completion_evidence_digest",
    )
    identity_fields = (
        "target_identity", "operation_identity", "adapter_identity",
    )
    if (
        any(not _is_digest(payload.get(field)) for field in digest_fields)
        or any(
            not isinstance(payload.get(field), str)
            or _IDENTITY.fullmatch(str(payload[field])) is None
            for field in identity_fields
        )
        or (
            payload.get("previous_attestation_hash") != "GENESIS"
            and not _is_digest(payload.get("previous_attestation_hash"))
        )
    ):
        return False
    evidence = dict(payload["completion_evidence"])
    if payload.get("completion_evidence_digest") != generate_digest(evidence):
        return False
    if payload.get("attestation_id") != generate_digest({
        "capability_id": payload["capability_id"],
        "finish": payload["execution_finish"],
        "classification": payload["completion_classification"],
        "completion_evidence_digest": payload[
            "completion_evidence_digest"
        ],
    }):
        return False
    evidence_valid = bool(payload["completion_evidence_valid"])
    if payload.get("completion_classification") == "COMPLETED" and not evidence_valid:
        return False
    if not evidence_valid and evidence:
        return False
    bound = {"integrity_domain": ATTESTATION_DOMAIN, "payload": dict(payload)}
    valid = (
        attestation.get("attestation_hash") == generate_digest(bound)
        and verify_signature(bound, attestation.get("integrity_binding", {}))
    )
    if not valid:
        return False
    if capability is not None:
        pairs = {
            "capability_id": "capability_id", "request_id": "request_id",
            "request_fingerprint": "request_fingerprint",
            "traversal_authority_digest": "traversal_authority_digest",
            "capability_digest": "capability_digest",
            "eie_digest": "eie_digest", "canonical_state_hash": "canonical_state_hash",
            "target_identity": "target_identity", "operation_identity": "operation_identity",
            "parameter_digest": "canonical_parameter_digest", "pipeline_mode": "pipeline_mode",
            "convergence_digest": "convergence_result", "adapter_identity": "execution_adapter_identity",
            "runtime_identity": "runtime_identity",
            "approved_baseline_identifier": "approved_baseline_identifier",
            "measurement_digest": "measurement_digest",
            "startup_attestation_digest": "startup_attestation_digest",
            "startup_sequence": "startup_sequence",
            "audit_lineage_identifier": "audit_lineage_identifier",
        }
        if not verify_capability(capability) or any(payload.get(left) != capability.get(right) for left, right in pairs.items()):
            return False
        if evidence_valid and not _verify_completion_evidence_for_digest(
            evidence,
            capability=capability,
            result_digest=str(payload["result_digest"]),
            now=finished,
        ):
            return False
    elif evidence_valid:
        evidence_payload = evidence.get("payload")
        if (
            not isinstance(evidence_payload, Mapping)
            or set(evidence) != {"payload", "integrity_binding"}
            or set(evidence_payload) != COMPLETION_EVIDENCE_FIELDS
            or evidence_payload.get("evidence_version")
            != COMPLETION_EVIDENCE_VERSION
            or evidence_payload.get("completion_status") != "POSITIVE"
            or evidence_payload.get("result_digest")
            != payload.get("result_digest")
            or evidence_payload.get("capability_id")
            != payload.get("capability_id")
            or not verify_signature(
                {
                    "integrity_domain": COMPLETION_EVIDENCE_DOMAIN,
                    "payload": dict(evidence_payload),
                },
                evidence.get("integrity_binding", {}),
            )
        ):
            return False
    if expected_result is not None and payload.get("result_digest") != generate_digest(dict(expected_result)):
        return False
    return True


def _completion_evidence(
    capability: Mapping[str, Any], *, result: Mapping[str, Any], now: datetime,
) -> dict[str, Any]:
    payload = {
        "evidence_version": COMPLETION_EVIDENCE_VERSION,
        "capability_id": capability["capability_id"],
        "request_fingerprint": capability["request_fingerprint"],
        "traversal_authority_digest": capability[
            "traversal_authority_digest"
        ],
        "capability_digest": capability["capability_digest"],
        "eie_digest": capability["eie_digest"],
        "canonical_state_hash": capability["canonical_state_hash"],
        "target_identity": capability["target_identity"],
        "operation_identity": capability["operation_identity"],
        "parameter_digest": capability["canonical_parameter_digest"],
        "result_digest": generate_digest(dict(result)),
        "adapter_identity": capability["execution_adapter_identity"],
        "runtime_identity": capability["runtime_identity"],
        "approved_baseline_identifier": capability[
            "approved_baseline_identifier"
        ],
        "measurement_digest": capability["measurement_digest"],
        "startup_attestation_digest": capability[
            "startup_attestation_digest"
        ],
        "startup_sequence": capability["startup_sequence"],
        "audit_lineage_identifier": capability[
            "audit_lineage_identifier"
        ],
        "observed_at": _text(now),
        "completion_status": "POSITIVE",
    }
    bound = {"integrity_domain": COMPLETION_EVIDENCE_DOMAIN, "payload": payload}
    return {"payload": payload, "integrity_binding": sign_payload(bound)}


def _validate_positive_local_acknowledgement(
    capability: Mapping[str, Any], result: Mapping[str, Any],
) -> None:
    """Accept only an explicit, exactly-bound local effect acknowledgement."""

    if not isinstance(result, Mapping):
        raise ExecutionIntegrityError("adapter_acknowledgement_missing")
    status = result.get("status")
    if (
        not isinstance(status, str)
        or status.strip().upper() not in CONFIRMED_LOCAL_EFFECT_STATUSES
    ):
        raise ExecutionIntegrityError("adapter_acknowledgement_unconfirmed")
    if result.get("target") != capability.get("target_identity"):
        raise ExecutionIntegrityError(
            "adapter_acknowledgement_binding_mismatch:target_identity"
        )
    if result.get("operation") != capability.get("operation_identity"):
        raise ExecutionIntegrityError(
            "adapter_acknowledgement_binding_mismatch:operation_identity"
        )
    optional_bindings = {
        "target_type": "target_type",
        "capability_id": "capability_id",
        "request_fingerprint": "request_fingerprint",
        "adapter_identity": "execution_adapter_identity",
    }
    for result_field, capability_field in optional_bindings.items():
        if (
            result_field in result
            and result.get(result_field) != capability.get(capability_field)
        ):
            raise ExecutionIntegrityError(
                f"adapter_acknowledgement_binding_mismatch:{result_field}"
            )
    for field in ("acknowledged", "confirmed", "complete", "successful"):
        if field in result and result.get(field) is not True:
            raise ExecutionIntegrityError(
                f"adapter_acknowledgement_unconfirmed:{field}"
            )
    for field in (
        "ambiguous",
        "unknown",
        "partial",
        "timed_out",
        "timeout",
        "unconfirmed",
    ):
        if field in result and result.get(field) is not False:
            raise ExecutionIntegrityError(
                f"adapter_acknowledgement_ambiguous:{field}"
            )
    for field in ("error", "failure", "exception"):
        if result.get(field) not in (None, False, "", {}):
            raise ExecutionIntegrityError(
                f"adapter_acknowledgement_failed:{field}"
            )


def _verify_completion_evidence(
    value: Any, *, capability: Mapping[str, Any], result: Mapping[str, Any], now: datetime,
) -> bool:
    return _verify_completion_evidence_for_digest(
        value,
        capability=capability,
        result_digest=generate_digest(dict(result)),
        now=now,
    )


def _verify_completion_evidence_for_digest(
    value: Any, *, capability: Mapping[str, Any],
    result_digest: str, now: datetime,
) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"payload", "integrity_binding"}
        or not isinstance(value.get("payload"), Mapping)
    ):
        return False
    payload = dict(value["payload"])
    observed = _parse(payload.get("observed_at"))
    expected = {
        "capability_id": capability.get("capability_id"),
        "request_fingerprint": capability.get("request_fingerprint"),
        "traversal_authority_digest": capability.get(
            "traversal_authority_digest"
        ),
        "capability_digest": capability.get("capability_digest"),
        "eie_digest": capability.get("eie_digest"),
        "canonical_state_hash": capability.get("canonical_state_hash"),
        "target_identity": capability.get("target_identity"),
        "operation_identity": capability.get("operation_identity"),
        "parameter_digest": capability.get("canonical_parameter_digest"),
        "result_digest": result_digest,
        "adapter_identity": capability.get("execution_adapter_identity"),
        "runtime_identity": capability.get("runtime_identity"),
        "approved_baseline_identifier": capability.get(
            "approved_baseline_identifier"
        ),
        "measurement_digest": capability.get("measurement_digest"),
        "startup_attestation_digest": capability.get(
            "startup_attestation_digest"
        ),
        "startup_sequence": capability.get("startup_sequence"),
        "audit_lineage_identifier": capability.get(
            "audit_lineage_identifier"
        ),
    }
    bound = {"integrity_domain": COMPLETION_EVIDENCE_DOMAIN, "payload": payload}
    return (
        verify_capability(capability)
        and set(payload) == COMPLETION_EVIDENCE_FIELDS
        and payload.get("evidence_version") == COMPLETION_EVIDENCE_VERSION
        and payload.get("completion_status") == "POSITIVE"
        and observed is not None
        and observed <= _utc(now)
        and _is_digest(payload.get("result_digest"))
        and isinstance(payload.get("startup_sequence"), int)
        and not isinstance(payload.get("startup_sequence"), bool)
        and payload.get("startup_sequence", 0) > 0
        and _valid_baseline_identifier(
            payload.get("approved_baseline_identifier")
        )
        and all(payload.get(field) == expected_value for field, expected_value in expected.items())
        and verify_signature(bound, value.get("integrity_binding", {}))
    )


class ExecutionIntegrityService:
    def __init__(
        self, store: CapabilityLifecycleStore, *,
        execution_specifications: Sequence[ExecutionSpecification],
        clock: Callable[[], datetime] | None = None,
        control_authorities: Sequence[str] = ("SBP_LEX_DESKTOP_V1_OPERATOR",),
    ) -> None:
        self.store = store
        specifications = tuple(execution_specifications)
        if (
            not specifications
            or any(not isinstance(item, ExecutionSpecification) for item in specifications)
            or len({item.specification_id for item in specifications}) != len(specifications)
        ):
            raise ExecutionIntegrityError("approved_execution_specifications_required")
        self._execution_specifications = {
            item.specification_id: item for item in specifications
        }
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._active_lock = RLock()
        self._active_adapters: dict[str, Any] = {}
        self.control_authorities = frozenset(control_authorities)
        if not self.control_authorities or any(not isinstance(item, str) or not item for item in self.control_authorities):
            raise ExecutionIntegrityError("execution_control_authority_invalid")
        try:
            self.store.validate_and_recover()
            self.store.acquire_writer_lease()
        except CapabilityStoreError as exc:
            raise ExecutionIntegrityError(str(exc)) from exc
        try:
            self._validate_persisted_specifications()
            self.recover_after_restart()
        except Exception:
            self.store.release_writer_lease()
            raise

    def close(self) -> None:
        with self._active_lock:
            if self._active_adapters:
                raise ExecutionIntegrityError("active_execution_prevents_service_close")
        self.store.release_writer_lease()

    def __del__(self) -> None:
        try:
            self.store.release_writer_lease()
        except Exception:
            pass

    def _register_active_adapter(self, capability: Mapping[str, Any], adapter: Any) -> None:
        capability_id = str(capability["capability_id"])
        with self._active_lock:
            if capability_id in self._active_adapters:
                raise ExecutionIntegrityError("duplicate_active_execution_denied")
            self._active_adapters[capability_id] = adapter

    def _release_active_adapter(self, capability: Mapping[str, Any]) -> None:
        with self._active_lock:
            self._active_adapters.pop(str(capability["capability_id"]), None)

    def _active_adapter(self, capability: Mapping[str, Any]) -> Any:
        with self._active_lock:
            return self._active_adapters.get(str(capability["capability_id"]))

    def _specification(self, specification_id: Any) -> ExecutionSpecification:
        if not isinstance(specification_id, str):
            raise ExecutionIntegrityError("execution_specification_missing")
        specification = self._execution_specifications.get(specification_id)
        if specification is None:
            raise ExecutionIntegrityError("execution_specification_not_approved")
        return specification

    def _validate_persisted_specifications(self) -> None:
        for capability_id in self.store.latest_states():
            history = self.store.history(capability_id)
            capability = history[0].get("details", {}).get("capability") if history else None
            if not isinstance(capability, Mapping) or not verify_capability(capability):
                raise ExecutionIntegrityError("persisted_capability_evidence_invalid")
            self._capability_specification(capability)

    def _capability_specification(self, capability: Mapping[str, Any]) -> ExecutionSpecification:
        specification = self._specification(capability.get("execution_specification_id"))
        if capability.get("execution_specification_digest") != specification.digest:
            raise ExecutionIntegrityError("execution_specification_binding_mismatch")
        return specification

    def build_execution_context(
        self, capability: Mapping[str, Any], *, state: Mapping[str, Any],
        parameters: str | Mapping[str, Any],
        constraints: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not verify_capability(capability):
            raise ExecutionIntegrityError("capability_integrity_invalid")
        specification = self._capability_specification(capability)
        payload = specification.payload()
        return binding_context(
            state, request_id=str(capability["request_id"]),
            target_identity=payload["target_identity"], target_type=payload["target_type"],
            operation_identity=payload["operation_identity"], parameters=parameters,
            allowed_parameter_fields=payload["allowed_parameter_fields"],
            required_parameter_fields=payload["required_parameter_fields"],
            constraints=constraints if constraints is not None else payload["constraints"],
            adapter_identity=payload["adapter_identity"],
        )

    def _now(self) -> datetime:
        try:
            return _utc(self._clock())
        except ExecutionIntegrityError:
            raise
        except Exception as exc:
            raise ExecutionIntegrityError("execution_clock_unavailable") from exc

    def issue(
        self, state: Mapping[str, Any], *, traversal_authority: Mapping[str, Any],
        specification_id: str, parameters: str | Mapping[str, Any],
        lifetime_seconds: int = 300,
        reservation_timeout_seconds: int = 30, execution_start_seconds: int = 60,
        maximum_execution_seconds: int = 120, completion_report_seconds: int = 180,
    ) -> dict[str, Any]:
        security = evaluate_strict_execution_security(state)
        if not security["valid"] or not security["allowed"]:
            raise ExecutionIntegrityError("canonical_execution_authority_invalid")
        if not verify_execution_traversal_authority(traversal_authority, state):
            raise ExecutionIntegrityError("execution_traversal_authority_invalid")
        authority_payload = traversal_authority["payload"]
        request_id = str(authority_payload["request_id"])
        specification = self._specification(specification_id)
        specification_payload = specification.payload()
        if specification_payload["operation_identity"] != state.get("action"):
            raise ExecutionIntegrityError("execution_operation_not_bound_to_request")
        temporal_values = (
            lifetime_seconds, reservation_timeout_seconds, execution_start_seconds,
            maximum_execution_seconds, completion_report_seconds,
        )
        if (
            any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in temporal_values)
            or reservation_timeout_seconds > execution_start_seconds
            or execution_start_seconds + maximum_execution_seconds
            > completion_report_seconds
            or completion_report_seconds > lifetime_seconds
        ):
            raise ExecutionIntegrityError("capability_temporal_policy_invalid")
        context = binding_context(
            state, request_id=request_id,
            target_identity=specification_payload["target_identity"],
            target_type=specification_payload["target_type"],
            operation_identity=specification_payload["operation_identity"], parameters=parameters,
            allowed_parameter_fields=specification_payload["allowed_parameter_fields"],
            required_parameter_fields=specification_payload["required_parameter_fields"],
            constraints=specification_payload["constraints"],
            adapter_identity=specification_payload["adapter_identity"],
        )
        for field in MEASURED_STARTUP_BINDING_FIELDS:
            if authority_payload.get(field) != context.get(field):
                raise ExecutionIntegrityError(f"traversal_runtime_binding_changed:{field}")
        issued = self._now()
        traversal_authority_digest = str(traversal_authority["authority_digest"])
        issuance_authority_key = generate_digest({
            "domain": "H7_SINGLE_CAPABILITY_PER_CANONICAL_TRAVERSAL",
            "traversal_authority_digest": traversal_authority_digest,
        })
        seed = {
            **{key: deepcopy(value) for key, value in context.items()},
            "traversal_authority_digest": traversal_authority_digest,
            "issuance_authority_key": issuance_authority_key,
            "execution_specification_id": specification.specification_id,
            "execution_specification_digest": specification.digest,
            "issued_at": _text(issued),
            "audit_lineage_identifier": state.get("audit_hash"),
        }
        capability_id = generate_digest({"domain": CAPABILITY_DOMAIN, "seed": seed})
        body = {
            "capability_version": CAPABILITY_VERSION,
            "capability_id": capability_id,
            **context,
            "traversal_authority_digest": traversal_authority_digest,
            "issuance_authority_key": issuance_authority_key,
            "execution_specification_id": specification.specification_id,
            "execution_specification_digest": specification.digest,
            "issued_at": _text(issued),
            "not_before": _text(issued),
            "expires_at": _text(issued + timedelta(seconds=lifetime_seconds)),
            "reservation_timeout_seconds": reservation_timeout_seconds,
            "execution_start_deadline": _text(issued + timedelta(seconds=execution_start_seconds)),
            "maximum_execution_seconds": maximum_execution_seconds,
            "completion_report_deadline": _text(issued + timedelta(seconds=completion_report_seconds)),
            "maximum_attempts": 1,
            "consumption_state": "UNCONSUMED",
            "cancellation_state": "NOT_CANCELLED",
            "safe_cancellation_supported": specification_payload["safe_cancellation_supported"],
            "issuer_identity": ISSUER,
            "execution_consumer_identity": LOCAL_EXECUTION_CONSUMER_ID,
            "audit_lineage_identifier": state.get("audit_hash"),
        }
        bound = {"integrity_domain": CAPABILITY_DOMAIN, "payload": body}
        capability = {
            **body,
            "capability_digest": generate_digest(bound),
            "integrity_binding": sign_payload(bound),
        }
        try:
            self.store.append_transition(
                capability_id=capability_id, capability_digest=capability["capability_digest"],
                event_type="CAPABILITY_ISSUED", expected_state=None, new_state="PENDING",
                occurred_at=_text(issued), details={"capability": capability},
            )
        except CapabilityStoreError as exc:
            raise ExecutionIntegrityError(str(exc)) from exc
        return capability

    def _transition(
        self, capability: Mapping[str, Any], *, expected: str, new: str,
        event: str, details: Mapping[str, Any] | None = None,
        attestation_payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not verify_capability(capability):
            raise ExecutionIntegrityError("capability_integrity_invalid")
        if expected not in STATES or new not in STATES or new not in TRANSITIONS[expected]:
            raise ExecutionIntegrityError("illegal_capability_transition")
        try:
            return self.store.append_transition(
                capability_id=str(capability["capability_id"]),
                capability_digest=str(capability["capability_digest"]),
                event_type=event, expected_state=expected, new_state=new,
                occurred_at=_text(self._now()), details=details,
                attestation_payload=attestation_payload,
            )
        except CapabilityStoreError as exc:
            raise ExecutionIntegrityError(str(exc)) from exc

    def activate(self, capability: Mapping[str, Any]) -> dict[str, Any]:
        self._temporal(capability, self._now(), allow_before=True)
        return self._transition(capability, expected="PENDING", new="ACTIVE", event="CAPABILITY_ACTIVATED")

    def _temporal(self, capability: Mapping[str, Any], now: datetime, *, allow_before: bool = False) -> None:
        current = _utc(now)
        not_before, expires = _parse(capability.get("not_before")), _parse(capability.get("expires_at"))
        if not_before is None or expires is None:
            raise ExecutionIntegrityError("capability_temporal_state_unknown")
        if not allow_before and current < not_before:
            raise ExecutionIntegrityError("capability_not_yet_valid")
        if current >= expires:
            raise ExecutionIntegrityError("capability_expired")

    def _validate_context(self, capability: Mapping[str, Any], context: Mapping[str, Any], now: datetime) -> None:
        if not verify_capability(capability):
            raise ExecutionIntegrityError("capability_integrity_invalid")
        self._capability_specification(capability)
        self._temporal(capability, now)
        for field in (
            "request_id", "request_fingerprint", "eie_identifier", "eie_digest", "canonical_state_hash",
            "pipeline_mode", "pipeline_a_result_digest", "pipeline_b_result_digest",
            "convergence_result", "procedural_truth_token", "classification_token",
            "licensing_token", "governance_token", "grc_token", "domain_token",
            "aurion_result", "target_identity", "target_type", "operation_identity",
            "canonical_parameter_digest", "runtime_identity", "approved_baseline_identifier",
            "measurement_digest", "startup_attestation_digest", "startup_sequence",
            "execution_adapter_identity",
            "audit_lineage_identifier",
        ):
            if context.get(field) != capability.get(field):
                raise ExecutionIntegrityError(f"capability_binding_mismatch:{field}")
        original_constraints = capability.get("constraint_snapshot")
        current_constraints = context.get("constraint_snapshot")
        if not isinstance(original_constraints, Mapping) or generate_digest(original_constraints) != capability.get("constraint_digest"):
            raise ExecutionIntegrityError("capability_constraint_integrity_invalid")
        if not isinstance(current_constraints, Mapping) or generate_digest(current_constraints) != context.get("constraint_digest"):
            raise ExecutionIntegrityError("current_constraint_integrity_invalid")
        if not constraints_preserved(original_constraints, current_constraints):
            raise ExecutionIntegrityError("execution_constraint_broadening_or_loss")
        measurement = ensure_measured_startup()
        if measurement.get("status") != "MEASURED_STARTUP_APPROVED":
            raise ExecutionIntegrityError("measured_startup_not_approved")
        for field in MEASURED_STARTUP_BINDING_FIELDS:
            if measurement.get(field) != capability.get(field):
                raise ExecutionIntegrityError(f"measured_runtime_binding_changed:{field}")
        if capability.get("execution_consumer_identity") != LOCAL_EXECUTION_CONSUMER_ID:
            raise ExecutionIntegrityError("execution_consumer_identity_mismatch")

    def reserve(self, capability: Mapping[str, Any], *, context: Mapping[str, Any]) -> dict[str, Any]:
        self._validate_context(capability, context, self._now())
        return self._transition(
            capability, expected="ACTIVE", new="RESERVED", event="CAPABILITY_RESERVED",
            details={"attempt": 1, "context_digest": generate_digest(dict(context))},
        )

    def start(self, capability: Mapping[str, Any], *, context: Mapping[str, Any]) -> dict[str, Any]:
        current = self._now()
        self._validate_context(capability, context, current)
        history = self.store.history(str(capability["capability_id"]))
        reservation = next((item for item in reversed(history) if item["event_type"] == "CAPABILITY_RESERVED"), None)
        if reservation is None:
            raise ExecutionIntegrityError("capability_reservation_missing")
        reserved_at = _parse(reservation["occurred_at"])
        start_deadline = _parse(capability["execution_start_deadline"])
        if reserved_at is None or start_deadline is None:
            raise ExecutionIntegrityError("execution_start_temporal_state_unknown")
        if current >= min(
            reserved_at + timedelta(seconds=int(capability["reservation_timeout_seconds"])),
            start_deadline,
        ):
            self._transition(
                capability, expected="RESERVED", new="EXPIRED", event="CAPABILITY_EXPIRED",
                details={"reason": "execution_start_deadline_exceeded"},
            )
            raise ExecutionIntegrityError("execution_start_deadline_exceeded")
        return self._transition(
            capability, expected="RESERVED", new="EXECUTING", event="EXECUTION_STARTED",
            details={"adapter_identity": context["execution_adapter_identity"]},
        )

    def revalidate(
        self, capability: Mapping[str, Any], *, context: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self.store.state(str(capability["capability_id"])) != "EXECUTING":
            raise ExecutionIntegrityError("capability_not_executing")
        now = self._now()
        try:
            self._validate_context(capability, context, now)
        except Exception as exc:
            reason = str(exc)
            attestation_payload = self._build_attestation_payload(
                capability, now=now, classification="FAILED",
                result_digest=generate_digest({"revalidation_failure": reason}),
                constraint_digest=generate_digest(context.get("constraint_snapshot", {})),
            )
            self._transition(
                capability, expected="EXECUTING", new="FAILED",
                event="EXECUTION_FAILED", details={"failure": reason},
                attestation_payload=attestation_payload,
            )
            raise ExecutionIntegrityError(reason) from exc
        history = self.store.history(str(capability["capability_id"]))
        started = next((item for item in reversed(history) if item["event_type"] == "EXECUTION_STARTED"), None)
        started_at = _parse(started["occurred_at"]) if started else None
        if started_at is None:
            raise ExecutionIntegrityError("execution_start_missing")
        if now >= started_at + timedelta(seconds=int(capability["maximum_execution_seconds"])):
            attestation_payload = self._build_attestation_payload(
                capability, now=now, classification="FAILED",
                result_digest=generate_digest({"failure": "maximum_execution_duration_exceeded"}),
                constraint_digest=generate_digest(context.get("constraint_snapshot", {})),
            )
            self._transition(
                capability, expected="EXECUTING", new="FAILED",
                event="EXECUTION_DURATION_EXCEEDED",
                attestation_payload=attestation_payload,
            )
            raise ExecutionIntegrityError("maximum_execution_duration_exceeded")
        return {
            "valid": True,
            "capability_id": capability["capability_id"],
            "checkpoint": len([item for item in history if item["event_type"] == "EXECUTION_REVALIDATED"]) + 1,
            "context_digest": generate_digest(dict(context)),
        }

    def record_checkpoint(
        self, capability: Mapping[str, Any], *, context: Mapping[str, Any],
    ) -> dict[str, Any]:
        result = self.revalidate(capability, context=context)
        return self._transition(
            capability, expected="EXECUTING", new="EXECUTING",
            event="EXECUTION_REVALIDATED", details=result,
        )

    def cancel(
        self, capability: Mapping[str, Any], *, authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = self._now()
        if not _verify_control(
            authorization, capability_id=str(capability.get("capability_id")),
            action="CANCEL", now=now, allowed_actors=self.control_authorities,
        ):
            raise ExecutionIntegrityError("capability_cancellation_unauthorised")
        for attempt in range(2):
            current = self.store.state(str(capability["capability_id"]))
            if current == "EXECUTING" and capability.get("safe_cancellation_supported") is not True:
                raise ExecutionIntegrityError("safe_cancellation_not_supported")
            if current not in {"PENDING", "ACTIVE", "RESERVED", "EXECUTING"}:
                raise ExecutionIntegrityError(f"capability_cancellation_denied:{current}")
            try:
                if current == "EXECUTING":
                    adapter = self._active_adapter(capability)
                    terminate = getattr(adapter, "terminate", None)
                    if adapter is None or not callable(terminate):
                        raise ExecutionIntegrityError("safe_termination_adapter_unavailable")
                    termination_result = terminate(str(capability["capability_id"]))
                    if (
                        not isinstance(termination_result, Mapping)
                        or dict(termination_result) != {
                            "safe_termination": True,
                            "capability_id": capability["capability_id"],
                            "adapter_identity": capability["execution_adapter_identity"],
                        }
                    ):
                        raise ExecutionIntegrityError("safe_termination_not_confirmed")
                    safe_termination_evidence = _completion_evidence(
                        capability, result=termination_result, now=now,
                    )
                    if not _verify_completion_evidence(
                        safe_termination_evidence, capability=capability,
                        result=termination_result, now=now,
                    ):
                        raise ExecutionIntegrityError("safe_termination_evidence_required")
                    attestation_payload = self._build_attestation_payload(
                        capability, now=now, classification="CANCELLED",
                        result_digest=generate_digest(termination_result),
                        constraint_digest=str(capability["constraint_digest"]),
                        completion_evidence=safe_termination_evidence,
                        completion_evidence_valid=True,
                    )
                    return self._transition(
                        capability, expected="EXECUTING", new="CANCELLED", event="EXECUTION_CANCELLED",
                        details={"authorization": authorization["payload"]},
                        attestation_payload=attestation_payload,
                    )
                return self._transition(
                    capability, expected=str(current), new="CANCELLED", event="CAPABILITY_CANCELLED",
                    details={"authorization": authorization["payload"]},
                )
            except ExecutionIntegrityError as exc:
                if attempt == 0 and exc.reason.startswith("capability_state_conflict:"):
                    continue
                raise
        raise ExecutionIntegrityError("capability_cancellation_race_denied")

    def revoke(
        self, capability: Mapping[str, Any], *, authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = self._now()
        if not _verify_control(
            authorization, capability_id=str(capability.get("capability_id")),
            action="REVOKE", now=now, allowed_actors=self.control_authorities,
        ):
            raise ExecutionIntegrityError("capability_revocation_unauthorised")
        for attempt in range(2):
            current = self.store.state(str(capability["capability_id"]))
            if current not in {"ACTIVE", "RESERVED", "EXECUTING"}:
                raise ExecutionIntegrityError(f"capability_revocation_denied:{current}")
            try:
                if current == "EXECUTING":
                    attestation_payload = self._build_attestation_payload(
                        capability, now=now, classification="FAILED",
                        result_digest=generate_digest({"failure": "revoked_during_execution"}),
                        constraint_digest=str(capability["constraint_digest"]),
                    )
                    return self._transition(
                        capability, expected="EXECUTING", new="FAILED", event="EXECUTION_REVOKED_FAILED",
                        details={"authorization": authorization["payload"]},
                        attestation_payload=attestation_payload,
                    )
                return self._transition(
                    capability, expected=str(current), new="REVOKED", event="CAPABILITY_REVOKED",
                    details={"authorization": authorization["payload"]},
                )
            except ExecutionIntegrityError as exc:
                if attempt == 0 and exc.reason.startswith("capability_state_conflict:"):
                    continue
                raise
        raise ExecutionIntegrityError("capability_revocation_race_denied")

    def expire(self, capability: Mapping[str, Any]) -> dict[str, Any]:
        now = self._now()
        current = self.store.state(str(capability["capability_id"]))
        if current not in {"ACTIVE", "RESERVED"}:
            raise ExecutionIntegrityError(f"capability_expiry_denied:{current}")
        expires_at = _parse(capability.get("expires_at"))
        if expires_at is None:
            raise ExecutionIntegrityError("capability_temporal_state_unknown")
        if now < expires_at:
            raise ExecutionIntegrityError("capability_not_expired")
        return self._transition(capability, expected=str(current), new="EXPIRED", event="CAPABILITY_EXPIRED")

    def _record_positive_completion_evidence(
        self, capability: Mapping[str, Any], *, result: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not verify_capability(capability):
            raise ExecutionIntegrityError("capability_integrity_invalid")
        if self.store.state(str(capability["capability_id"])) != "EXECUTING":
            raise ExecutionIntegrityError("capability_not_executing")
        if self._active_adapter(capability) is None:
            raise ExecutionIntegrityError("adapter_completion_session_missing")
        _validate_positive_local_acknowledgement(capability, result)
        return _completion_evidence(capability, result=result, now=self._now())

    def complete(
        self, capability: Mapping[str, Any], *, context: Mapping[str, Any],
        completion_classification: str, result: Mapping[str, Any] | None,
        positive_completion_evidence: Mapping[str, Any] | None,
        communication_lost: bool = False,
    ) -> dict[str, Any]:
        self.revalidate(capability, context=context)
        now = self._now()
        classification = "AMBIGUOUS" if communication_lost else completion_classification
        if classification not in {"COMPLETED", "FAILED", "AMBIGUOUS"}:
            raise ExecutionIntegrityError("completion_classification_invalid")
        result_value = dict(result or {})
        evidence_valid = _verify_completion_evidence(
            positive_completion_evidence, capability=capability,
            result=result_value, now=now,
        ) if positive_completion_evidence else False
        if classification == "COMPLETED":
            try:
                _validate_positive_local_acknowledgement(
                    capability, result_value
                )
            except ExecutionIntegrityError:
                classification = "AMBIGUOUS"
                evidence_valid = False
        if classification == "COMPLETED" and not evidence_valid:
            classification = "AMBIGUOUS"
        deadline = _parse(capability["completion_report_deadline"])
        if deadline is None or now >= deadline:
            classification = "AMBIGUOUS"
        result_digest = generate_digest(result_value)
        attestation_payload = self._build_attestation_payload(
            capability, now=now, classification=classification,
            result_digest=result_digest,
            constraint_digest=generate_digest(context["constraint_snapshot"]),
            completion_evidence=(
                positive_completion_evidence if evidence_valid else None
            ),
            completion_evidence_valid=evidence_valid,
        )
        event = {
            "COMPLETED": "EXECUTION_COMPLETED",
            "FAILED": "EXECUTION_FAILED",
            "AMBIGUOUS": "EXECUTION_AMBIGUOUS",
        }[classification]
        record = self._transition(
            capability, expected="EXECUTING", new=classification, event=event,
            details={
                "completion_evidence_digest": generate_digest(dict(positive_completion_evidence or {})),
                "completion_evidence_valid": evidence_valid,
            },
            attestation_payload=attestation_payload,
        )
        attestation = record["details"]["execution_attestation"]
        if not verify_post_execution_attestation(attestation, capability=capability, expected_result=result_value):
            raise ExecutionIntegrityError("post_execution_attestation_invalid")
        return attestation

    def _build_attestation_payload(
        self, capability: Mapping[str, Any], *, now: datetime,
        classification: str, result_digest: str, constraint_digest: str,
        completion_evidence: Mapping[str, Any] | None = None,
        completion_evidence_valid: bool = False,
    ) -> dict[str, Any]:
        history = self.store.history(str(capability["capability_id"]))
        started = next((item for item in reversed(history) if item["event_type"] == "EXECUTION_STARTED"), None)
        if started is None:
            raise ExecutionIntegrityError("execution_start_missing")
        evidence = deepcopy(dict(completion_evidence or {}))
        if not isinstance(completion_evidence_valid, bool):
            raise ExecutionIntegrityError(
                "completion_evidence_validity_invalid"
            )
        if completion_evidence_valid and not evidence:
            raise ExecutionIntegrityError("completion_evidence_required")
        evidence_digest = generate_digest(evidence)
        payload = {
            "attestation_version": ATTESTATION_VERSION,
            "attestation_id": generate_digest({
                "capability_id": capability["capability_id"],
                "finish": _text(now), "classification": classification,
                "completion_evidence_digest": evidence_digest,
            }),
            "capability_id": capability["capability_id"],
            "request_id": capability["request_id"],
            "request_fingerprint": capability["request_fingerprint"],
            "traversal_authority_digest": capability[
                "traversal_authority_digest"
            ],
            "capability_digest": capability["capability_digest"],
            "eie_digest": capability["eie_digest"],
            "canonical_state_hash": capability["canonical_state_hash"],
            "target_identity": capability["target_identity"],
            "operation_identity": capability["operation_identity"],
            "parameter_digest": capability["canonical_parameter_digest"],
            "constraint_digest": constraint_digest,
            "pipeline_mode": capability["pipeline_mode"],
            "convergence_digest": capability["convergence_result"],
            "execution_start": started["occurred_at"],
            "execution_finish": _text(now),
            "completion_classification": classification,
            "result_digest": result_digest,
            "adapter_identity": capability["execution_adapter_identity"],
            "runtime_identity": capability["runtime_identity"],
            "approved_baseline_identifier": capability[
                "approved_baseline_identifier"
            ],
            "measurement_digest": capability["measurement_digest"],
            "startup_attestation_digest": capability[
                "startup_attestation_digest"
            ],
            "startup_sequence": capability["startup_sequence"],
            "audit_lineage_identifier": capability["audit_lineage_identifier"],
            "completion_evidence": evidence,
            "completion_evidence_digest": evidence_digest,
            "completion_evidence_valid": completion_evidence_valid,
        }
        return payload

    def execute_once(
        self, capability: Mapping[str, Any], *,
        context_provider: Callable[[], Mapping[str, Any]],
        parameters: str | Mapping[str, Any],
        adapter: Callable[[str, str, str, Mapping[str, Any], Callable[[], None]], Mapping[str, Any]],
    ) -> dict[str, Any]:
        specification = self._capability_specification(capability)
        specification_payload = specification.payload()
        if getattr(adapter, "identity", None) != capability.get("execution_adapter_identity"):
            raise ExecutionIntegrityError("capability_binding_mismatch:execution_adapter_identity")
        if bool(getattr(adapter, "safe_cancellation_supported", False)) != capability.get("safe_cancellation_supported"):
            raise ExecutionIntegrityError("adapter_cancellation_policy_mismatch")
        canonical = canonical_parameters(
            parameters, allowed_fields=specification_payload["allowed_parameter_fields"],
            required_fields=specification_payload["required_parameter_fields"],
        )
        if generate_digest(canonical) != capability.get("canonical_parameter_digest"):
            raise ExecutionIntegrityError("capability_binding_mismatch:canonical_parameter_digest")
        initial_context = deepcopy(dict(context_provider()))
        self.reserve(capability, context=initial_context)
        self.start(capability, context=deepcopy(dict(context_provider())))
        self._register_active_adapter(capability, adapter)

        def checkpoint() -> None:
            self.record_checkpoint(capability, context=deepcopy(dict(context_provider())))

        try:
            checkpoint()
            result = adapter(
                str(capability["target_identity"]), str(capability["target_type"]),
                str(capability["operation_identity"]), deepcopy(canonical), checkpoint,
            )
            if not isinstance(result, Mapping):
                raise ExecutionIntegrityError("adapter_result_invalid")
        except Exception as exc:
            if self.store.state(str(capability["capability_id"])) == "EXECUTING":
                now = self._now()
                payload = self._build_attestation_payload(
                    capability, now=now, classification="AMBIGUOUS",
                    result_digest=generate_digest({"adapter_exception": type(exc).__name__}),
                    constraint_digest=str(capability["constraint_digest"]),
                )
                self._transition(
                    capability, expected="EXECUTING", new="AMBIGUOUS",
                    event="EXECUTION_AMBIGUOUS",
                    details={"automatic_retry": False, "reason": "adapter_completion_unknown"},
                    attestation_payload=payload,
                )
            self._release_active_adapter(capability)
            if isinstance(exc, ExecutionIntegrityError):
                raise
            raise ExecutionIntegrityError("adapter_completion_ambiguous") from exc
        result_value = deepcopy(dict(result))
        try:
            evidence = self._record_positive_completion_evidence(capability, result=result_value)
            final_context = deepcopy(dict(context_provider()))
            attestation = self.complete(
                capability, context=final_context,
                completion_classification="COMPLETED", result=result_value,
                positive_completion_evidence=evidence,
            )
        except Exception as exc:
            if self.store.state(str(capability["capability_id"])) == "EXECUTING":
                now = self._now()
                payload = self._build_attestation_payload(
                    capability, now=now, classification="AMBIGUOUS",
                    result_digest=generate_digest(result_value),
                    constraint_digest=str(capability["constraint_digest"]),
                )
                self._transition(
                    capability, expected="EXECUTING", new="AMBIGUOUS",
                    event="EXECUTION_AMBIGUOUS",
                    details={"automatic_retry": False, "reason": "post_effect_completion_window_failed"},
                    attestation_payload=payload,
                )
            self._release_active_adapter(capability)
            if isinstance(exc, ExecutionIntegrityError):
                raise
            raise ExecutionIntegrityError("post_effect_completion_ambiguous") from exc
        self._release_active_adapter(capability)
        attestation_payload = attestation.get("payload", {})
        if (
            not isinstance(attestation_payload, Mapping)
            or attestation_payload.get("completion_classification")
            != "COMPLETED"
            or attestation_payload.get("completion_evidence_valid") is not True
            or not verify_post_execution_attestation(
                attestation,
                capability=capability,
                expected_result=result_value,
            )
        ):
            raise ExecutionIntegrityError(
                "confirmed_effect_attestation_invalid"
            )
        return {
            "result": result_value,
            "execution_attestation": attestation,
            "effect_status": "CONFIRMED_SUCCESS",
        }

    def retire(self, capability: Mapping[str, Any]) -> dict[str, Any]:
        current = self.store.state(str(capability["capability_id"]))
        if current not in TERMINAL_STATES - {"RETIRED"}:
            raise ExecutionIntegrityError(f"capability_retirement_denied:{current}")
        return self._transition(capability, expected=str(current), new="RETIRED", event="CAPABILITY_RETIRED")

    def recover_after_restart(self) -> list[str]:
        try:
            self.store.validate_and_recover()
            latest = self.store.latest_states()
        except CapabilityStoreError as exc:
            raise ExecutionIntegrityError(str(exc)) from exc
        recovered: list[str] = []
        for capability_id, value in latest.items():
            if value["state"] == "EXECUTING":
                history = self.store.history(capability_id)
                capability = history[0]["details"].get("capability")
                if not isinstance(capability, Mapping) or not verify_capability(capability):
                    raise ExecutionIntegrityError("restart_capability_evidence_invalid")
                now = self._now()
                attestation_payload = self._build_attestation_payload(
                    capability, now=now, classification="AMBIGUOUS",
                    result_digest=generate_digest({"restart": "completion_unknown"}),
                    constraint_digest=str(capability["constraint_digest"]),
                )
                self._transition(
                    capability, expected="EXECUTING", new="AMBIGUOUS",
                    event="RESTART_DURING_EXECUTION_AMBIGUOUS",
                    details={"automatic_retry": False},
                    attestation_payload=attestation_payload,
                )
                recovered.append(capability_id)
        return recovered
