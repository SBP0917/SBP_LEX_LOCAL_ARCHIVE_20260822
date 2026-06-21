from __future__ import annotations

import json
import math
import re
from typing import Any, Mapping

MAX_JSON_DEPTH = 8
MAX_JSON_KEYS = 160
MAX_STRING_LENGTH = 4096
MAX_LIST_LENGTH = 128
MAX_EVIDENCE_ITEMS = 25
MAX_PRE_CONTEXT_SIGNAL_KEYS = 32

ACTION_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_:\-]{0,63}$")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_:\-.]{1,128}$")
SOURCE_PATTERN = re.compile(r"^[A-Za-z0-9_:\-.]{1,128}$")
COMMAND_INJECTION_PATTERN = re.compile(
    r"(?:\$\(|`|&&|\|\||(?:^|\s)(?:cmd(?:\.exe)?|powershell(?:\.exe)?|bash|sh)\s+(?:/c|-c)\b)",
    re.IGNORECASE,
)
TEMPLATE_INJECTION_PATTERN = re.compile(r"(?:\{\{|\{%|<%|\$\{)")
REPORT_INJECTION_PATTERN = re.compile(
    r"(?:<script\b|javascript:|data:text/html|(?:\r?\n)#{1,6}\s)",
    re.IGNORECASE,
)

FORBIDDEN_KEYS = {
    "__class__",
    "__dict__",
    "__globals__",
    "__mro__",
    "__subclasses__",
    "__proto__",
    "constructor",
    "prototype",
}

REQUEST_ALLOWED_KEYS = {
    "action",
    "payload",
    "resolved_authority",
    "jurisdiction",
    "context",
    "safety_profile",
}

PAYLOAD_ALLOWED_KEYS = {
    "classification",
    "licence",
    "license",
    "licence_state",
    "license_state",
    "manufacturer_declaration",
    "parameters",
    "metadata",
}

CLASSIFICATION_ALLOWED_KEYS = {
    "ap_acf_class",
    "class",
    "subclass",
    "autonomy_level",
    "autonomy_ceiling",
    "operational_scope",
    "public_exposure",
    "environment_modifiers",
    "deployment_restrictions",
    "manufacturer_declaration",
}

SAFETY_ALLOWED_KEYS = {
    "human_safety",
    "irreversibility",
    "cascading_impact",
    "financial_operational",
}

CONTEXT_ALLOWED_KEYS = {
    "evidence",
    "financial_amount",
    "operational_scope",
    "public_exposure",
    "environment",
    "human_proximity",
    "geographic_isolation",
    "operational_containment",
    "emergency_stop_available",
    "licence_state",
    "license_state",
    "licence",
    "license",
    "dependencies",
    "critical_dependency_present",
    "policy_conflict_detected",
    "policy_conflict_reference",
    "precedence_available",
    "precedence_reference",
    "temporal_rule_lineage",
    "environment_modifiers",
    "classification",
    "escalation_threshold",
    "prior_denied_fingerprint",
    "material_change_declared",
    "material_change_reason",
    "escalation_path_available",
    "deployment_profile",
    "domain_fallback_safe",
}

API_BODY_ALLOWED_KEYS = {
    "/runtime/traverse": {"request", "request_id", "pre_context_signals"},
    "/runtime/replay": {"request", "replay_count", "pre_context_signals"},
    "/connector/build-envelope": {"request", "request_id", "source", "metadata"},
    "/connector/envelope": {"request_id", "source", "request", "metadata", "digest", "signature"},
}

CONNECTOR_ENVELOPE_ALLOWED_KEYS = {
    "request_id",
    "source",
    "request",
    "metadata",
    "digest",
    "signature",
}

PRE_CONTEXT_SIGNAL_ALLOWED_KEYS = {
    "request_fingerprint",
    "intent_signal",
    "risk_potential_signal",
    "authority_link_signal",
    "jurisdiction_signal",
    "dependency_signal",
    "policy_conflict_signal",
    "operational_context_signal",
    "precedence_signal",
    "ap_acf_declaration",
    "manufacturer_declaration",
    "skg_digest",
    "dtn_digest",
    "skg_context",
    "dtn_context",
    "digest",
    "signature",
    "timestamp",
    "timestamp_authority",
    "nonce",
}

EVIDENCE_ALLOWED_KEYS = {
    "source",
    "content",
    "verified",
    "attested",
    "freshness_valid",
    "consistency_valid",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def loads_strict_json(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non_finite_json_number:{value}")
        ),
    )


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _append_unknown_keys(failures: list[str], *, prefix: str, data: Mapping[str, Any], allowed: set[str]) -> None:
    for key in data.keys():
        if key not in allowed:
            failures.append(f"unknown_field:{prefix}.{key}")


def _validate_primitive_limits(value: Any, *, path: str, failures: list[str], depth: int, counter: list[int]) -> None:
    if depth > MAX_JSON_DEPTH:
        failures.append(f"json_depth_exceeded:{path}")
        return

    if isinstance(value, Mapping):
        counter[0] += len(value)
        if counter[0] > MAX_JSON_KEYS:
            failures.append("json_key_limit_exceeded")
            return
        for key, child in value.items():
            if not isinstance(key, str):
                failures.append(f"non_string_key:{path}")
                continue
            if key in FORBIDDEN_KEYS or key.startswith("__"):
                failures.append(f"forbidden_key:{path}.{key}")
            _validate_primitive_limits(child, path=f"{path}.{key}", failures=failures, depth=depth + 1, counter=counter)
        return

    if isinstance(value, list):
        if len(value) > MAX_LIST_LENGTH:
            failures.append(f"list_length_exceeded:{path}")
            return
        for index, item in enumerate(value):
            _validate_primitive_limits(item, path=f"{path}[{index}]", failures=failures, depth=depth + 1, counter=counter)
        return

    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            failures.append(f"string_length_exceeded:{path}")
        if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in value):
            failures.append(f"control_character_detected:{path}")
        if COMMAND_INJECTION_PATTERN.search(value):
            failures.append(f"command_injection_rejected:{path}")
        if TEMPLATE_INJECTION_PATTERN.search(value):
            failures.append(f"template_injection_rejected:{path}")
        if REPORT_INJECTION_PATTERN.search(value):
            failures.append(f"report_injection_rejected:{path}")
        return

    if isinstance(value, float) and not math.isfinite(value):
        failures.append(f"non_finite_number:{path}")
        return

    if value is None or isinstance(value, (bool, int, float)):
        return

    failures.append(f"unsupported_json_type:{path}:{type(value).__name__}")


def validate_json_shape(value: Any, *, root_name: str = "json") -> tuple[bool, list[str]]:
    failures: list[str] = []
    _validate_primitive_limits(value, path=root_name, failures=failures, depth=0, counter=[0])
    return len(failures) == 0, failures


def validate_runtime_request_schema(request: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not _is_mapping(request):
        return False, ["request_not_mapping"]

    _, shape_failures = validate_json_shape(request, root_name="request")
    failures.extend(shape_failures)
    _append_unknown_keys(failures, prefix="request", data=request, allowed=REQUEST_ALLOWED_KEYS)

    action = request.get("action")
    if not isinstance(action, str) or not ACTION_PATTERN.match(action):
        failures.append("invalid_action_name")

    payload = request.get("payload")
    if not _is_mapping(payload):
        failures.append("payload_not_mapping")
    else:
        _append_unknown_keys(failures, prefix="payload", data=payload, allowed=PAYLOAD_ALLOWED_KEYS)
        classification = payload.get("classification")
        if not _is_mapping(classification):
            failures.append("payload_classification_required")
        else:
            _append_unknown_keys(failures, prefix="payload.classification", data=classification, allowed=CLASSIFICATION_ALLOWED_KEYS)
            if not isinstance(classification.get("ap_acf_class") or classification.get("class"), str):
                failures.append("classification_class_required")
            for numeric_field in ("autonomy_level", "autonomy_ceiling"):
                value = classification.get(numeric_field)
                if value is not None and not isinstance(value, int):
                    failures.append(f"classification_{numeric_field}_must_be_int")
            restrictions = classification.get("deployment_restrictions")
            if restrictions is not None and not isinstance(restrictions, list):
                failures.append("deployment_restrictions_must_be_list")

    context = request.get("context")
    if not _is_mapping(context):
        failures.append("context_required")
    else:
        _append_unknown_keys(failures, prefix="context", data=context, allowed=CONTEXT_ALLOWED_KEYS)
        evidence = context.get("evidence", [])
        if not isinstance(evidence, list):
            failures.append("context_evidence_must_be_list")
        elif len(evidence) > MAX_EVIDENCE_ITEMS:
            failures.append("context_evidence_limit_exceeded")
        else:
            for index, item in enumerate(evidence):
                if not _is_mapping(item):
                    failures.append(f"evidence_item_not_mapping:{index}")
                    continue
                _append_unknown_keys(
                    failures,
                    prefix=f"context.evidence[{index}]",
                    data=item,
                    allowed=EVIDENCE_ALLOWED_KEYS,
                )
                source = item.get("source")
                if not isinstance(source, str) or not SOURCE_PATTERN.match(source):
                    failures.append(f"invalid_evidence_source:{index}")
                if not isinstance(item.get("content"), str):
                    failures.append(f"invalid_evidence_content:{index}")
                for flag in (
                    "verified",
                    "attested",
                    "freshness_valid",
                    "consistency_valid",
                ):
                    if item.get(flag) is not None and not isinstance(item.get(flag), bool):
                        failures.append(f"evidence_{flag}_must_be_bool:{index}")

    safety_profile = request.get("safety_profile")
    if not _is_mapping(safety_profile):
        failures.append("safety_profile_required")
    else:
        _append_unknown_keys(failures, prefix="safety_profile", data=safety_profile, allowed=SAFETY_ALLOWED_KEYS)
        for key in SAFETY_ALLOWED_KEYS:
            value = safety_profile.get(key)
            if not isinstance(value, int):
                failures.append(f"safety_profile_{key}_must_be_int")
            elif value < 0 or value > 5:
                failures.append(f"safety_profile_{key}_out_of_range")

    for field in ("resolved_authority", "jurisdiction"):
        value = request.get(field)
        if not isinstance(value, str) or not value.strip():
            failures.append(f"{field}_required")
        elif len(value) > 128:
            failures.append(f"{field}_too_long")

    return len(failures) == 0, failures


def validate_api_body_schema(path: str, body: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not _is_mapping(body):
        return False, ["api_body_not_mapping"]
    allowed = API_BODY_ALLOWED_KEYS.get(path)
    if allowed is None:
        return False, ["api_path_schema_not_defined"]
    _append_unknown_keys(failures, prefix="api_body", data=body, allowed=allowed)
    _, shape_failures = validate_json_shape(body, root_name="api_body")
    failures.extend(shape_failures)

    if path in {"/runtime/traverse", "/runtime/replay", "/connector/build-envelope"}:
        request = body.get("request", body if path != "/connector/build-envelope" else None)
        if not _is_mapping(request):
            failures.append("request_required")
        else:
            _, request_failures = validate_runtime_request_schema(request)
            failures.extend(request_failures)

    request_id = body.get("request_id")
    if request_id is not None and (not isinstance(request_id, str) or not REQUEST_ID_PATTERN.match(request_id)):
        failures.append("invalid_request_id")

    if path == "/runtime/replay":
        replay_count = body.get("replay_count", 2)
        if not isinstance(replay_count, int):
            failures.append("replay_count_must_be_int")

    if path == "/connector/build-envelope":
        source = body.get("source", "manual")
        if not isinstance(source, str) or not SOURCE_PATTERN.match(source):
            failures.append("invalid_source")
        metadata = body.get("metadata", {})
        if not _is_mapping(metadata):
            failures.append("metadata_must_be_mapping")

    if path == "/connector/envelope":
        _, envelope_failures = validate_connector_envelope_schema(body)
        failures.extend(envelope_failures)

    pre_context = body.get("pre_context_signals")
    if pre_context is not None:
        _, signal_failures = validate_pre_context_signal_schema(pre_context)
        failures.extend(signal_failures)

    return len(failures) == 0, failures


def validate_connector_envelope_schema(envelope: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not _is_mapping(envelope):
        return False, ["envelope_not_mapping"]
    _, shape_failures = validate_json_shape(envelope, root_name="envelope")
    failures.extend(shape_failures)
    _append_unknown_keys(failures, prefix="envelope", data=envelope, allowed=CONNECTOR_ENVELOPE_ALLOWED_KEYS)
    if not isinstance(envelope.get("request_id"), str) or not REQUEST_ID_PATTERN.match(envelope.get("request_id", "")):
        failures.append("invalid_request_id")
    if not isinstance(envelope.get("source"), str) or not SOURCE_PATTERN.match(envelope.get("source", "")):
        failures.append("invalid_source")
    request = envelope.get("request")
    if not _is_mapping(request):
        failures.append("invalid_envelope_request")
    else:
        _, request_failures = validate_runtime_request_schema(request)
        failures.extend(request_failures)
    metadata = envelope.get("metadata", {})
    if not _is_mapping(metadata):
        failures.append("metadata_must_be_mapping")
    if envelope.get("digest") is not None and not isinstance(envelope.get("digest"), str):
        failures.append("digest_must_be_string")
    if envelope.get("signature") is not None and not _is_mapping(envelope.get("signature")):
        failures.append("signature_must_be_mapping")
    return len(failures) == 0, failures


def validate_pre_context_signal_schema(signals: Any) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not _is_mapping(signals):
        return False, ["pre_context_signals_not_mapping"]
    if len(signals) > MAX_PRE_CONTEXT_SIGNAL_KEYS:
        failures.append("pre_context_signal_key_limit_exceeded")
    _append_unknown_keys(failures, prefix="pre_context_signals", data=signals, allowed=PRE_CONTEXT_SIGNAL_ALLOWED_KEYS)
    _, shape_failures = validate_json_shape(signals, root_name="pre_context_signals")
    failures.extend(shape_failures)
    return len(failures) == 0, failures
