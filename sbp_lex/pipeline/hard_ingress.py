from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping
import unicodedata

from external_substrates.shared.validation import (
    PROHIBITED_AUTHORITY_KEYS,
    PROHIBITED_AUTHORITY_VALUES,
    contains_prohibited_authority,
)
from external_substrates.shared.canonical_json import canonical_dumps
from sbp_lex.api.schema_validation import (
    MAX_RUNTIME_REQUEST_BYTES,
    validate_pre_context_signal_schema,
    validate_runtime_request_schema,
)
from sbp_lex.collective.digital_twin_network_engine import verify_dtn_context
from sbp_lex.collective.sovereign_knowledge_graph_engine import verify_skg_context
from sbp_lex.runtime.boundary_types import (
    AdapterResult,
    EIEReplayRegistry,
    HardEntryAdmission,
    HardEntryResult,
)
from sbp_lex.security.pqc import (
    generate_digest,
    verify_signature,
)
from sbp_lex.shared.control_chain_validation import validate_eie_binding
from sbp_lex.shared.state_builder import build_execution_intent_envelope


ADAPTER_SCHEMA_VERSION = "desktop-v1.request-adapter.v1"
HARD_ENTRY_SCHEMA_VERSION = "desktop-v1.hard-entry-admission.v1"
COLLECTIVE_SIGNAL_SCHEMA_VERSION = "desktop-v1.collective-signal.v1"
REQUIRED_REQUEST_FIELDS = ("action", "payload")
REQUIRED_SIGNAL_FIELDS = (
    "collective_signal_schema_version",
    "request_fingerprint",
    "eie_digest",
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
    "freshness_window_seconds",
    "nonce",
)
CANONICAL_SIGNAL_AUTHORITY = "CANONICAL_RUNTIME"
PROHIBITED_EXTERNAL_AUTHORITY_KEYS = PROHIBITED_AUTHORITY_KEYS
PROHIBITED_EXTERNAL_AUTHORITY_VALUES = PROHIBITED_AUTHORITY_VALUES
DIRECT_STATE_INJECTION_KEYS = frozenset({
    "state",
    "state_hash",
    "state_version",
    "state_schema_version",
    "request_identity_snapshot",
    "hard_entry_gate",
    "boundary_protection",
    "verified_substrate_references",
    "collective_signals",
    "collective_attachment",
    "tokens",
    "classification_result",
    "licensing_result",
    "domain_result",
    "aurion15_result",
    "authority_first_result",
    "procedural_truth_result",
})
SUBSTRATE_EVIDENCE_ALLOWED_FIELDS = frozenset({
    "runtime",
    "authority_role",
    "provider_mode",
    "request_fingerprint",
    "eie_digest",
    "skg_package_reference",
    "skg_package_digest",
    "skg_validation_status",
    "dtn_package_reference",
    "dtn_package_digest",
    "dtn_validation_status",
    "bridge_validation_status",
    "bridge_result_digest",
    "signature_mode",
    "fixture_issued_at",
    "validation_time",
    "stage_order",
    "raw_packages_crossed_hard_entry",
    "direct_state_write",
})


def _canonical_signal_timestamp(request_fingerprint: str) -> int:
    return int(str(request_fingerprint)[:12], 16)


def _canonical_signal_nonce(
    request_fingerprint: str, eie_digest: str, timestamp: int
) -> str:
    return generate_digest({
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie_digest,
        "timestamp": timestamp,
        "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
    })[:32]


def _normalize_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("adapter_non_string_key")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized:
                raise ValueError("adapter_unicode_key_collision")
            normalized[key] = _normalize_json(item)
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"adapter_unsupported_type:{type(value).__name__}")


def _contains_injected_state_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key) in DIRECT_STATE_INJECTION_KEYS
            or _contains_injected_state_key(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_injected_state_key(item) for item in value)
    return False


def adapt_external_request(
    request: Mapping[str, Any],
) -> tuple[AdapterResult | None, list[str]]:
    failures: list[str] = []
    if not isinstance(request, Mapping):
        return None, ["request_not_mapping"]
    for field in REQUIRED_REQUEST_FIELDS:
        if field not in request:
            failures.append(f"missing_request_field:{field}")
    schema_ok, schema_failures = validate_runtime_request_schema(request)
    if not schema_ok:
        failures.extend(schema_failures)
    if _contains_injected_state_key(request):
        failures.append("direct_internal_state_injection_rejected")
    try:
        normalized = _normalize_json(request)
        normalized_json = canonical_dumps(normalized)
    except (TypeError, ValueError) as exc:
        failures.append(str(exc))
        return None, sorted(set(failures))
    size = len(normalized_json.encode("utf-8"))
    if size > MAX_RUNTIME_REQUEST_BYTES:
        failures.append("request_size_limit_exceeded")
    normalized_ok, normalized_failures = validate_runtime_request_schema(
        normalized
    )
    if not normalized_ok:
        failures.extend(normalized_failures)
    if failures:
        return None, sorted(set(failures))
    fingerprint = generate_digest(normalized)
    adapter_payload = {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "normalized_request_digest": fingerprint,
        "request_fingerprint": fingerprint,
        "input_size_bytes": size,
    }
    return AdapterResult(
        schema_version=ADAPTER_SCHEMA_VERSION,
        normalized_request_json=normalized_json,
        normalized_request_digest=fingerprint,
        request_fingerprint=fingerprint,
        input_size_bytes=size,
        adapter_digest=generate_digest(adapter_payload),
    ), []


def validate_request_ingress(
    request: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    adapter, failures = adapt_external_request(request)
    return adapter is not None and not failures, failures


def _signal_payload_for_digest(signals: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in dict(signals).items()
        if key not in {"digest", "signature"}
    }


def _contains_external_authority(value: Any) -> bool:
    return contains_prohibited_authority(value)


def validate_pre_context_signal_package(
    *,
    signals: Mapping[str, Any] | None,
    request_fingerprint: str,
    expected_eie_digest: str | None = None,
    validation_logical_time: int | None = None,
    require_signature: bool = True,
) -> tuple[bool, list[str]]:
    if signals is None:
        return False, ["pre_context_signals_required"]
    failures: list[str] = []
    if not isinstance(signals, Mapping):
        return False, ["signals_not_mapping"]
    schema_ok, schema_failures = validate_pre_context_signal_schema(signals)
    if not schema_ok:
        failures.extend(schema_failures)
    for field in REQUIRED_SIGNAL_FIELDS:
        if field not in signals:
            failures.append(f"missing_signal_field:{field}")
    if _contains_external_authority(signals):
        failures.append("external_signal_contains_authority_result")
    if failures:
        return False, sorted(set(failures))
    if signals.get("collective_signal_schema_version") != (
        COLLECTIVE_SIGNAL_SCHEMA_VERSION
    ):
        failures.append("collective_signal_schema_version_invalid")
    if signals.get("request_fingerprint") != request_fingerprint:
        failures.append("signal_request_fingerprint_mismatch")
    if (
        expected_eie_digest is not None
        and signals.get("eie_digest") != expected_eie_digest
    ):
        failures.append("signal_eie_digest_mismatch")
    timestamp = signals.get("timestamp")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        failures.append("invalid_signal_timestamp")
    else:
        expected_timestamp = _canonical_signal_timestamp(request_fingerprint)
        if timestamp != expected_timestamp:
            failures.append("signal_timestamp_not_canonical")
    if signals.get("timestamp_authority") != CANONICAL_SIGNAL_AUTHORITY:
        failures.append("signal_timestamp_authority_invalid")
    window = signals.get("freshness_window_seconds")
    if not isinstance(window, int) or isinstance(window, bool) or window < 0:
        failures.append("signal_freshness_window_invalid")
    elif isinstance(timestamp, int) and validation_logical_time is not None:
        age = validation_logical_time - timestamp
        if age < 0 or age > window:
            failures.append("stale_collective_signal")
    expected_nonce = (
        _canonical_signal_nonce(
            request_fingerprint,
            str(signals.get("eie_digest", "")),
            timestamp,
        )
        if isinstance(timestamp, int) and not isinstance(timestamp, bool)
        else None
    )
    if not isinstance(signals.get("nonce"), str) or not signals.get(
        "nonce", ""
    ).strip():
        failures.append("invalid_signal_nonce")
    elif expected_nonce is not None and signals.get("nonce") != expected_nonce:
        failures.append("signal_nonce_not_canonical")
    payload = _signal_payload_for_digest(signals)
    if signals.get("digest") != generate_digest(payload):
        failures.append("signal_digest_mismatch")
    if require_signature and not verify_signature(
        payload, signals.get("signature", {})
    ):
        failures.append("signal_signature_invalid")
    skg_context = signals.get("skg_context")
    dtn_context = signals.get("dtn_context")
    skg_valid, skg_failures = verify_skg_context(
        skg_context if isinstance(skg_context, Mapping) else {}
    )
    if not skg_valid:
        failures.extend(skg_failures)
    dtn_valid, dtn_failures = verify_dtn_context(
        dtn_context if isinstance(dtn_context, Mapping) else {},
        expected_skg_digest=signals.get("skg_digest"),
    )
    if not dtn_valid:
        failures.extend(dtn_failures)
    return not failures, sorted(set(failures))


def _bridge_payload(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "bridge_validation_status": evidence.get("bridge_validation_status"),
        "request_fingerprint": evidence.get("request_fingerprint"),
        "eie_digest": evidence.get("eie_digest"),
        "skg_package_digest": evidence.get("skg_package_digest"),
        "dtn_package_digest": evidence.get("dtn_package_digest"),
    }


def _substrate_evidence(
    *, signals: Mapping[str, Any], eie: Mapping[str, Any]
) -> dict[str, Any]:
    supplied = signals.get("synthetic_substrate_evidence")
    if isinstance(supplied, Mapping):
        return deepcopy(dict(supplied))
    references = eie.get("external_substrate_references", {})
    evidence: dict[str, Any] = {
        "runtime": "DESKTOP_V1_SIGNED_LOCAL_CONTEXT",
        "authority_role": "context_only_non_authoritative",
        "provider_mode": "synthetic_local",
        "request_fingerprint": eie.get("request_fingerprint"),
        "eie_digest": eie.get("eie_hash"),
        "skg_package_reference": references.get("skg_package_reference"),
        "skg_package_digest": signals.get("skg_digest"),
        "skg_validation_status": "VALID",
        "dtn_package_reference": references.get("dtn_package_reference"),
        "dtn_package_digest": signals.get("dtn_digest"),
        "dtn_validation_status": "VALID",
        "bridge_validation_status": "PASS",
        "signature_mode": "CANONICAL_RUNTIME_PQC",
        "raw_packages_crossed_hard_entry": False,
        "direct_state_write": False,
    }
    evidence["bridge_result_digest"] = generate_digest(
        _bridge_payload(evidence)
    )
    return evidence


def _validate_substrate_evidence(
    *,
    evidence: Mapping[str, Any],
    eie: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if set(evidence).difference(SUBSTRATE_EVIDENCE_ALLOWED_FIELDS):
        failures.append("substrate_evidence_unknown_field")
    if evidence.get("request_fingerprint") != eie.get("request_fingerprint"):
        failures.append("substrate_request_fingerprint_mismatch")
    if evidence.get("eie_digest") != eie.get("eie_hash"):
        failures.append("substrate_eie_digest_mismatch")
    references = eie.get("external_substrate_references", {})
    if evidence.get("skg_package_reference") != references.get(
        "skg_package_reference"
    ):
        failures.append("skg_package_reference_mismatch")
    if evidence.get("dtn_package_reference") != references.get(
        "dtn_package_reference"
    ):
        failures.append("dtn_package_reference_mismatch")
    for field in (
        "skg_package_digest",
        "dtn_package_digest",
        "bridge_result_digest",
    ):
        if not isinstance(evidence.get(field), str) or not evidence.get(field):
            failures.append(f"substrate_evidence_missing:{field}")
    if evidence.get("skg_validation_status") != "VALID":
        failures.append("skg_validation_status_rejected")
    if evidence.get("dtn_validation_status") != "VALID":
        failures.append("dtn_validation_status_rejected")
    if evidence.get("bridge_validation_status") != "PASS":
        failures.append("bridge_validation_status_rejected")
    if evidence.get("raw_packages_crossed_hard_entry") is not False:
        failures.append("raw_substrate_package_injection_rejected")
    if evidence.get("direct_state_write") is not False:
        failures.append("direct_state_write_rejected")
    if evidence.get("bridge_result_digest") != generate_digest(
        _bridge_payload(evidence)
    ):
        failures.append("bridge_result_digest_mismatch")
    return not failures, sorted(set(failures))


def _validate_eie_for_entry(
    *,
    adapter: AdapterResult,
    eie: Mapping[str, Any],
    validation_logical_time: int,
) -> list[str]:
    request = adapter.normalized_request()
    temporary_state = {
        "eie": eie,
        "eie_hash": eie.get("eie_hash"),
        "request_identity_snapshot": request,
        "source_payload_hash": eie.get("source_payload_hash"),
        "request_fingerprint": adapter.request_fingerprint,
        "traversal_id": eie.get("traversal_id"),
    }
    valid, failures = validate_eie_binding(temporary_state)
    result = list(failures) if not valid else []
    freshness = eie.get("freshness", {})
    if isinstance(freshness, Mapping):
        issued_at = freshness.get("issued_at")
        valid_until = freshness.get("valid_until")
        if (
            not isinstance(issued_at, int)
            or not isinstance(valid_until, int)
            or validation_logical_time < issued_at
            or validation_logical_time > valid_until
        ):
            result.append("stale_eie")
    else:
        result.append("eie_freshness_schema_invalid")
    return sorted(set(result))


def _denial_evidence(
    *,
    failures: list[str],
    adapter: AdapterResult | None,
    eie: Mapping[str, Any] | None,
    stopped_at: str,
) -> dict[str, Any]:
    payload = {
        "object_type": "HardEntryDenialEvidence",
        "schema_version": "desktop-v1.hard-entry-denial.v1",
        "accepted": False,
        "governed_state_formed": False,
        "authority_token_issued": False,
        "governance_result_issued": False,
        "downstream_stage_reached": False,
        "stopped_at": stopped_at,
        "failures": sorted(set(failures)),
        "normalized_request_digest": (
            adapter.normalized_request_digest if adapter else None
        ),
        "request_fingerprint": adapter.request_fingerprint if adapter else None,
        "eie_digest": eie.get("eie_hash") if isinstance(eie, Mapping) else None,
    }
    return {**payload, "denial_evidence_digest": generate_digest(payload)}


def run_hard_ingress(
    *,
    request: Mapping[str, Any],
    pre_context_signals: Mapping[str, Any] | None = None,
    validation_logical_time: int | None = None,
    replay_registry: EIEReplayRegistry | None = None,
) -> HardEntryResult:
    adapter, adapter_failures = adapt_external_request(request)
    if adapter is None:
        evidence = _denial_evidence(
            failures=adapter_failures,
            adapter=None,
            eie=None,
            stopped_at="adapter",
        )
        return HardEntryResult(False, None, canonical_dumps(evidence))
    adapter_valid, adapter_seal_failures = adapter.validate()
    if not adapter_valid:
        evidence = _denial_evidence(
            failures=adapter_seal_failures,
            adapter=adapter,
            eie=None,
            stopped_at="adapter",
        )
        return HardEntryResult(False, None, canonical_dumps(evidence))
    normalized_request = adapter.normalized_request()
    eie = build_execution_intent_envelope(normalized_request)
    freshness = eie.get("freshness", {})
    logical_time = (
        validation_logical_time
        if validation_logical_time is not None
        else int(freshness.get("issued_at", -1))
    )
    eie_failures = _validate_eie_for_entry(
        adapter=adapter,
        eie=eie,
        validation_logical_time=logical_time,
    )
    if eie_failures:
        evidence = _denial_evidence(
            failures=eie_failures,
            adapter=adapter,
            eie=eie,
            stopped_at="eie",
        )
        return HardEntryResult(False, None, canonical_dumps(evidence))

    signals: Mapping[str, Any] | None = pre_context_signals
    substrate_failures: list[str] = []
    if signals is None:
        from sbp_lex.runtime.synthetic_substrates import (
            prepare_synthetic_substrate_signals,
        )

        substrate = prepare_synthetic_substrate_signals(
            normalized_request, eie=eie
        )
        signals = substrate.signals
        substrate_failures.extend(substrate.failures)
    signal_valid, signal_failures = validate_pre_context_signal_package(
        signals=signals,
        request_fingerprint=adapter.request_fingerprint,
        expected_eie_digest=str(eie.get("eie_hash", "")),
        validation_logical_time=logical_time,
        require_signature=True,
    )
    if not signal_valid:
        substrate_failures.extend(signal_failures)
    evidence = (
        _substrate_evidence(signals=signals, eie=eie)
        if isinstance(signals, Mapping)
        else {}
    )
    evidence_valid, evidence_failures = _validate_substrate_evidence(
        evidence=evidence,
        eie=eie,
    )
    if not evidence_valid:
        substrate_failures.extend(evidence_failures)
    if substrate_failures or not isinstance(signals, Mapping):
        evidence_record = _denial_evidence(
            failures=substrate_failures or ["pre_context_signals_required"],
            adapter=adapter,
            eie=eie,
            stopped_at="hard_entry",
        )
        return HardEntryResult(False, None, canonical_dumps(evidence_record))

    replay = replay_registry or EIEReplayRegistry()
    replay_valid, replay_failures = replay.validate_and_record(
        nonce=str(eie.get("replay", {}).get("nonce", "")),
        eie_digest=str(eie.get("eie_hash", "")),
    )
    if not replay_valid:
        evidence_record = _denial_evidence(
            failures=replay_failures,
            adapter=adapter,
            eie=eie,
            stopped_at="hard_entry",
        )
        return HardEntryResult(False, None, canonical_dumps(evidence_record))

    admission_stub = HardEntryAdmission(
        schema_version=HARD_ENTRY_SCHEMA_VERSION,
        adapter=adapter,
        eie_json=canonical_dumps(eie),
        eie_digest=str(eie["eie_hash"]),
        collective_signal_json=canonical_dumps(signals),
        collective_signal_digest=str(signals["digest"]),
        substrate_evidence_json=canonical_dumps(evidence),
        bridge_result_digest=str(evidence["bridge_result_digest"]),
        validation_logical_time=logical_time,
        admission_digest="",
    )
    admission = HardEntryAdmission(
        **{
            **admission_stub.__dict__,
            "admission_digest": generate_digest(admission_stub.digest_payload()),
        }
    )
    admission_valid, admission_failures = admission.validate_seal()
    if not admission_valid:
        evidence_record = _denial_evidence(
            failures=admission_failures,
            adapter=adapter,
            eie=eie,
            stopped_at="hard_entry",
        )
        return HardEntryResult(False, None, canonical_dumps(evidence_record))
    accepted_payload = {
        "object_type": "HardEntryAcceptanceEvidence",
        "schema_version": HARD_ENTRY_SCHEMA_VERSION,
        "accepted": True,
        "request_fingerprint": adapter.request_fingerprint,
        "normalized_request_digest": adapter.normalized_request_digest,
        "eie_digest": admission.eie_digest,
        "skg_package_digest": evidence.get("skg_package_digest"),
        "dtn_package_digest": evidence.get("dtn_package_digest"),
        "bridge_result_digest": admission.bridge_result_digest,
        "collective_signal_digest": admission.collective_signal_digest,
        "admission_digest": admission.admission_digest,
    }
    accepted_evidence = {
        **accepted_payload,
        "acceptance_evidence_digest": generate_digest(accepted_payload),
    }
    return HardEntryResult(True, admission, canonical_dumps(accepted_evidence))
