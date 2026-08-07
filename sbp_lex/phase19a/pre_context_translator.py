from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from external_substrates.dtn.signal_builder import validate_dtn_signal_package
from external_substrates.shared.pre_context_package import validate_pre_context_package
from external_substrates.shared.validation import contains_prohibited_authority
from external_substrates.skg.signal_builder import validate_skg_signal_package

from sbp_lex.pipeline.hard_ingress import (
    CANONICAL_SIGNAL_AUTHORITY,
    validate_pre_context_signal_package,
)
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.shared.state_builder import (
    EIE_FRESHNESS_WINDOW_SECONDS,
    build_execution_intent_envelope,
)

REQUIRED_EXTERNAL_SIGNALS = {
    "authority_link_signal",
    "jurisdiction_signal",
    "precedence_signal",
    "policy_conflict_signal",
    "operational_context_signal",
    "dependency_signal",
    "risk_potential_signal",
}

PHASE19A_PROHIBITED_AUTHORITY_KEYS = {
    "governance_result",
    "classification_result",
    "licensing_result",
    "domain_result",
    "aurion_result",
    "aurion15_result",
    "execution_permission",
    "execution_result",
    "execution_verified",
    "final_admissibility",
}
PHASE19A_PROHIBITED_AUTHORITY_VALUES = {"ALLOW", "DENY", "ESCALATE", "EXECUTE", "HALT"}


@dataclass(frozen=True)
class TranslationResult:
    accepted: bool
    signals: dict[str, Any] | None
    failures: tuple[str, ...]
    evidence: dict[str, Any]


def translate_external_pre_context_package(
    *,
    request: Mapping[str, Any],
    package: Mapping[str, Any],
    skg_package: Mapping[str, Any] | None,
    dtn_package: Mapping[str, Any] | None,
) -> TranslationResult:
    """Validate external SKG/DTN evidence and translate it into runtime-local signals.

    The translator does not allow the external package to traverse directly and
    does not import external decisions, governance results, or execution claims.
    It only re-expresses bounded context into the existing Hard Entry package
    shape, signed by the local runtime provider.
    """

    failures: list[str] = []
    if not isinstance(request, Mapping):
        return _reject(["request_not_mapping"])
    if not isinstance(package, Mapping):
        return _reject(["external_package_not_mapping"])

    request_fingerprint = generate_digest(dict(request))
    package_fingerprint = package.get("request_fingerprint")
    if package_fingerprint != request_fingerprint:
        failures.append("external_package_request_fingerprint_unbound")

    if skg_package is None:
        failures.append("skg_package_unavailable")
    elif not validate_skg_signal_package(skg_package):
        failures.append("skg_package_invalid")

    if dtn_package is None:
        failures.append("dtn_package_unavailable")
    elif skg_package is not None and not validate_dtn_signal_package(
        dtn_package, skg_constraint_package=skg_package
    ):
        failures.append("dtn_package_invalid_or_not_skg_constrained")

    if skg_package is not None and dtn_package is not None:
        if not validate_pre_context_package(
            package, skg_package=skg_package, dtn_package=dtn_package
        ):
            failures.append("external_pre_context_package_invalid")

    if contains_prohibited_authority(package) or _contains_phase19a_authority(package):
        failures.append("external_package_contains_authority")

    _validate_metadata_readiness(package, failures)
    signal_payloads = _extract_signal_payloads(package, failures)
    _validate_semantic_failure_markers(package, signal_payloads, failures)

    if failures:
        return _reject(failures)

    skg_context = _build_runtime_skg_context(request, signal_payloads)
    dtn_context = _build_runtime_dtn_context(signal_payloads, skg_context)
    eie = build_execution_intent_envelope(request)
    runtime_signals = {
        "collective_signal_schema_version": "desktop-v1.collective-signal.v1",
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie["eie_hash"],
        "intent_signal": _intent_signal(request),
        "risk_potential_signal": signal_payloads["risk_potential_signal"],
        "authority_link_signal": skg_context["authority_link_signal"],
        "jurisdiction_signal": skg_context["jurisdiction_signal"],
        "dependency_signal": dtn_context["dependency_signal"],
        "policy_conflict_signal": skg_context["policy_conflict_signal"],
        "operational_context_signal": dtn_context["operational_context_signal"],
        "precedence_signal": skg_context["precedence_signal"],
        "skg_digest": skg_context["skg_digest"],
        "dtn_digest": dtn_context["dtn_digest"],
        "skg_context": skg_context,
        "dtn_context": dtn_context,
        "timestamp": _canonical_signal_timestamp(request_fingerprint),
        "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
        "freshness_window_seconds": EIE_FRESHNESS_WINDOW_SECONDS,
    }
    runtime_signals["nonce"] = _canonical_signal_nonce(
        request_fingerprint,
        eie["eie_hash"],
        runtime_signals["timestamp"],
    )
    body = deepcopy(runtime_signals)
    runtime_signals["digest"] = generate_digest(body)
    runtime_signals["signature"] = sign_payload(body)

    valid, hard_entry_failures = validate_pre_context_signal_package(
        signals=runtime_signals,
        request_fingerprint=request_fingerprint,
        expected_eie_digest=eie["eie_hash"],
        validation_logical_time=runtime_signals["timestamp"],
    )
    if not valid:
        return _reject([f"translated_signal_{failure}" for failure in hard_entry_failures])

    evidence = {
        "translator": "PHASE19A_BOUNDED_EXTERNAL_PRE_CONTEXT_TRANSLATOR",
        "runtime_attached": False,
        "authority_role": "context_only_non_authoritative",
        "request_fingerprint": request_fingerprint,
        "external_package_digest": package.get("digest"),
        "skg_package_digest": package.get("skg_package_digest"),
        "dtn_package_digest": package.get("dtn_package_digest"),
    }
    return TranslationResult(True, runtime_signals, (), evidence)


def _reject(failures: list[str]) -> TranslationResult:
    return TranslationResult(
        accepted=False,
        signals=None,
        failures=tuple(dict.fromkeys(failures)),
        evidence={
            "translator": "PHASE19A_BOUNDED_EXTERNAL_PRE_CONTEXT_TRANSLATOR",
            "runtime_attached": False,
            "authority_role": "context_only_non_authoritative",
        },
    )


def _validate_metadata_readiness(package: Mapping[str, Any], failures: list[str]) -> None:
    skg_metadata = package.get("skg_truth_foundation_metadata", {})
    dtn_metadata = package.get("dtn_contextual_verification_metadata", {})
    if not isinstance(skg_metadata, Mapping):
        failures.append("skg_metadata_missing")
    else:
        if skg_metadata.get("skg_verification_status") != "VALID":
            failures.append("skg_verification_not_valid")
        if skg_metadata.get("truth_foundation_readiness_status") != "READY":
            failures.append("skg_truth_foundation_not_ready")
    if not isinstance(dtn_metadata, Mapping):
        failures.append("dtn_metadata_missing")
    else:
        if dtn_metadata.get("dtn_contextualisation_status") != "VALID":
            failures.append("dtn_contextualisation_not_valid")
        if dtn_metadata.get("contextual_readiness_status") != "READY":
            failures.append("dtn_contextual_readiness_not_ready")


def _extract_signal_payloads(
    package: Mapping[str, Any], failures: list[str]
) -> dict[str, dict[str, Any]]:
    signals = package.get("signals")
    if not isinstance(signals, Mapping):
        failures.append("external_signals_missing")
        return {}
    missing = REQUIRED_EXTERNAL_SIGNALS.difference(signals)
    if missing:
        failures.extend(f"external_signal_missing:{name}" for name in sorted(missing))
        return {}
    payloads: dict[str, dict[str, Any]] = {}
    for name in sorted(REQUIRED_EXTERNAL_SIGNALS):
        signal = signals.get(name)
        if not isinstance(signal, Mapping) or not isinstance(signal.get("payload"), Mapping):
            failures.append(f"external_signal_payload_invalid:{name}")
            continue
        payload = deepcopy(dict(signal["payload"]))
        if contains_prohibited_authority(payload) or _contains_phase19a_authority(payload):
            failures.append(f"external_signal_payload_contains_authority:{name}")
        payloads[name] = payload
    return payloads


def _validate_semantic_failure_markers(
    package: Mapping[str, Any],
    payloads: Mapping[str, Mapping[str, Any]],
    failures: list[str],
) -> None:
    skg_metadata = package.get("skg_truth_foundation_metadata", {})
    dtn_metadata = package.get("dtn_contextual_verification_metadata", {})
    if isinstance(skg_metadata, Mapping):
        provenance = skg_metadata.get("provenance_metadata")
        source_map = skg_metadata.get("source_independence_mapping", {})
        if not provenance or not isinstance(provenance, list):
            failures.append("skg_truth_foundation_insufficient")
        elif isinstance(source_map, Mapping) and int(source_map.get("source_count", 0) or 0) < 1:
            failures.append("skg_truth_foundation_insufficient")
        if skg_metadata.get("attestation_status") != "VALID":
            failures.append("skg_truth_foundation_insufficient")
        if _truthy_conflict(skg_metadata.get("contradiction_indicators")):
            failures.append("skg_conflict_detected")
    if _truthy_conflict(payloads.get("policy_conflict_signal")):
        failures.append("skg_conflict_detected")

    if isinstance(dtn_metadata, Mapping):
        if dtn_metadata.get("runtime_world_correspondence") is not True:
            failures.append("dtn_environmental_mismatch")
        if dtn_metadata.get("physical_world_digital_state_alignment") is not True:
            failures.append("dtn_environmental_mismatch")
        if dtn_metadata.get("state_correspondence_verification") is not True:
            failures.append("dtn_context_conflict")
        if _truthy_conflict(dtn_metadata.get("consequence_context")):
            failures.append("dtn_context_conflict")
    operational = payloads.get("operational_context_signal", {})
    dependency = payloads.get("dependency_signal", {})
    if isinstance(operational, Mapping) and (
        operational.get("environment_mismatch") is True
        or operational.get("context_conflict") is True
        or operational.get("freshness_status") == "STALE"
    ):
        if operational.get("freshness_status") == "STALE":
            failures.append("dtn_context_stale")
        elif operational.get("environment_mismatch") is True:
            failures.append("dtn_environmental_mismatch")
        else:
            failures.append("dtn_context_conflict")
    if isinstance(dependency, Mapping) and (
        dependency.get("dependency_mismatch") is True
        or dependency.get("dependency_available") is False
        or dependency.get("available") is False
    ):
        failures.append("dtn_dependency_mismatch")


def _truthy_conflict(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("conflict_detected") is True or value.get("valid") is False:
            return True
        for key in ("conflicts", "unresolved_conflicts", "contradictions"):
            item = value.get(key)
            if isinstance(item, list) and len(item) > 0:
                return True
        return any(_truthy_conflict(item) for item in value.values())
    if isinstance(value, list):
        return any(_truthy_conflict(item) for item in value)
    return False


def _contains_phase19a_authority(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            key in PHASE19A_PROHIBITED_AUTHORITY_KEYS
            or _contains_phase19a_authority(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_phase19a_authority(item) for item in value)
    return isinstance(value, str) and value.strip().upper() in PHASE19A_PROHIBITED_AUTHORITY_VALUES


def _build_runtime_skg_context(
    request: Mapping[str, Any], payloads: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    context = request.get("context", {}) if isinstance(request.get("context"), Mapping) else {}
    authority_payload = dict(payloads.get("authority_link_signal", {}))
    jurisdiction_payload = dict(payloads.get("jurisdiction_signal", {}))
    authority_signal = {
        **authority_payload,
        "resolved_authority": request.get(
            "resolved_authority", context.get("resolved_authority", "UNRESOLVED")
        ),
        "authority_declared": bool(
            request.get("resolved_authority") or context.get("resolved_authority")
        ),
        "authority_source": "phase19a_external_skg_translation",
    }
    jurisdiction_signal = {
        **jurisdiction_payload,
        "jurisdiction": request.get("jurisdiction", context.get("jurisdiction", "UNRESOLVED")),
        "jurisdiction_declared": bool(request.get("jurisdiction") or context.get("jurisdiction")),
        "jurisdiction_source": "phase19a_external_skg_translation",
    }
    payload = {
        "authority_link_signal": authority_signal,
        "jurisdiction_signal": jurisdiction_signal,
        "policy_conflict_signal": dict(payloads["policy_conflict_signal"]),
        "precedence_signal": dict(payloads["precedence_signal"]),
    }
    signed_payload = {**payload, "skg_digest": generate_digest(payload)}
    return {**signed_payload, "skg_signature": sign_payload(signed_payload)}


def _build_runtime_dtn_context(
    payloads: Mapping[str, Mapping[str, Any]], skg_context: Mapping[str, Any]
) -> dict[str, Any]:
    payload = {
        "dependency_signal": dict(payloads["dependency_signal"]),
        "operational_context_signal": dict(payloads["operational_context_signal"]),
        "risk_potential_signal": dict(payloads["risk_potential_signal"]),
        "skg_constraint_digest": skg_context.get("skg_digest"),
    }
    signed_payload = {**payload, "dtn_digest": generate_digest(payload)}
    return {**signed_payload, "dtn_signature": sign_payload(signed_payload)}


def _intent_signal(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "action": request.get("action"),
        "payload_digest": generate_digest(request.get("payload", {})),
        "source": "phase19a_external_pre_context_translation",
    }


def _canonical_signal_timestamp(request_fingerprint: str) -> int:
    return int(request_fingerprint[:12], 16)


def _canonical_signal_nonce(
    request_fingerprint: str, eie_digest: str, timestamp: int
) -> str:
    return generate_digest(
        {
            "request_fingerprint": request_fingerprint,
            "eie_digest": eie_digest,
            "timestamp": timestamp,
            "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
        }
    )[:32]
