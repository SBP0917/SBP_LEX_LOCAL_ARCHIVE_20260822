from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from external_substrates.dtn.capability_model import model_capabilities
from external_substrates.dtn.cascading_impact_engine import evaluate_cascading_impact
from external_substrates.dtn.constraint_applier import apply_skg_constraints
from external_substrates.dtn.context_ingestor import ingest_context
from external_substrates.dtn.dependency_model import model_dependencies
from external_substrates.dtn.environment_model import model_environment
from external_substrates.dtn.feasibility_engine import evaluate_feasibility
from external_substrates.dtn.operational_state_engine import model_operational_state
from external_substrates.dtn.pathway_model import model_pathway
from external_substrates.dtn.risk_potential_engine import evaluate_risk_potential
from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.freshness import utc_timestamp
from external_substrates.shared.package_identity import package_identity
from external_substrates.shared.source_crypto import sign_source_package, source_signature_shape_valid
from external_substrates.shared.signal_envelope import build_signal_envelope, validate_signal_envelope
from external_substrates.shared.signing import sign_payload, verify_signature
from external_substrates.shared.source_attestation import summarise_sources
from external_substrates.shared.validation import contains_prohibited_authority

DTN_SIGNAL_TYPES = (
    "operational_context_signal",
    "dependency_signal",
    "capability_signal",
    "feasibility_signal",
    "risk_potential_signal",
    "cascading_impact_signal",
    "pathway_context_signal",
)
DTN_PACKAGE_VERSION = "1.0"


def _package_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key not in {"digest", "signature"}}


def _signature_body(package: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in package.items() if key != "signature"}


def build_dtn_signal_package(
    *,
    request_fingerprint: str,
    skg_constraint_package: Mapping[str, Any],
    context: Mapping[str, Any],
    source_records: Sequence[Mapping[str, Any]],
    timestamp: str | None = None,
    signing_key: str | bytes | None = None,
    transport_identity: str = "desktop-v1-local-adapter",
    source_private_key: bytes | None = None,
    source_key_id: str | None = None,
    source_signer_id: str | None = None,
) -> dict[str, Any]:
    if skg_constraint_package.get("request_fingerprint") != request_fingerprint:
        raise ValueError("SKG and DTN request fingerprints must match")
    constraints = apply_skg_constraints(skg_constraint_package)
    if constraints.get("valid") is not True:
        raise ValueError("SKG constraints are unresolved")
    ingested = ingest_context(context)
    dependencies = model_dependencies(ingested.get("dependencies", []))
    capabilities = model_capabilities(ingested.get("capabilities", []))
    pathway = model_pathway(ingested.get("pathway", {}), constraints)
    feasibility = evaluate_feasibility(dependencies, capabilities, pathway)
    cascading = evaluate_cascading_impact(ingested)
    risk = evaluate_risk_potential(ingested, cascading)
    payloads: dict[str, Mapping[str, Any]] = {
        "operational_context_signal": {
            "environment": model_environment(ingested),
            "operational_state": model_operational_state(ingested),
        },
        "dependency_signal": dependencies,
        "capability_signal": capabilities,
        "feasibility_signal": feasibility,
        "risk_potential_signal": risk,
        "cascading_impact_signal": cascading,
        "pathway_context_signal": pathway,
    }
    package_timestamp = timestamp or utc_timestamp()
    sources = [deepcopy(dict(source)) for source in source_records]
    constraint_digest = str(constraints["skg_constraint_digest"])
    signals = {
        signal_type: build_signal_envelope(
            request_fingerprint=request_fingerprint,
            signal_type=signal_type,
            payload=payloads[signal_type],
            source_records=sources,
            timestamp=package_timestamp,
            signing_key=signing_key,
            extra={"skg_constraint_digest": constraint_digest},
        )
        for signal_type in DTN_SIGNAL_TYPES
    }
    package: dict[str, Any] = {
        "package_type": "external_dtn_signal_package",
        "package_version": DTN_PACKAGE_VERSION,
        "schema_version": DTN_PACKAGE_VERSION,
        "request_fingerprint": request_fingerprint,
        "skg_constraint_digest": constraint_digest,
        "signals": signals,
        "source_records": sources,
        "source_summary": summarise_sources(sources),
        "dtn_contextual_verification_metadata": {
            "locality_context": ingested.get("locality", {}),
            "landscape_context": ingested.get("landscape", {}),
            "close_proximity_situational_context": ingested.get("proximity", {}),
            "operational_state_context": payloads["operational_context_signal"],
            "environmental_context": payloads["operational_context_signal"].get("environment", {}),
            "infrastructure_relevance": ingested.get("infrastructure", {}),
            "system_state_relevance": payloads["operational_context_signal"].get("operational_state", {}),
            "runtime_world_correspondence": True,
            "physical_world_digital_state_alignment": True,
            "consequence_context": risk,
            "affected_assets": ingested.get("assets", []),
            "affected_dependencies": dependencies,
            "cascading_effect_indicators": cascading,
            "state_correspondence_verification": True,
            "dtn_contextualisation_status": "VALID",
            "contextual_readiness_status": "READY",
        },
        "freshness_valid": all(signal["freshness_valid"] for signal in signals.values()),
        "consistency_valid": all(signal["consistency_valid"] for signal in signals.values()),
        "timestamp": package_timestamp,
        "issued_at": package_timestamp,
        "transport_identity": transport_identity,
    }
    package["package_id"] = package_identity(
        package_type=package["package_type"],
        package_version=package["package_version"],
        request_fingerprint=request_fingerprint,
        issued_at=package_timestamp,
        source_digests=[str(source.get("digest")) for source in sources],
        transport_identity=transport_identity,
    )
    package["dtn_contextual_verification_metadata"]["dtn_enrichment_hash"] = digest_mapping(
        package["dtn_contextual_verification_metadata"]
    )
    package["digest"] = digest_mapping(_package_body(package))
    package["signature"] = sign_payload(_signature_body(package), signing_key)
    if source_private_key is not None:
        if not source_key_id or not source_signer_id:
            raise ValueError("managed source key identity is required")
        package = sign_source_package(
            package, private_key=source_private_key, source_id=source_signer_id,
            key_id=source_key_id, substrate_type="DTN",
        )
    return package


def validate_dtn_signal_package(
    package: Mapping[str, Any],
    *,
    skg_constraint_package: Mapping[str, Any] | None = None,
    verification_key: str | bytes | None = None,
) -> bool:
    required = {"package_type", "request_fingerprint", "skg_constraint_digest", "signals", "digest", "signature", "timestamp"}
    if not isinstance(package, Mapping) or not required.issubset(package):
        return False
    if (
        package.get("package_type") != "external_dtn_signal_package"
        or package.get("package_version") != DTN_PACKAGE_VERSION
        or contains_prohibited_authority(package)
    ):
        return False
    if package.get("freshness_valid") is not True or package.get("consistency_valid") is not True:
        return False
    if skg_constraint_package is not None:
        if skg_constraint_package.get("digest") != package.get("skg_constraint_digest"):
            return False
        if skg_constraint_package.get("request_fingerprint") != package.get("request_fingerprint"):
            return False
    signals = package.get("signals")
    if not isinstance(signals, Mapping) or set(signals) != set(DTN_SIGNAL_TYPES):
        return False
    if any(
        signal.get("request_fingerprint") != package.get("request_fingerprint")
        or signal.get("skg_constraint_digest") != package.get("skg_constraint_digest")
        for signal in signals.values()
    ):
        return False
    if not all(validate_signal_envelope(signal, verification_key=verification_key) for signal in signals.values()):
        return False
    if package.get("digest") != digest_mapping(_package_body(package)):
        return False
    if isinstance(package.get("signature"), Mapping):
        return source_signature_shape_valid(package, substrate_type="DTN")
    return verify_signature(_signature_body(package), str(package.get("signature")), verification_key)
