from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from external_substrates.shared.digest import digest_mapping
from external_substrates.shared.external_boundary import (
    ExternalBoundaryError,
    parse_canonical_json,
)
from external_substrates.shared.synthetic_runtime import (
    PROVIDER_MODE,
    SyntheticReplayRegistry,
    build_synthetic_dtn_package,
    build_synthetic_skg_package,
    canonical_package,
    validate_provider_mode,
    validate_synthetic_bridge,
)
from sbp_lex.collective.context_interface import (
    prepare_pre_context_signals,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.state_builder import build_execution_intent_envelope

FIXTURE_ISSUED_AT = "2026-08-07T00:00:00Z"
FIXTURE_VALIDATION_TIME = "2026-08-07T00:00:00Z"
STAGE_ORDER = (
    "external_request",
    "adapter",
    "eie",
    "synthetic_skg",
    "synthetic_dtn",
    "contract_validation",
    "bridge_validation",
    "hard_entry",
    "state_construction",
    "attachment",
)


@dataclass(frozen=True)
class SyntheticSubstrateResult:
    accepted: bool
    signals: dict[str, Any] | None
    failures: tuple[str, ...]
    evidence: dict[str, Any]


def _source_records(
    request: Mapping[str, Any], issued_at: str
) -> list[dict[str, Any]]:
    context = (
        request.get("context", {})
        if isinstance(request.get("context"), Mapping)
        else {}
    )
    evidence = (
        context.get("evidence", [])
        if isinstance(context.get("evidence"), list)
        else []
    )
    if not evidence:
        evidence = [{
            "source": "desktop-v1-synthetic-source",
            "content": "request-bound synthetic fixture",
            "verified": True,
            "attested": True,
        }]
    records: list[dict[str, Any]] = []
    for index, item in enumerate(evidence):
        value = dict(item) if isinstance(item, Mapping) else {"content": item}
        declared_source_id = str(
            value.get("source", value.get("source_id", f"source-{index + 1}"))
        )
        records.append({
            "source_id": f"{declared_source_id}#{index + 1}",
            "source_uri": f"fixture:/synthetic/{index + 1}",
            "retrieved_at": issued_at,
            "digest": digest_mapping(value),
            # These flags attest the controlled local fixture source, not the
            # request evidence claim. Claim qualification remains a later PT
            # input and is preserved unchanged in the normalized request.
            "verified": True,
            "attested": True,
        })
    return records


def _dependencies(request: Mapping[str, Any]) -> list[dict[str, Any]]:
    context = (
        request.get("context", {})
        if isinstance(request.get("context"), Mapping)
        else {}
    )
    declared = context.get("dependencies")
    if isinstance(declared, list):
        values = [
            {
                "dependency_id": str(item.get("dependency_id", "")),
                "available": item.get("available") is True,
            }
            for item in declared
            if isinstance(item, Mapping)
        ]
        if values:
            return values
    return [{"dependency_id": "desktop_local_runtime", "available": True}]


def build_synthetic_fixture_chain(
    request: Mapping[str, Any],
    *,
    issued_at: str = FIXTURE_ISSUED_AT,
    eie: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build the EIE first, followed by deterministic external fixture packages."""
    request_copy = deepcopy(dict(request))
    canonical_eie = (
        deepcopy(dict(eie))
        if isinstance(eie, Mapping)
        else build_execution_intent_envelope(request_copy)
    )
    request_fingerprint = str(canonical_eie["request_fingerprint"])
    references = canonical_eie["external_substrate_references"]
    authority_id = str(request_copy.get("resolved_authority", "UNRESOLVED"))
    jurisdiction = str(request_copy.get("jurisdiction", "UNRESOLVED"))
    provenance = _source_records(request_copy, issued_at)
    evidence_references = [record["digest"] for record in provenance]
    skg = build_synthetic_skg_package(
        request_fingerprint=request_fingerprint,
        eie_digest=str(canonical_eie["eie_hash"]),
        package_reference=str(references["skg_package_reference"]),
        authority_id=authority_id,
        jurisdiction=jurisdiction,
        issued_at=issued_at,
        provenance=provenance,
        evidence_references=evidence_references,
        procedural_references=["desktop-v1:procedural-truth:input-only"],
    )
    context = (
        request_copy.get("context", {})
        if isinstance(request_copy.get("context"), Mapping)
        else {}
    )
    payload = (
        request_copy.get("payload", {})
        if isinstance(request_copy.get("payload"), Mapping)
        else {}
    )
    classification = (
        payload.get("classification", {})
        if isinstance(payload.get("classification"), Mapping)
        else {}
    )
    dtn = build_synthetic_dtn_package(
        request_fingerprint=request_fingerprint,
        eie_digest=str(canonical_eie["eie_hash"]),
        package_reference=str(references["dtn_package_reference"]),
        skg_package=skg,
        authority_id=authority_id,
        jurisdiction=jurisdiction,
        operational_context={
            "objective": canonical_eie["objective"],
            "autonomy": classification.get(
                "autonomy_level", canonical_eie["autonomy"]
            ),
            "deployment": canonical_eie["deployment"],
        },
        environmental_context={
            "environment": canonical_eie["environment"],
            "locality": context.get("locality", "desktop_local"),
            "containment": context.get(
                "operational_containment", "bounded"
            ),
        },
        dependencies=_dependencies(request_copy),
        pathway_id=str(context.get("pathway_id", "desktop_local_pathway")),
        issued_at=issued_at,
        provenance=provenance,
    )
    return canonical_eie, skg, dtn


def validate_raw_synthetic_chain(
    *,
    request: Mapping[str, Any],
    raw_skg: str,
    raw_dtn: str,
    validation_time: str,
    provider_configuration: Mapping[str, Any] | None = None,
    replay_registry: SyntheticReplayRegistry | None = None,
    eie: Mapping[str, Any] | None = None,
) -> SyntheticSubstrateResult:
    """Validate raw external fixtures and emit only bounded local signals."""
    provider = validate_provider_mode(
        provider_configuration
        or {
            "provider_mode": PROVIDER_MODE,
            "source_uri": "fixture:/synthetic/runtime",
            "network_enabled": False,
            "live_ingestion": False,
        }
    )
    if not provider.accepted:
        return _rejected(provider.failures, "provider_mode")
    try:
        skg = parse_canonical_json(raw_skg)
        dtn = parse_canonical_json(raw_dtn)
    except (ExternalBoundaryError, TypeError, ValueError) as exc:
        code = getattr(exc, "code", "malformed_external_package")
        return _rejected((str(code),), "contract_validation")

    canonical_eie = (
        deepcopy(dict(eie))
        if isinstance(eie, Mapping)
        else build_execution_intent_envelope(request)
    )
    references = canonical_eie["external_substrate_references"]
    reference_failures: list[str] = []
    if skg.get("package_reference") != references["skg_package_reference"]:
        reference_failures.append("skg_package_reference_mismatch")
    if dtn.get("package_reference") != references["dtn_package_reference"]:
        reference_failures.append("dtn_package_reference_mismatch")
    if reference_failures:
        return _rejected(tuple(reference_failures), "contract_validation")
    bridge = validate_synthetic_bridge(
        skg,
        dtn,
        validation_time=validation_time,
        expected_request_fingerprint=str(canonical_eie["request_fingerprint"]),
        expected_eie_digest=str(canonical_eie["eie_hash"]),
        replay_registry=replay_registry or SyntheticReplayRegistry(),
    )
    if not bridge.accepted:
        return _rejected(bridge.failures, "bridge_validation")

    # Raw packages stop here. Only the established minimal local signal
    # package crosses Hard Entry; no state object is accepted or mutated.
    evidence = {
        "runtime": "DESKTOP_V1_SYNTHETIC_EXTERNAL_SUBSTRATES",
        "authority_role": "context_only_non_authoritative",
        "provider_mode": PROVIDER_MODE,
        "request_fingerprint": canonical_eie["request_fingerprint"],
        "eie_digest": canonical_eie["eie_hash"],
        "skg_package_reference": skg["package_reference"],
        "skg_package_digest": skg["digest"],
        "skg_validation_status": "VALID",
        "dtn_package_reference": dtn["package_reference"],
        "dtn_package_digest": dtn["digest"],
        "dtn_validation_status": "VALID",
        "bridge_validation_status": "PASS",
        "signature_mode": skg["signature_mode"],
        "fixture_issued_at": skg["issued_at"],
        "validation_time": validation_time,
        "stage_order": list(STAGE_ORDER),
        "raw_packages_crossed_hard_entry": False,
        "direct_state_write": False,
    }
    bridge_payload = {
        "bridge_validation_status": evidence["bridge_validation_status"],
        "request_fingerprint": evidence["request_fingerprint"],
        "eie_digest": evidence["eie_digest"],
        "skg_package_digest": evidence["skg_package_digest"],
        "dtn_package_digest": evidence["dtn_package_digest"],
    }
    evidence["bridge_result_digest"] = generate_digest(bridge_payload)
    signals = prepare_pre_context_signals(
        request,
        eie=canonical_eie,
        substrate_evidence=evidence,
    )
    return SyntheticSubstrateResult(True, signals, (), evidence)


def prepare_synthetic_substrate_signals(
    request: Mapping[str, Any],
    *,
    eie: Mapping[str, Any] | None = None,
) -> SyntheticSubstrateResult:
    canonical_eie, skg, dtn = build_synthetic_fixture_chain(
        request, eie=eie
    )
    return validate_raw_synthetic_chain(
        request=request,
        raw_skg=canonical_package(skg),
        raw_dtn=canonical_package(dtn),
        validation_time=FIXTURE_VALIDATION_TIME,
        replay_registry=SyntheticReplayRegistry(),
        eie=canonical_eie,
    )


def _rejected(
    failures: tuple[str, ...],
    stopped_at: str,
) -> SyntheticSubstrateResult:
    return SyntheticSubstrateResult(
        False,
        None,
        tuple(dict.fromkeys(failures)),
        {
            "runtime": "DESKTOP_V1_SYNTHETIC_EXTERNAL_SUBSTRATES",
            "authority_role": "context_only_non_authoritative",
            "provider_mode": PROVIDER_MODE,
            "stopped_at": stopped_at,
            "raw_packages_crossed_hard_entry": False,
            "direct_state_write": False,
        },
    )
