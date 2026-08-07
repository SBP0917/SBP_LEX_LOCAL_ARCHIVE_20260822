from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from external_substrates.shared.validation import contains_prohibited_authority
from sbp_lex.security.pqc import generate_digest, verify_signature

EIE_DIGEST_EXCLUDED_FIELDS = {"eie_hash"}
EIE_ALLOWED_FIELDS = frozenset({
    "object_type",
    "eie_version",
    "schema_version",
    "canonical_traversal_state",
    "adapter_identity",
    "source_system_identity",
    "native_format",
    "source_payload_hash",
    "request_fingerprint",
    "traversal_id",
    "intent",
    "action",
    "objective",
    "actor",
    "principal",
    "authority_claim_inputs",
    "autonomy",
    "deployment",
    "environment",
    "consequence",
    "ap_acf_deployment_declarations",
    "environment_modifiers",
    "payload",
    "context",
    "resolved_authority",
    "jurisdiction",
    "external_substrate_references",
    "freshness",
    "replay",
    "eie_hash",
})

REQUIRED_EIE_STRING_FIELDS = (
    "object_type",
    "eie_version",
    "adapter_identity",
    "source_system_identity",
    "native_format",
    "source_payload_hash",
    "request_fingerprint",
    "traversal_id",
    "intent",
)

REQUIRED_SKG_METADATA_FIELDS = (
    "skg_verification_status",
    "truth_foundation_readiness_status",
    "skg_enrichment_hash",
    "provenance_metadata",
    "source_independence_mapping",
    "freshness_metadata",
    "consistency_information",
    "attestation_status",
    "integrity_references",
    "jurisdictional_relevance",
)

REQUIRED_DTN_METADATA_FIELDS = (
    "dtn_contextualisation_status",
    "contextual_readiness_status",
    "dtn_enrichment_hash",
    "operational_state_context",
    "environmental_context",
    "runtime_world_correspondence",
    "physical_world_digital_state_alignment",
    "consequence_context",
    "state_correspondence_verification",
)

ROOT_PAYLOAD_BINDINGS = (
    "eie_hash",
    "source_payload_hash",
    "adapter_identity",
    "source_system_identity",
    "request_fingerprint",
    "skg_verification_status",
    "skg_enrichment_hash",
    "dtn_contextualisation_status",
    "dtn_enrichment_hash",
    "evidence_package_hash",
    "pt_evidence_envelope_digest",
    "state_hash",
    "traversal_id",
    "token_chain_reference",
    "audit_chain_reference",
)


def canonical_eie_payload(eie: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in dict(eie).items()
        if key not in EIE_DIGEST_EXCLUDED_FIELDS
    }


def canonical_eie_digest(eie: Mapping[str, Any]) -> str:
    return generate_digest(canonical_eie_payload(eie))


def _present_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _metadata_digest(metadata: Mapping[str, Any], hash_field: str) -> str:
    payload = {key: deepcopy(value) for key, value in dict(metadata).items() if key != hash_field}
    return generate_digest(payload)


def validate_eie_binding(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    eie = state.get("eie")
    if not isinstance(eie, Mapping):
        return False, ["eie_missing_or_malformed"]

    if eie.get("object_type") != "ExecutionIntentEnvelope":
        failures.append("eie_object_type_invalid")
    if eie.get("schema_version") != "desktop-v1.eie.v1":
        failures.append("eie_schema_version_invalid")
    if eie.get("canonical_traversal_state") is not True:
        failures.append("eie_canonical_traversal_state_missing")
    if set(eie) != EIE_ALLOWED_FIELDS:
        failures.append("eie_schema_fields_rejected")
    if contains_prohibited_authority(eie):
        failures.append("eie_contains_runtime_authority_outcome")

    for field in REQUIRED_EIE_STRING_FIELDS:
        if not _present_string(eie.get(field)):
            failures.append(f"eie_missing:{field}")

    snapshot = state.get("request_identity_snapshot")
    if not isinstance(snapshot, Mapping):
        failures.append("eie_request_snapshot_missing")
        snapshot = {}

    expected_source_payload_hash = generate_digest(snapshot.get("payload", {}))
    expected_request_fingerprint = generate_digest(dict(snapshot))
    expected_traversal_id = generate_digest(
        {
            "request_fingerprint": expected_request_fingerprint,
            "source_payload_hash": expected_source_payload_hash,
            "adapter_identity": eie.get("adapter_identity"),
        }
    )

    if state.get("source_payload_hash") != expected_source_payload_hash:
        failures.append("source_payload_hash_mismatch")
    if eie.get("source_payload_hash") != expected_source_payload_hash:
        failures.append("eie_source_payload_hash_mismatch")
    if state.get("request_fingerprint") != expected_request_fingerprint:
        failures.append("request_fingerprint_mismatch")
    if eie.get("request_fingerprint") != expected_request_fingerprint:
        failures.append("eie_request_fingerprint_mismatch")
    if state.get("traversal_id") != expected_traversal_id:
        failures.append("traversal_id_mismatch")
    if eie.get("traversal_id") != expected_traversal_id:
        failures.append("eie_traversal_id_mismatch")
    if state.get("eie_hash") != eie.get("eie_hash"):
        failures.append("eie_hash_state_mismatch")
    if eie.get("eie_hash") != canonical_eie_digest(eie):
        failures.append("eie_hash_invalid")
    if state.get("eie_hash") != canonical_eie_digest(eie):
        failures.append("state_eie_hash_invalid")
    if eie.get("intent") != snapshot.get("action"):
        failures.append("eie_intent_mismatch")
    if eie.get("action") != snapshot.get("action"):
        failures.append("eie_action_mismatch")
    if eie.get("payload") != snapshot.get("payload", {}):
        failures.append("eie_payload_mismatch")
    if eie.get("context") != snapshot.get("context", {}):
        failures.append("eie_context_mismatch")
    freshness = eie.get("freshness")
    if not isinstance(freshness, Mapping) or set(freshness) != {
        "clock", "issued_at", "valid_until", "max_age_seconds"
    }:
        failures.append("eie_freshness_schema_invalid")
    else:
        issued_at = freshness.get("issued_at")
        valid_until = freshness.get("valid_until")
        max_age = freshness.get("max_age_seconds")
        if (
            freshness.get("clock")
            != "REQUEST_FINGERPRINT_LOGICAL_CLOCK_V1"
            or not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(valid_until, int)
            or isinstance(valid_until, bool)
            or not isinstance(max_age, int)
            or isinstance(max_age, bool)
            or max_age < 0
            or valid_until != issued_at + max_age
        ):
            failures.append("eie_freshness_contract_invalid")
    replay = eie.get("replay")
    if not isinstance(replay, Mapping) or set(replay) != {"nonce", "scope"}:
        failures.append("eie_replay_schema_invalid")
    elif (
        not _present_string(replay.get("nonce"))
        or replay.get("scope") != "DESKTOP_V1_HARD_ENTRY"
    ):
        failures.append("eie_replay_contract_invalid")
    return not failures, sorted(set(failures))


def validate_skg_dtn_binding(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    envelope = state.get("pt_evidence_envelope")
    if not isinstance(envelope, Mapping):
        return False, ["pt_evidence_envelope_missing"]
    if envelope.get("eie_hash") != state.get("eie_hash"):
        failures.append("pt_envelope_eie_hash_mismatch")
    if envelope.get("request_fingerprint") != state.get("request_fingerprint"):
        failures.append("pt_envelope_request_fingerprint_mismatch")
    if envelope.get("traversal_id") != state.get("traversal_id"):
        failures.append("pt_envelope_traversal_id_mismatch")
    if envelope.get("source_payload_hash") != state.get("source_payload_hash"):
        failures.append("pt_envelope_source_payload_hash_mismatch")
    if not _present_string(envelope.get("pre_context_digest")):
        failures.append("pre_context_digest_missing")
    if state.get("pt_evidence_envelope_digest") != generate_digest(dict(envelope)):
        failures.append("pt_evidence_envelope_digest_mismatch")

    skg = envelope.get("skg_truth_foundation_metadata")
    dtn = envelope.get("dtn_contextual_verification_metadata")
    if not isinstance(skg, Mapping):
        failures.append("skg_metadata_missing")
        skg = {}
    if not isinstance(dtn, Mapping):
        failures.append("dtn_metadata_missing")
        dtn = {}
    for field in REQUIRED_SKG_METADATA_FIELDS:
        if field not in skg or skg.get(field) in (None, "", []):
            failures.append(f"skg_metadata_missing:{field}")
    for field in REQUIRED_DTN_METADATA_FIELDS:
        if field not in dtn or dtn.get(field) in (None, "", []):
            failures.append(f"dtn_metadata_missing:{field}")
    if skg.get("skg_verification_status") != "VALID":
        failures.append("skg_verification_not_valid")
    if skg.get("truth_foundation_readiness_status") != "READY":
        failures.append("skg_truth_foundation_not_ready")
    if dtn.get("dtn_contextualisation_status") != "VALID":
        failures.append("dtn_contextualisation_not_valid")
    if dtn.get("contextual_readiness_status") != "READY":
        failures.append("dtn_contextualisation_not_ready")
    if skg.get("skg_enrichment_hash") != _metadata_digest(skg, "skg_enrichment_hash"):
        failures.append("skg_enrichment_hash_mismatch")
    if dtn.get("dtn_enrichment_hash") != _metadata_digest(dtn, "dtn_enrichment_hash"):
        failures.append("dtn_enrichment_hash_mismatch")
    collective = state.get("collective_signal_evidence", {})
    if not isinstance(collective, Mapping):
        failures.append("collective_signal_evidence_missing")
    else:
        if collective.get("request_fingerprint") != state.get(
            "request_fingerprint"
        ):
            failures.append("collective_request_binding_mismatch")
        if collective.get("eie_digest") != state.get("eie_hash"):
            failures.append("collective_eie_binding_mismatch")
    return not failures, sorted(set(failures))


def validate_root_anchor_binding(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    anchor = state.get("root_of_trust_evidence_anchor")
    envelope = state.get("pt_evidence_envelope", {})
    if not isinstance(anchor, Mapping):
        return False, ["root_anchor_missing"]
    if anchor.get("valid") is not True or anchor.get("anchorage_status") != "VALID":
        failures.append("root_anchor_not_valid")
    payload = anchor.get("payload")
    if not isinstance(payload, Mapping):
        return False, sorted(set(failures + ["root_anchor_payload_missing"]))
    for field in ROOT_PAYLOAD_BINDINGS:
        if payload.get(field) in (None, "", []):
            failures.append(f"root_anchor_missing:{field}")
    if anchor.get("anchor_digest") != generate_digest(dict(payload)):
        failures.append("root_anchor_digest_mismatch")
    if not verify_signature(payload, anchor.get("signature", {})):
        failures.append("root_anchor_signature_invalid")
    expected = {
        "eie_hash": state.get("eie_hash"),
        "source_payload_hash": state.get("source_payload_hash"),
        "request_fingerprint": state.get("request_fingerprint"),
        "skg_enrichment_hash": envelope.get("skg_truth_foundation_metadata", {}).get("skg_enrichment_hash")
        if isinstance(envelope, Mapping)
        else None,
        "dtn_enrichment_hash": envelope.get("dtn_contextual_verification_metadata", {}).get("dtn_enrichment_hash")
        if isinstance(envelope, Mapping)
        else None,
        "evidence_package_hash": envelope.get("pre_context_digest") if isinstance(envelope, Mapping) else None,
        "pt_evidence_envelope_digest": state.get("pt_evidence_envelope_digest"),
        "state_hash": state.get("root_anchor_bound_state_hash", state.get("state_hash")),
        "traversal_id": state.get("traversal_id"),
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            failures.append(f"root_anchor_mismatch:{field}")
    return not failures, sorted(set(failures))


def validate_control_chain_bindings(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    from sbp_lex.shared.state_builder import validate_boundary_protection

    boundary_valid, boundary_failures = validate_boundary_protection(state)
    if not boundary_valid:
        failures.extend(boundary_failures)
    for validator in (validate_eie_binding, validate_skg_dtn_binding):
        valid, validator_failures = validator(state)
        if not valid:
            failures.extend(validator_failures)
    if state.get("root_of_trust_evidence_anchor"):
        root_valid, root_failures = validate_root_anchor_binding(state)
        if not root_valid:
            failures.extend(root_failures)
    return not failures, sorted(set(failures))
