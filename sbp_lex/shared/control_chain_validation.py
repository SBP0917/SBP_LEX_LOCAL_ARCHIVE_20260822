from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from external_substrates.shared.validation import contains_prohibited_authority
from sbp_lex.security.pqc import generate_digest, verify_signature
from sbp_lex.security.token_stack import verify_token
from sbp_lex.shared.hash_chain import rebuild_state_hash, verify_hash_chain

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

COLLECTIVE_ATTACHMENT_PAYLOAD_FIELDS = frozenset({
    "schema_version",
    "request_fingerprint",
    "eie_digest",
    "signal_digest",
    "collective_projection_digest",
    "logical_timestamp",
    "freshness_window_seconds",
    "prior_state_hash",
    "skg_package_digest",
    "dtn_package_digest",
    "bridge_result_digest",
    "root_trust_material",
    "root_trust_material_digest",
})
COLLECTIVE_ATTACHMENT_ATTESTATION_PAYLOAD_FIELDS = frozenset({
    "schema_version",
    "attachment_hash",
    "request_fingerprint",
    "eie_digest",
    "collective_signal_digest",
    "collective_projection_digest",
    "prior_state_hash",
    "root_trust_material_digest",
})
ROOT_EVIDENCE_FIELDS = frozenset({
    "schema_version",
    "valid",
    "anchorage_status",
    "result",
    "reason",
    "root_evidence_digest",
    "anchor_digest",
    "payload",
    "signature",
    "verified",
    "authority",
    "failures",
})
ROOT_EVIDENCE_PAYLOAD_FIELDS = frozenset({
    "schema_version",
    "result",
    "reason",
    "failures",
    "stopped_stage",
    "eie_identity",
    "eie_hash",
    "source_payload_hash",
    "adapter_identity",
    "source_system_identity",
    "request_fingerprint",
    "canonical_request_identity",
    "skg_digest",
    "skg_verification_status",
    "skg_enrichment_hash",
    "dtn_digest",
    "dtn_contextualisation_status",
    "dtn_enrichment_hash",
    "pre_context_digest",
    "evidence_package_hash",
    "authority_reference_hash",
    "pt_evidence_envelope_digest",
    "state_hash",
    "state_hash_entering_root",
    "state_hash_after_root_chain",
    "traversal_id",
    "timestamp_freshness_reference",
    "token_chain_reference",
    "audit_chain_reference",
    "collective_digest",
    "collective_signal_digest",
    "collective_attachment_hash",
    "root_trust_material_digest",
    "authority_identity",
    "jurisdiction",
    "attestation_identities",
    "logical_timestamp",
    "nonce",
    "root_context_digest",
    "validation_basis",
    "stage_results",
    "stage_evidence_digests",
    "truth_anchor_digest",
})
ROOT_AUTHORITY_MATERIAL_FIELDS = frozenset({
    "authority_identity",
    "jurisdiction",
    "legitimacy_status",
    "authority_status",
    "revoked",
    "issued_at",
    "valid_until",
    "skg_package_digest",
    "authority_evidence_digest",
})
ROOT_ATTESTATION_MATERIAL_FIELDS = frozenset({
    "attestation_identity",
    "authority_identity",
    "jurisdiction",
    "status",
    "revoked",
    "collective_signature_digest",
    "consensus_statement_digest",
    "request_fingerprint",
    "eie_digest",
    "collective_signal_digest",
    "issued_at",
    "valid_until",
    "nonce",
    "attestation_digest",
})
ROOT_TRUTH_MATERIAL_FIELDS = frozenset({
    "truth_identity",
    "status",
    "revoked",
    "continuity_reference",
    "request_fingerprint",
    "eie_digest",
    "collective_signal_digest",
    "issued_at",
    "valid_until",
    "nonce",
    "truth_material_digest",
})
ROOT_VALIDATION_BASIS_FIELDS = frozenset({
    "basis",
    "authority_identity_exact",
    "jurisdiction_exact",
    "skg_package_digest",
    "dtn_package_digest",
    "bridge_result_digest",
    "closed_synthetic_schema_revocation_default",
})
ROOT_CONTEXT_FIELDS = frozenset({
    "schema_version",
    "request_fingerprint",
    "eie_digest",
    "canonical_request_identity",
    "state_hash_entering_root",
    "collective_signal_digest",
    "collective_attachment_hash",
    "root_trust_material_digest",
    "authority_identity",
    "jurisdiction",
    "attestation_identities",
    "logical_timestamp",
    "nonce",
    "validation_basis",
    "token_chain_reference_entering_root",
    "audit_chain_reference_entering_root",
    "context_digest",
})


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


def _digest_without(value: Mapping[str, Any], *excluded: str) -> str:
    return generate_digest({
        key: deepcopy(item)
        for key, item in dict(value).items()
        if key not in set(excluded)
    })


def _logical_interval_valid(
    *, issued_at: Any, valid_until: Any, logical_time: Any
) -> bool:
    return (
        isinstance(issued_at, int)
        and not isinstance(issued_at, bool)
        and isinstance(valid_until, int)
        and not isinstance(valid_until, bool)
        and isinstance(logical_time, int)
        and not isinstance(logical_time, bool)
        and issued_at <= logical_time <= valid_until
    )


def validate_collective_attachment_binding(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Validate the signed, minimal collective projection consumed by Root."""

    failures: list[str] = []
    if state.get("collective_signal_status") != "ATTACHED":
        failures.append("collective_signals_not_attached")
    signals = state.get("collective_signals")
    if not isinstance(signals, Mapping) or not signals:
        return False, ["collective_signal_projection_missing"]
    attachment = state.get("collective_attachment")
    if not isinstance(attachment, Mapping):
        return False, ["collective_attachment_missing"]
    verified_references = state.get("verified_substrate_references", {})
    verified_references = (
        verified_references
        if isinstance(verified_references, Mapping)
        else {}
    )

    payload = {
        key: deepcopy(value)
        for key, value in dict(attachment).items()
        if key not in {"attachment_hash", "attestation"}
    }
    if set(payload) != COLLECTIVE_ATTACHMENT_PAYLOAD_FIELDS:
        failures.append("collective_attachment_schema_invalid")
    attachment_hash = attachment.get("attachment_hash")
    if attachment_hash != generate_digest(payload):
        failures.append("collective_attachment_hash_mismatch")
    expected_values = {
        "schema_version": "desktop-v1.collective-attachment.v1",
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "signal_digest": signals.get("digest"),
        "collective_projection_digest": generate_digest(dict(signals)),
        "skg_package_digest": verified_references.get("skg_package_digest"),
        "dtn_package_digest": verified_references.get("dtn_package_digest"),
        "bridge_result_digest": verified_references.get(
            "bridge_result_digest"
        ),
    }
    for field, expected in expected_values.items():
        if payload.get(field) != expected:
            failures.append(f"collective_attachment_mismatch:{field}")
    if signals.get("request_fingerprint") != state.get("request_fingerprint"):
        failures.append("collective_signal_request_fingerprint_mismatch")
    if signals.get("eie_digest") != state.get("eie_hash"):
        failures.append("collective_signal_eie_digest_mismatch")
    if state.get("collective_signal_evidence", {}).get(
        "signal_digest"
    ) != signals.get("digest"):
        failures.append("collective_signal_evidence_digest_mismatch")
    if state.get("hard_entry_gate", {}).get("signal_digest") != signals.get(
        "digest"
    ):
        failures.append("hard_entry_collective_digest_mismatch")
    timestamp = signals.get("timestamp")
    window = signals.get("freshness_window_seconds")
    if not (
        isinstance(timestamp, int)
        and not isinstance(timestamp, bool)
        and isinstance(window, int)
        and not isinstance(window, bool)
        and window >= 0
    ):
        failures.append("collective_signal_freshness_contract_invalid")
    else:
        try:
            expected_timestamp = int(
                str(state.get("request_fingerprint", ""))[:12], 16
            )
        except (TypeError, ValueError):
            expected_timestamp = None
        if expected_timestamp is None or timestamp != expected_timestamp:
            failures.append("collective_signal_timestamp_not_canonical")
        expected_nonce = generate_digest({
            "request_fingerprint": state.get("request_fingerprint"),
            "eie_digest": state.get("eie_hash"),
            "timestamp": timestamp,
            "timestamp_authority": "CANONICAL_RUNTIME",
        })[:32]
        if signals.get("nonce") != expected_nonce:
            failures.append("collective_signal_nonce_not_canonical")
    if signals.get("timestamp_authority") != "CANONICAL_RUNTIME":
        failures.append("collective_signal_timestamp_authority_invalid")

    material = payload.get("root_trust_material")
    if not isinstance(material, Mapping):
        failures.append("root_trust_material_missing")
    else:
        if payload.get("root_trust_material_digest") != material.get(
            "material_digest"
        ):
            failures.append("root_trust_material_attachment_mismatch")
        if material.get("material_digest") != _digest_without(
            material, "material_digest"
        ):
            failures.append("root_trust_material_digest_mismatch")

    attestation = attachment.get("attestation")
    if not isinstance(attestation, Mapping) or set(attestation) != {
        "payload", "attestation_digest", "signature", "verified"
    }:
        failures.append("collective_attachment_attestation_schema_invalid")
    else:
        attestation_payload = attestation.get("payload")
        if (
            not isinstance(attestation_payload, Mapping)
            or set(attestation_payload)
            != COLLECTIVE_ATTACHMENT_ATTESTATION_PAYLOAD_FIELDS
        ):
            failures.append("collective_attachment_attestation_payload_invalid")
            attestation_payload = {}
        expected_attestation = {
            "schema_version": "desktop-v1.collective-attachment-attestation.v1",
            "attachment_hash": attachment_hash,
            "request_fingerprint": state.get("request_fingerprint"),
            "eie_digest": state.get("eie_hash"),
            "collective_signal_digest": signals.get("digest"),
            "collective_projection_digest": generate_digest(dict(signals)),
            "prior_state_hash": payload.get("prior_state_hash"),
            "root_trust_material_digest": payload.get(
                "root_trust_material_digest"
            ),
        }
        if dict(attestation_payload) != expected_attestation:
            failures.append("collective_attachment_attestation_binding_mismatch")
        if attestation.get("attestation_digest") != generate_digest(
            dict(attestation_payload)
        ):
            failures.append("collective_attachment_attestation_digest_mismatch")
        if attestation.get("verified") is not True or not verify_signature(
            attestation_payload, attestation.get("signature", {})
        ):
            failures.append("collective_attachment_attestation_signature_invalid")
    return not failures, sorted(set(failures))


def validate_root_trust_material(
    state: Mapping[str, Any], *, structural_only: bool = False
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    attachment = state.get("collective_attachment", {})
    material = (
        attachment.get("root_trust_material", {})
        if isinstance(attachment, Mapping)
        else {}
    )
    if not isinstance(material, Mapping):
        return False, ["root_trust_material_missing"]
    verified_references = state.get("verified_substrate_references", {})
    verified_references = (
        verified_references
        if isinstance(verified_references, Mapping)
        else {}
    )
    if set(material) != {
        "schema_version", "authority", "attestations", "truth",
        "skg_validation_status", "dtn_validation_status",
        "bridge_validation_status", "validation_basis", "material_digest",
    }:
        failures.append("root_trust_material_schema_invalid")
    if material.get("schema_version") != "desktop-v1.root-trust-material.v1":
        failures.append("root_trust_material_schema_version_invalid")
    if material.get("material_digest") != _digest_without(
        material, "material_digest"
    ):
        failures.append("root_trust_material_digest_mismatch")
    for field, expected in (
        ("skg_validation_status", "VALID"),
        ("dtn_validation_status", "VALID"),
        ("bridge_validation_status", "PASS"),
    ):
        if material.get(field) != expected:
            failures.append(f"root_trust_material_{field}_invalid")
    basis = material.get("validation_basis")
    if not isinstance(basis, Mapping):
        failures.append("root_trust_validation_basis_missing")
        basis = {}
    elif set(basis) != ROOT_VALIDATION_BASIS_FIELDS:
        failures.append("root_trust_validation_basis_schema_invalid")
    if basis.get("basis") != "VALIDATED_SYNTHETIC_SKG_DTN_BRIDGE":
        failures.append("root_trust_validation_basis_invalid")
    if basis.get("authority_identity_exact") is not True:
        failures.append("root_trust_basis_authority_mismatch")
    if basis.get("jurisdiction_exact") is not True:
        failures.append("root_trust_basis_jurisdiction_mismatch")
    if basis.get("closed_synthetic_schema_revocation_default") != "CLEAR":
        failures.append("root_trust_basis_revocation_invalid")
    for field in (
        "skg_package_digest", "dtn_package_digest", "bridge_result_digest"
    ):
        if basis.get(field) != verified_references.get(field):
            failures.append(f"root_trust_basis_digest_mismatch:{field}")

    logical_time = attachment.get("logical_timestamp")
    signals = state.get("collective_signals", {})
    signals = signals if isinstance(signals, Mapping) else {}
    authority = material.get("authority")
    if not isinstance(authority, Mapping):
        failures.append("root_authority_material_missing")
        authority = {}
    elif set(authority) != ROOT_AUTHORITY_MATERIAL_FIELDS:
        failures.append("root_authority_material_schema_invalid")
    if authority.get("authority_evidence_digest") != _digest_without(
        authority, "authority_evidence_digest"
    ):
        failures.append("root_authority_evidence_digest_invalid")
    if authority.get("authority_identity") != state.get("resolved_authority"):
        failures.append("root_authority_identity_mismatch")
    if authority.get("jurisdiction") != state.get("jurisdiction"):
        failures.append("root_authority_jurisdiction_mismatch")
    if not structural_only:
        if authority.get("legitimacy_status") != "VALID":
            failures.append("root_authority_not_legitimate")
        if authority.get("authority_status") != "ACTIVE":
            failures.append("root_authority_status_invalid")
        if authority.get("revoked") is not False:
            failures.append("root_authority_revoked")
        if not _logical_interval_valid(
            issued_at=authority.get("issued_at"),
            valid_until=authority.get("valid_until"),
            logical_time=logical_time,
        ):
            failures.append("root_authority_expired")
    if authority.get("skg_package_digest") != verified_references.get(
        "skg_package_digest"
    ):
        failures.append("root_authority_skg_digest_mismatch")

    attestations = material.get("attestations")
    if not isinstance(attestations, list) or not attestations:
        failures.append("root_attestation_material_missing")
        attestations = []
    identities: list[str] = []
    for index, item in enumerate(attestations):
        if not isinstance(item, Mapping):
            failures.append(f"root_attestation_malformed:{index}")
            continue
        if set(item) != ROOT_ATTESTATION_MATERIAL_FIELDS:
            failures.append(f"root_attestation_schema_invalid:{index}")
        if item.get("attestation_digest") != _digest_without(
            item, "attestation_digest"
        ):
            failures.append(f"root_attestation_digest_invalid:{index}")
        identity = item.get("attestation_identity")
        if not _present_string(identity):
            failures.append(f"root_attestation_identity_missing:{index}")
        else:
            identities.append(str(identity))
        if not _present_string(item.get("consensus_statement_digest")):
            failures.append(
                f"root_attestation_consensus_statement_missing:{index}"
            )
        expected_item = {
            "authority_identity": state.get("resolved_authority"),
            "jurisdiction": state.get("jurisdiction"),
            "request_fingerprint": state.get("request_fingerprint"),
            "eie_digest": state.get("eie_hash"),
            "collective_signal_digest": signals.get("digest"),
            "nonce": signals.get("nonce"),
        }
        for field, expected in expected_item.items():
            if item.get(field) != expected:
                failures.append(f"root_attestation_binding_mismatch:{index}:{field}")
        if not structural_only and item.get("status") != "VALID":
            failures.append(f"root_attestation_status_invalid:{index}")
        if not structural_only and item.get("revoked") is not False:
            failures.append(f"root_attestation_revoked:{index}")
        if item.get("collective_signature_digest") != generate_digest(
            signals.get("signature", {})
        ):
            failures.append(f"root_attestation_signature_identity_mismatch:{index}")
        if not structural_only and not _logical_interval_valid(
            issued_at=item.get("issued_at"),
            valid_until=item.get("valid_until"),
            logical_time=logical_time,
        ):
            failures.append(f"root_attestation_expired:{index}")
    if len(identities) != len(set(identities)):
        failures.append("root_attestation_identity_duplicate")

    truth = material.get("truth")
    if not isinstance(truth, Mapping):
        failures.append("root_truth_material_missing")
        truth = {}
    elif set(truth) != ROOT_TRUTH_MATERIAL_FIELDS:
        failures.append("root_truth_material_schema_invalid")
    if truth.get("truth_material_digest") != _digest_without(
        truth, "truth_material_digest"
    ):
        failures.append("root_truth_material_digest_invalid")
    for field, expected in (
        ("request_fingerprint", state.get("request_fingerprint")),
        ("eie_digest", state.get("eie_hash")),
        ("collective_signal_digest", signals.get("digest")),
        ("nonce", signals.get("nonce")),
    ):
        if truth.get(field) != expected:
            failures.append(f"root_truth_binding_mismatch:{field}")
    if not structural_only and truth.get("status") != "VALID":
        failures.append("root_truth_status_invalid")
    if not structural_only and truth.get("revoked") is not False:
        failures.append("root_truth_revoked")
    if not structural_only and not _logical_interval_valid(
        issued_at=truth.get("issued_at"),
        valid_until=truth.get("valid_until"),
        logical_time=logical_time,
    ):
        failures.append("root_truth_expired")
    lineage = signals.get("precedence_signal", {})
    lineage = lineage.get("temporal_rule_lineage", []) if isinstance(
        lineage, Mapping
    ) else []
    if (
        not structural_only
        and truth.get("continuity_reference") != generate_digest(lineage)
    ):
        failures.append("root_truth_continuity_reference_mismatch")
    return not failures, sorted(set(failures))


def validate_root_input_bindings(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Strict Root entry gate over the complete admitted canonical basis."""

    failures: list[str] = []
    hard_entry = state.get("hard_entry_gate", {})
    if not isinstance(hard_entry, Mapping) or hard_entry.get(
        "accepted"
    ) is not True:
        failures.append("hard_entry_not_accepted")
    if state.get("ap_acf_precheck_result") != "PASS":
        failures.append("ap_acf_precheck_not_pass")
    if state.get("root_of_trust_evidence") or state.get(
        "root_of_trust_evidence_anchor"
    ):
        failures.append("root_reentry_requires_full_retraversal")
    if state.get("state_hash") != rebuild_state_hash(state):
        failures.append("root_input_state_hash_mismatch")
    if not verify_hash_chain(state):
        failures.append("root_input_hash_chain_invalid")
    from sbp_lex.shared.state_builder import validate_boundary_protection

    for validator in (
        validate_boundary_protection,
        validate_eie_binding,
        validate_skg_dtn_binding,
        validate_collective_attachment_binding,
    ):
        valid, validator_failures = validator(state)
        if not valid:
            failures.extend(validator_failures)
    material_valid, material_failures = validate_root_trust_material(
        state, structural_only=True
    )
    if not material_valid:
        failures.extend(material_failures)
    return not failures, sorted(set(failures))


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
    signals = state.get("collective_signals", {})
    signals = signals if isinstance(signals, Mapping) else {}
    for envelope_field, signal_field in (
        ("skg_digest", "skg_digest"),
        ("dtn_digest", "dtn_digest"),
        ("pre_context_digest", "digest"),
    ):
        if envelope.get(envelope_field) != signals.get(signal_field):
            failures.append(
                f"pt_envelope_collective_mismatch:{envelope_field}"
            )
    for legacy_digest_field in ("skg_digest", "dtn_digest"):
        if not _present_string(envelope.get(legacy_digest_field)):
            failures.append(f"root_anchor_missing:{legacy_digest_field}")
    if state.get("pt_evidence_envelope_digest") != generate_digest(dict(envelope)):
        failures.append("pt_evidence_envelope_digest_mismatch")
        failures.append("pt_evidence_envelope_digest_invalid")

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


def validate_root_of_trust_evidence(
    state: Mapping[str, Any], *, require_pass: bool = True
) -> tuple[bool, list[str]]:
    """Verify the final signed Root result and all canonical input bindings."""

    failures: list[str] = []
    anchor = state.get("root_of_trust_evidence_anchor")
    evidence = state.get("root_of_trust_evidence", anchor)
    envelope = state.get("pt_evidence_envelope", {})
    envelope = envelope if isinstance(envelope, Mapping) else {}
    skg_metadata = envelope.get("skg_truth_foundation_metadata", {})
    skg_metadata = skg_metadata if isinstance(skg_metadata, Mapping) else {}
    dtn_metadata = envelope.get("dtn_contextual_verification_metadata", {})
    dtn_metadata = dtn_metadata if isinstance(dtn_metadata, Mapping) else {}
    signals = state.get("collective_signals", {})
    signals = signals if isinstance(signals, Mapping) else {}
    attachment = state.get("collective_attachment", {})
    attachment = attachment if isinstance(attachment, Mapping) else {}
    context = state.get("root_of_trust_context", {})
    context = context if isinstance(context, Mapping) else {}
    feedback = state.get("governance_feedback", {})
    feedback = feedback if isinstance(feedback, Mapping) else {}
    if require_pass:
        # The live state hash advances after Root as PT and later stages append
        # their transitions.  Root binds its own immutable issuance hashes in
        # the signed evidence and authority token; requiring the later live
        # hash to equal a fresh rebuild would confuse those two time domains.
        if not verify_hash_chain(state):
            failures.append("post_root_hash_chain_invalid")
        from sbp_lex.shared.state_builder import validate_boundary_protection

        for validator in (
            validate_boundary_protection,
            validate_eie_binding,
            validate_skg_dtn_binding,
            validate_collective_attachment_binding,
        ):
            current_valid, current_failures = validator(state)
            if not current_valid:
                failures.extend(current_failures)
    if not isinstance(anchor, Mapping):
        return False, ["root_anchor_missing"]
    if not isinstance(evidence, Mapping):
        return False, ["root_evidence_missing"]
    if dict(anchor) != dict(evidence):
        failures.append("root_evidence_anchor_alias_mismatch")
    if set(anchor) != ROOT_EVIDENCE_FIELDS:
        failures.append("root_evidence_wrapper_schema_invalid")
    if anchor.get("schema_version") != "desktop-v1.root-evidence.v1":
        failures.append("root_evidence_schema_invalid")
    if require_pass and (
        anchor.get("valid") is not True
        or anchor.get("anchorage_status") != "VALID"
        or anchor.get("result") != "PASS"
    ):
        failures.append("root_anchor_not_valid")
    payload = anchor.get("payload")
    if not isinstance(payload, Mapping):
        return False, sorted(set(failures + ["root_anchor_payload_missing"]))
    if set(payload) != ROOT_EVIDENCE_PAYLOAD_FIELDS:
        failures.append("root_evidence_payload_schema_invalid")
    if payload.get("schema_version") != "desktop-v1.root-evidence-payload.v1":
        failures.append("root_evidence_payload_version_invalid")
    for field in ROOT_PAYLOAD_BINDINGS:
        if field not in payload or (
            require_pass and payload.get(field) in (None, "", [])
        ):
            failures.append(f"root_anchor_missing:{field}")
    payload_digest = generate_digest(dict(payload))
    if anchor.get("anchor_digest") != payload_digest:
        failures.append("root_anchor_digest_mismatch")
    if anchor.get("root_evidence_digest") != payload_digest:
        failures.append("root_evidence_digest_mismatch")
    if not verify_signature(payload, anchor.get("signature", {})):
        failures.append("root_anchor_signature_invalid")
    if anchor.get("verified") is not True:
        failures.append("root_evidence_verified_flag_invalid")
    if anchor.get("authority") != "CANONICAL_RUNTIME_ROOT_OF_TRUST":
        failures.append("root_evidence_authority_invalid")
    wrapper_failures = anchor.get("failures")
    payload_failures = payload.get("failures")
    if (
        not isinstance(wrapper_failures, list)
        or not isinstance(payload_failures, list)
        or wrapper_failures != payload_failures
    ):
        failures.append("root_evidence_failures_mismatch")
    if anchor.get("result") == "FAIL":
        if anchor.get("valid") is not False or anchor.get(
            "anchorage_status"
        ) != "INVALID":
            failures.append("root_failure_status_invalid")
    if set(context) != ROOT_CONTEXT_FIELDS:
        failures.append("root_context_schema_invalid")
    if context.get("context_digest") != _digest_without(
        context, "context_digest"
    ):
        failures.append("root_context_digest_invalid")
    eie = state.get("eie", {})
    eie = eie if isinstance(eie, Mapping) else {}
    material = attachment.get("root_trust_material", {})
    material = material if isinstance(material, Mapping) else {}
    attestations = material.get("attestations", [])
    attestations = attestations if isinstance(attestations, list) else []
    expected = {
        "eie_hash": state.get("eie_hash"),
        "source_payload_hash": state.get("source_payload_hash"),
        "adapter_identity": eie.get("adapter_identity"),
        "source_system_identity": eie.get("source_system_identity"),
        "request_fingerprint": state.get("request_fingerprint"),
        "canonical_request_identity": state.get("request_identity_digest"),
        "skg_digest": envelope.get("skg_digest"),
        "skg_verification_status": skg_metadata.get(
            "skg_verification_status"
        ),
        "skg_enrichment_hash": skg_metadata.get("skg_enrichment_hash"),
        "dtn_digest": envelope.get("dtn_digest"),
        "dtn_contextualisation_status": dtn_metadata.get(
            "dtn_contextualisation_status"
        ),
        "dtn_enrichment_hash": dtn_metadata.get("dtn_enrichment_hash"),
        "pre_context_digest": envelope.get("pre_context_digest"),
        "evidence_package_hash": envelope.get("pre_context_digest"),
        "authority_reference_hash": generate_digest(dict(skg_metadata)),
        "pt_evidence_envelope_digest": state.get("pt_evidence_envelope_digest"),
        "state_hash": state.get("root_anchor_bound_state_hash", state.get("state_hash")),
        "state_hash_entering_root": context.get("state_hash_entering_root"),
        "traversal_id": state.get("traversal_id"),
        "timestamp_freshness_reference": envelope.get("freshness_status"),
        "token_chain_reference": context.get(
            "token_chain_reference_entering_root"
        ),
        "audit_chain_reference": context.get(
            "audit_chain_reference_entering_root"
        ),
        "collective_digest": signals.get("digest"),
        "collective_signal_digest": signals.get("digest"),
        "collective_attachment_hash": attachment.get("attachment_hash"),
        "root_trust_material_digest": attachment.get(
            "root_trust_material_digest"
        ),
        "authority_identity": state.get("resolved_authority"),
        "jurisdiction": state.get("jurisdiction"),
        "attestation_identities": [
            item.get("attestation_identity")
            for item in attestations
            if isinstance(item, Mapping)
        ],
        "logical_timestamp": attachment.get("logical_timestamp"),
        "nonce": signals.get("nonce"),
        "root_context_digest": context.get("context_digest"),
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            failures.append(f"root_anchor_mismatch:{field}")
    expected_eie_identity = {
        "object_type": eie.get("object_type"),
        "eie_version": eie.get("eie_version"),
        "request_fingerprint": state.get("request_fingerprint"),
    }
    if payload.get("eie_identity") != expected_eie_identity:
        failures.append("root_anchor_mismatch:eie_identity")
    stage_results = payload.get("stage_results")
    required_stages = (
        "anchor_validation",
        "attestation",
        "attestation_consensus",
        "truth_anchor",
        "truth_continuity",
        "truth_expiry",
        "truth_revocation",
    )
    if not isinstance(stage_results, Mapping) or set(stage_results) != set(
        required_stages
    ):
        failures.append("root_stage_results_schema_invalid")
    elif require_pass and any(
        stage_results.get(stage) != "PASS" for stage in required_stages
    ):
        failures.append("root_stage_result_not_pass")
    expected_stage_digests = {
        stage: (
            generate_digest(feedback.get(stage, {}))
            if isinstance(feedback.get(stage), Mapping)
            else None
        )
        for stage in required_stages
    }
    if payload.get("stage_evidence_digests") != expected_stage_digests:
        failures.append("root_stage_evidence_digest_mismatch")
    if payload.get("result") != anchor.get("result"):
        failures.append("root_evidence_result_mismatch")
    if payload.get("reason") != anchor.get("reason"):
        failures.append("root_evidence_reason_mismatch")
    if payload.get("result") != state.get("authority_first_result"):
        failures.append("root_state_result_mismatch")
    stopped_stage = payload.get("stopped_stage")
    if payload.get("result") == "PASS" and stopped_stage is not None:
        failures.append("root_stopped_stage_invalid")
    if payload.get("result") == "FAIL" and not _present_string(stopped_stage):
        failures.append("root_stopped_stage_missing")
    basis = material.get("validation_basis", {}) if isinstance(
        material, Mapping
    ) else {}
    if payload.get("validation_basis") != basis:
        failures.append("root_validation_basis_mismatch")
    if require_pass:
        truth_anchor = feedback.get("truth_anchor", {})
        truth_anchor = truth_anchor if isinstance(truth_anchor, Mapping) else {}
        if payload.get("truth_anchor_digest") != truth_anchor.get(
            "truth_anchor_hash"
        ):
            failures.append("root_truth_anchor_digest_mismatch")
        tokens = state.get("tokens", {})
        authority_token = tokens.get("authority") if isinstance(
            tokens, Mapping
        ) else None
        if not isinstance(authority_token, Mapping):
            failures.append("root_authority_token_missing")
        elif not verify_token(
            authority_token,
            expected_request_fingerprint=state.get("request_fingerprint"),
        ):
            failures.append("root_authority_token_invalid")
        else:
            if authority_token.get("name") != "authority":
                failures.append("root_authority_token_name_invalid")
            if authority_token.get("issued_at_stage") != "root_of_trust":
                failures.append("root_authority_token_stage_invalid")
            token_payload = authority_token.get("payload", {})
            expected_token_payload = {
                "authority_result": "PASS",
                "root_chain_complete": True,
                "evidence_anchor_digest": anchor.get(
                    "root_evidence_digest"
                ),
                "root_evidence_digest": anchor.get("root_evidence_digest"),
                "request_fingerprint": state.get("request_fingerprint"),
                "eie_digest": state.get("eie_hash"),
                "state_hash_entering_root": context.get(
                    "state_hash_entering_root"
                ),
                "collective_signal_digest": signals.get("digest"),
                "collective_attachment_hash": attachment.get(
                    "attachment_hash"
                ),
                "authority_identity": state.get("resolved_authority"),
                "jurisdiction": state.get("jurisdiction"),
                "attestation_identities": payload.get(
                    "attestation_identities", []
                ),
                "logical_timestamp": payload.get("logical_timestamp"),
                "nonce": payload.get("nonce"),
            }
            if not isinstance(token_payload, Mapping) or dict(
                token_payload
            ) != expected_token_payload:
                failures.append("root_authority_token_payload_mismatch")
            if authority_token.get("state_hash") != payload.get(
                "state_hash_after_root_chain"
            ):
                failures.append("root_authority_token_state_hash_mismatch")
    return not failures, sorted(set(failures))


def validate_root_anchor_binding(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Compatibility name for the authoritative Pass-4 Root validator."""

    return validate_root_of_trust_evidence(state, require_pass=True)


def validate_control_chain_bindings(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    from sbp_lex.shared.state_builder import validate_boundary_protection

    boundary_valid, boundary_failures = validate_boundary_protection(state)
    if not boundary_valid:
        failures.extend(boundary_failures)
    for validator in (
        validate_eie_binding,
        validate_skg_dtn_binding,
        validate_collective_attachment_binding,
    ):
        valid, validator_failures = validator(state)
        if not valid:
            failures.extend(validator_failures)
    if state.get("root_of_trust_evidence_anchor"):
        root_valid, root_failures = validate_root_of_trust_evidence(
            state, require_pass=True
        )
        if not root_valid:
            failures.extend(root_failures)
    return not failures, sorted(set(failures))
