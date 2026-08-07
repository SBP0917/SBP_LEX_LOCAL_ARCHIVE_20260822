from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.collective.digital_twin_network_engine import (
    prepare_dtn_context,
    sign_dtn_context,
    verify_dtn_context,
)
from sbp_lex.collective.sovereign_knowledge_graph_engine import (
    prepare_skg_context,
    sign_skg_context,
    verify_skg_context,
)
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.hash_chain import append_hash_entry, rebuild_state_hash
from sbp_lex.governance.procedural_truth_envelope import (
    build_pt_evidence_envelope,
)
from sbp_lex.shared.state_builder import (
    EIE_FRESHNESS_WINDOW_SECONDS,
    build_execution_intent_envelope,
    validate_boundary_protection,
)

COLLECTIVE_SIGNAL_STATUS_ATTACHED = "ATTACHED"
COLLECTIVE_SIGNAL_STATUS_EMPTY = "EMPTY"
COLLECTIVE_SIGNAL_STATUS_REJECTED = "REJECTED"
CANONICAL_SIGNAL_AUTHORITY = "CANONICAL_RUNTIME"


def _canonical_signal_timestamp(request_fingerprint: str) -> int:
    return int(request_fingerprint[:12], 16)


def prepare_pre_context_signals(
    request: Mapping[str, Any],
    *,
    eie: Mapping[str, Any] | None = None,
    substrate_evidence: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    request_fingerprint = generate_digest(dict(request))
    canonical_eie = (
        deepcopy(dict(eie))
        if isinstance(eie, Mapping)
        else build_execution_intent_envelope(request)
    )
    skg_context = sign_skg_context(prepare_skg_context(request))
    dtn_context = sign_dtn_context(prepare_dtn_context(request, skg_context))
    timestamp = _canonical_signal_timestamp(request_fingerprint)
    payload = {
        "collective_signal_schema_version": "desktop-v1.collective-signal.v1",
        "request_fingerprint": request_fingerprint,
        "eie_digest": canonical_eie.get("eie_hash"),
        "intent_signal": str(request.get("action", "")),
        "risk_potential_signal": dtn_context.get("risk_potential_signal"),
        "authority_link_signal": skg_context.get("authority_link_signal"),
        "jurisdiction_signal": skg_context.get("jurisdiction_signal"),
        "dependency_signal": dtn_context.get("dependency_signal"),
        "policy_conflict_signal": skg_context.get("policy_conflict_signal"),
        "operational_context_signal": dtn_context.get("operational_context_signal"),
        "precedence_signal": skg_context.get("precedence_signal"),
        "ap_acf_declaration": request.get("payload", {}).get("classification", request.get("classification", {})),
        "manufacturer_declaration": request.get("manufacturer_declaration", {}),
        "skg_digest": skg_context.get("skg_digest"),
        "dtn_digest": dtn_context.get("dtn_digest"),
        "skg_context": skg_context,
        "dtn_context": dtn_context,
        "timestamp": timestamp,
        "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
        "freshness_window_seconds": EIE_FRESHNESS_WINDOW_SECONDS,
        "nonce": generate_digest(
            {
                "request_fingerprint": request_fingerprint,
                "eie_digest": canonical_eie.get("eie_hash"),
                "timestamp": timestamp,
                "timestamp_authority": CANONICAL_SIGNAL_AUTHORITY,
            }
        )[:32],
    }
    if substrate_evidence is not None:
        payload["synthetic_substrate_evidence"] = deepcopy(
            dict(substrate_evidence)
        )
    return {**payload, "digest": generate_digest(payload), "signature": sign_payload(payload)}


def _signal_payload_for_digest(signals: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: deepcopy(value) for key, value in dict(signals).items() if key not in {"digest", "signature"}}


def _root_trust_material(
    *,
    state: Mapping[str, Any],
    signals: Mapping[str, Any],
    substrate_evidence: Mapping[str, Any],
) -> Dict[str, Any]:
    """Project only admitted, signed Desktop-v1 material needed by Root.

    The projection does not grant authority.  It records the authority and
    attestation assertions that crossed Hard Entry so Root can validate them
    rather than reconstructing authority from unbound request fields.
    """

    authority_signal = signals.get("authority_link_signal", {})
    authority_signal = (
        authority_signal if isinstance(authority_signal, Mapping) else {}
    )
    jurisdiction_signal = signals.get("jurisdiction_signal", {})
    jurisdiction_signal = (
        jurisdiction_signal if isinstance(jurisdiction_signal, Mapping) else {}
    )
    precedence_signal = signals.get("precedence_signal", {})
    precedence_signal = (
        precedence_signal if isinstance(precedence_signal, Mapping) else {}
    )
    timestamp = signals.get("timestamp")
    window = signals.get("freshness_window_seconds")
    valid_until = (
        timestamp + window
        if isinstance(timestamp, int)
        and not isinstance(timestamp, bool)
        and isinstance(window, int)
        and not isinstance(window, bool)
        else None
    )
    authority_identity = authority_signal.get("resolved_authority")
    jurisdiction = jurisdiction_signal.get("jurisdiction")
    collective_digest = signals.get("digest")
    collective_signature_digest = generate_digest(signals.get("signature", {}))
    verified_references = state.get("verified_substrate_references", {})
    verified_references = (
        verified_references
        if isinstance(verified_references, Mapping)
        else {}
    )
    skg_status = substrate_evidence.get(
        "skg_validation_status",
        verified_references.get("skg_validation_status"),
    )
    dtn_status = substrate_evidence.get(
        "dtn_validation_status",
        verified_references.get("dtn_validation_status"),
    )
    bridge_status = substrate_evidence.get(
        "bridge_validation_status",
        verified_references.get("bridge_validation_status"),
    )
    admitted_basis_valid = (
        skg_status == "VALID"
        and dtn_status == "VALID"
        and bridge_status == "PASS"
        and authority_identity == state.get("resolved_authority")
        and jurisdiction == state.get("jurisdiction")
    )
    common_binding = {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": collective_digest,
        "issued_at": timestamp,
        "valid_until": valid_until,
        "nonce": signals.get("nonce"),
    }

    authority = {
        "authority_identity": authority_identity,
        "jurisdiction": jurisdiction,
        "legitimacy_status": authority_signal.get(
            "legitimacy_status", "VALID" if admitted_basis_valid else "INVALID"
        ),
        "authority_status": authority_signal.get(
            "authority_status", "ACTIVE" if admitted_basis_valid else "INVALID"
        ),
        "revoked": authority_signal.get(
            "authority_revoked", authority_signal.get("revoked", False)
        ),
        "issued_at": authority_signal.get("authority_valid_from", timestamp),
        "valid_until": authority_signal.get(
            "authority_valid_until", valid_until
        ),
        "skg_package_digest": substrate_evidence.get(
            "skg_package_digest",
            verified_references.get("skg_package_digest", signals.get("skg_digest")),
        ),
    }
    authority["authority_evidence_digest"] = generate_digest(authority)

    default_attestation_identity = generate_digest(
        {
            "authority_identity": authority_identity,
            "collective_signal_digest": collective_digest,
            "collective_signature_digest": collective_signature_digest,
        }
    )
    consensus_inputs = authority_signal.get("attestation_consensus_records")
    if not isinstance(consensus_inputs, list) or not consensus_inputs:
        consensus_inputs = [{}]
    attestations: list[dict[str, Any]] = []
    for index, supplied in enumerate(consensus_inputs):
        supplied = supplied if isinstance(supplied, Mapping) else {}
        attestation = {
            "attestation_identity": supplied.get(
                "attestation_identity",
                authority_signal.get(
                    "attestation_identity",
                    default_attestation_identity
                    if index == 0
                    else generate_digest(
                        {
                            "base": default_attestation_identity,
                            "index": index,
                        }
                    ),
                ),
            ),
            "authority_identity": supplied.get(
                "attestation_authority_identity",
                authority_signal.get(
                    "attestation_authority_identity", authority_identity
                ),
            ),
            "jurisdiction": supplied.get(
                "attestation_jurisdiction",
                authority_signal.get("attestation_jurisdiction", jurisdiction),
            ),
            "status": supplied.get(
                "attestation_status",
                authority_signal.get(
                    "attestation_status",
                    "VALID" if admitted_basis_valid else "INVALID",
                ),
            ),
            "revoked": supplied.get(
                "attestation_revoked",
                authority_signal.get("attestation_revoked", False),
            ),
            "collective_signature_digest": collective_signature_digest,
            "consensus_statement_digest": supplied.get(
                "consensus_statement_digest",
                authority_signal.get(
                    "attestation_consensus_statement_digest",
                    collective_digest,
                ),
            ),
            **common_binding,
        }
        attestation["collective_signal_digest"] = supplied.get(
            "attestation_subject_digest",
            authority_signal.get(
                "attestation_subject_digest", collective_digest
            ),
        )
        attestation["issued_at"] = supplied.get(
            "attestation_issued_at",
            authority_signal.get("attestation_issued_at", timestamp),
        )
        attestation["valid_until"] = supplied.get(
            "attestation_valid_until",
            authority_signal.get("attestation_valid_until", valid_until),
        )
        attestation["attestation_digest"] = generate_digest(attestation)
        attestations.append(attestation)

    lineage = precedence_signal.get("temporal_rule_lineage", [])
    truth = {
        "truth_identity": generate_digest(
            {
                "request_fingerprint": state.get("request_fingerprint"),
                "eie_digest": state.get("eie_hash"),
                "collective_signal_digest": collective_digest,
                "temporal_rule_lineage": lineage,
            }
        ),
        "status": precedence_signal.get(
            "truth_status", "VALID" if admitted_basis_valid else "INVALID"
        ),
        "revoked": precedence_signal.get("truth_revoked", False),
        "continuity_reference": precedence_signal.get(
            "truth_continuity_reference", generate_digest(lineage)
        ),
        **common_binding,
    }
    truth["issued_at"] = precedence_signal.get("truth_issued_at", timestamp)
    truth["valid_until"] = precedence_signal.get(
        "truth_valid_until", valid_until
    )
    truth["truth_material_digest"] = generate_digest(truth)

    material = {
        "schema_version": "desktop-v1.root-trust-material.v1",
        "authority": authority,
        "attestations": attestations,
        "truth": truth,
        "skg_validation_status": skg_status,
        "dtn_validation_status": dtn_status,
        "bridge_validation_status": bridge_status,
        "validation_basis": {
            "basis": "VALIDATED_SYNTHETIC_SKG_DTN_BRIDGE",
            "authority_identity_exact": authority_identity
            == state.get("resolved_authority"),
            "jurisdiction_exact": jurisdiction == state.get("jurisdiction"),
            "skg_package_digest": verified_references.get("skg_package_digest"),
            "dtn_package_digest": verified_references.get("dtn_package_digest"),
            "bridge_result_digest": verified_references.get(
                "bridge_result_digest"
            ),
            "closed_synthetic_schema_revocation_default": "CLEAR",
        },
    }
    return {**material, "material_digest": generate_digest(material)}


def _collective_attachment_attestation(
    attachment_payload: Mapping[str, Any], attachment_hash: str
) -> Dict[str, Any]:
    payload = {
        "schema_version": "desktop-v1.collective-attachment-attestation.v1",
        "attachment_hash": attachment_hash,
        "request_fingerprint": attachment_payload.get("request_fingerprint"),
        "eie_digest": attachment_payload.get("eie_digest"),
        "collective_signal_digest": attachment_payload.get("signal_digest"),
        "collective_projection_digest": attachment_payload.get(
            "collective_projection_digest"
        ),
        "prior_state_hash": attachment_payload.get("prior_state_hash"),
        "root_trust_material_digest": attachment_payload.get(
            "root_trust_material_digest"
        ),
    }
    digest = generate_digest(payload)
    signature = sign_payload(payload)
    return {
        "payload": payload,
        "attestation_digest": digest,
        "signature": signature,
        "verified": verify_signature(payload, signature),
    }


def validate_collective_signal_package(
    *,
    signals: Mapping[str, Any],
    request_fingerprint: str,
    eie_digest: str | None = None,
    validation_logical_time: int | None = None,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if not isinstance(signals, Mapping):
        return False, ["collective_signals_not_mapping"]
    if signals.get("request_fingerprint") != request_fingerprint:
        failures.append("collective_signal_request_fingerprint_mismatch")
    if eie_digest is not None and signals.get("eie_digest") != eie_digest:
        failures.append("collective_signal_eie_digest_mismatch")
    payload = _signal_payload_for_digest(signals)
    if signals.get("digest") != generate_digest(payload):
        failures.append("collective_signal_digest_mismatch")
    if not verify_signature(payload, signals.get("signature", {})):
        failures.append("collective_signal_signature_invalid")
    if not signals.get("nonce"):
        failures.append("collective_signal_nonce_missing")
    if not isinstance(signals.get("timestamp"), int):
        failures.append("collective_signal_timestamp_invalid")
    window = signals.get("freshness_window_seconds")
    if not isinstance(window, int) or isinstance(window, bool) or window < 0:
        failures.append("collective_signal_freshness_window_invalid")
    elif validation_logical_time is not None and isinstance(
        signals.get("timestamp"), int
    ):
        age = validation_logical_time - int(signals["timestamp"])
        if age < 0 or age > window:
            failures.append("stale_collective_signal")
    skg_context = signals.get("skg_context", {})
    dtn_context = signals.get("dtn_context", {})
    skg_valid, skg_failures = verify_skg_context(skg_context)
    if not skg_valid:
        failures.extend(skg_failures)
    dtn_valid, dtn_failures = verify_dtn_context(
        dtn_context, expected_skg_digest=signals.get("skg_digest")
    )
    if not dtn_valid:
        failures.extend(dtn_failures)
    if signals.get("skg_digest") != skg_context.get("skg_digest"):
        failures.append("collective_skg_digest_mismatch")
    if signals.get("dtn_digest") != dtn_context.get("dtn_digest"):
        failures.append("collective_dtn_digest_mismatch")
    for field in (
        "authority_link_signal",
        "jurisdiction_signal",
        "policy_conflict_signal",
        "precedence_signal",
    ):
        if signals.get(field) != skg_context.get(field):
            failures.append(f"collective_skg_projection_mismatch:{field}")
    for field in (
        "risk_potential_signal",
        "dependency_signal",
        "operational_context_signal",
    ):
        if signals.get(field) != dtn_context.get(field):
            failures.append(f"collective_dtn_projection_mismatch:{field}")
    return len(failures) == 0, failures


def attach_collective_signals(
    state: Mapping[str, Any],
    pre_context_signals: Mapping[str, Any] | None = None,
    *,
    validation_logical_time: int | None = None,
) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    if working_state.get("collective_signal_status") != "UNATTACHED":
        raise ValueError("collective_signal_already_attached")
    protected_valid, protected_failures = validate_boundary_protection(
        working_state
    )
    if not protected_valid:
        raise ValueError(
            "protected_state_invalid_before_attachment:"
            + ",".join(protected_failures)
        )
    if pre_context_signals is None:
        working_state["collective_signals"] = {}
        working_state["collective_signal_status"] = COLLECTIVE_SIGNAL_STATUS_REJECTED
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state.setdefault("governance_feedback", {})[
            "collective_signal_failures"
        ] = ["pre_context_signals_required"]
        working_state.setdefault("audit_trace", []).append({
            "stage": "collective_attach",
            "event": "NO_PRE_CONTEXT_SIGNALS_PROVIDED",
        })
        return append_hash_entry(
            working_state,
            stage="collective_attach",
            payload={"status": COLLECTIVE_SIGNAL_STATUS_REJECTED},
        )

    eie = working_state.get("eie", {})
    freshness = eie.get("freshness", {}) if isinstance(eie, Mapping) else {}
    logical_time = (
        validation_logical_time
        if validation_logical_time is not None
        else freshness.get("issued_at")
    )
    valid, failures = validate_collective_signal_package(
        signals=pre_context_signals,
        request_fingerprint=working_state.get("request_fingerprint", ""),
        eie_digest=working_state.get("eie_hash"),
        validation_logical_time=(
            logical_time if isinstance(logical_time, int) else None
        ),
    )
    authority_signal = pre_context_signals.get("authority_link_signal", {})
    jurisdiction_signal = pre_context_signals.get("jurisdiction_signal", {})
    if authority_signal.get("resolved_authority") != working_state.get("resolved_authority"):
        failures.append("collective_authority_context_mismatch")
        valid = False
    if jurisdiction_signal.get("jurisdiction") != working_state.get("jurisdiction"):
        failures.append("collective_jurisdiction_context_mismatch")
        valid = False
    if not valid:
        working_state["collective_signals"] = {}
        working_state["collective_signal_status"] = COLLECTIVE_SIGNAL_STATUS_REJECTED
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state.setdefault("governance_feedback", {})["collective_signal_failures"] = failures
        working_state.setdefault("audit_trace", []).append({"stage": "collective_attach", "event": "COLLECTIVE_SIGNAL_REJECTED", "failures": failures})
        return append_hash_entry(working_state, stage="collective_attach", payload={"status": COLLECTIVE_SIGNAL_STATUS_REJECTED, "failures": failures})

    working_state["collective_signals"] = deepcopy(dict(pre_context_signals))
    working_state["collective_signals"] = {
        key: deepcopy(pre_context_signals.get(key))
        for key in (
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
            "ap_acf_declaration",
            "manufacturer_declaration",
            "skg_digest",
            "dtn_digest",
            "timestamp",
            "timestamp_authority",
            "freshness_window_seconds",
            "nonce",
            "digest",
            "signature",
        )
    }
    working_state["collective_signal_status"] = COLLECTIVE_SIGNAL_STATUS_ATTACHED
    substrate_evidence = pre_context_signals.get(
        "synthetic_substrate_evidence", {}
    )
    if not isinstance(substrate_evidence, Mapping):
        substrate_evidence = {}
    working_state["collective_signal_evidence"] = {
        "role": "context_only_non_authoritative",
        "request_bound": True,
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_bound": True,
        "eie_digest": working_state.get("eie_hash"),
        "digest_bound": True,
        "signal_digest": pre_context_signals.get("digest"),
        "collective_projection_digest": generate_digest(
            working_state.get("collective_signals", {})
        ),
        "freshness_bound": True,
        "logical_timestamp": pre_context_signals.get("timestamp"),
        "skg_verified": True,
        "dtn_verified": True,
        "skg_dtn_relation_verified": True,
        "provenance": {
            "skg_digest": pre_context_signals.get("skg_digest"),
            "dtn_digest": pre_context_signals.get("dtn_digest"),
            "timestamp_authority": pre_context_signals.get("timestamp_authority"),
            "skg_package_digest": substrate_evidence.get(
                "skg_package_digest", pre_context_signals.get("skg_digest")
            ),
            "dtn_package_digest": substrate_evidence.get(
                "dtn_package_digest", pre_context_signals.get("dtn_digest")
            ),
            "bridge_result_digest": substrate_evidence.get(
                "bridge_result_digest"
            ),
        },
    }
    request_snapshot = working_state.get("request_identity_snapshot", {})
    if not isinstance(request_snapshot, Mapping) or not isinstance(eie, Mapping):
        raise ValueError("attachment_state_binding_invalid")
    envelope, envelope_digest = build_pt_evidence_envelope(
        request_snapshot,
        pre_context_signals,
        eie=eie,
        admitted_basis=working_state.get("verified_substrate_references", {}),
    )
    working_state["pt_evidence_envelope"] = envelope
    working_state["pt_evidence_envelope_digest"] = envelope_digest
    attachment_payload = {
        "schema_version": "desktop-v1.collective-attachment.v1",
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "signal_digest": pre_context_signals.get("digest"),
        "collective_projection_digest": generate_digest(
            working_state.get("collective_signals", {})
        ),
        "logical_timestamp": pre_context_signals.get("timestamp"),
        "freshness_window_seconds": pre_context_signals.get(
            "freshness_window_seconds"
        ),
        "prior_state_hash": working_state.get("state_hash"),
        "skg_package_digest": working_state.get(
            "verified_substrate_references", {}
        ).get("skg_package_digest"),
        "dtn_package_digest": working_state.get(
            "verified_substrate_references", {}
        ).get("dtn_package_digest"),
        "bridge_result_digest": working_state.get(
            "verified_substrate_references", {}
        ).get("bridge_result_digest"),
    }
    root_trust_material = _root_trust_material(
        state=working_state,
        signals=pre_context_signals,
        substrate_evidence=substrate_evidence,
    )
    attachment_payload["root_trust_material"] = root_trust_material
    attachment_payload["root_trust_material_digest"] = root_trust_material[
        "material_digest"
    ]
    attachment_hash = generate_digest(attachment_payload)
    working_state["collective_attachment"] = {
        **attachment_payload,
        "attachment_hash": attachment_hash,
        "attestation": _collective_attachment_attestation(
            attachment_payload, attachment_hash
        ),
    }
    working_state.setdefault("audit_trace", []).append({"stage": "collective_attach", "event": "COLLECTIVE_SIGNAL_ATTACHED", "digest": pre_context_signals.get("digest")})
    protected_valid, protected_failures = validate_boundary_protection(
        working_state
    )
    if not protected_valid:
        raise ValueError(
            "protected_state_overwrite_rejected:"
            + ",".join(protected_failures)
        )
    working_state = append_hash_entry(
        working_state,
        stage="collective_attach",
        payload={
            "status": COLLECTIVE_SIGNAL_STATUS_ATTACHED,
            "digest": pre_context_signals.get("digest"),
            "attachment_hash": working_state["collective_attachment"][
                "attachment_hash"
            ],
        },
    )
    working_state["state_hash"] = rebuild_state_hash(working_state)
    return working_state
