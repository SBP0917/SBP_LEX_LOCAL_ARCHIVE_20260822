from __future__ import annotations

from typing import Any, Mapping

from sbp_lex.security.pqc import generate_digest, verify_signature
from sbp_lex.security.threshold_tokens import verify_threshold_bundle
from sbp_lex.security.token_stack import verify_token
from sbp_lex.config.security_config import STATE_VERSION
from sbp_lex.shared.control_chain_validation import validate_control_chain_bindings

TOKEN_STAGE = {
    "authority": "root_of_trust",
    "procedural_truth": "procedural_truth",
    "classification": "classification",
    "licensing": "licensing",
    "governance": "governance",
    "grc": "grc",
    "domain": "domain_wrap",
    "aurion": "aurion_runtime",
    "execution_boundary": "execution_gate",
    "execution_attestation": "execution_gate",
}

CANONICAL_STAGE_SEQUENCE = (
    "hard_ingress",
    "state_construction",
    "collective_attach",
    "ap_acf_precheck",
    "root_of_trust",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain_wrap",
    "aurion_runtime",
    "execution_gate",
)


def _evidence_digest(
    evidence: Mapping[str, Any], *names: str
) -> object:
    for name in names:
        value = evidence.get(name)
        if value not in (None, ""):
            return value
    return None


def _payload_value(payload: Mapping[str, Any], *names: str) -> object:
    for name in names:
        if name in payload:
            return payload.get(name)
    return None


def _validate_procedural_truth_evidence(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Validate the signed, immutable PT result consumed downstream."""
    evidence = state.get("procedural_truth_evidence")
    if not isinstance(evidence, Mapping):
        return False, ["procedural_truth_evidence_missing"]
    payload = evidence.get("payload")
    if not isinstance(payload, Mapping):
        return False, ["procedural_truth_evidence_payload_missing"]

    failures: list[str] = []
    digest = _evidence_digest(
        evidence,
        "pt_evidence_digest",
        "procedural_truth_evidence_digest",
        "evidence_digest",
    )
    if digest != generate_digest(dict(payload)):
        failures.append("procedural_truth_evidence_digest_invalid")
    if evidence.get("verified") is not True:
        failures.append("procedural_truth_evidence_not_verified")
    if not verify_signature(payload, evidence.get("signature", {})):
        failures.append("procedural_truth_evidence_signature_invalid")

    expected = {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "procedural_truth_outcome": state.get("procedural_truth_outcome"),
        "tier": state.get("safety_profile", {}).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
    }
    aliases = {
        "eie_digest": ("eie_digest", "eie_hash"),
        "procedural_truth_result": (
            "procedural_truth_result",
            "pt_result",
            "result",
        ),
        "procedural_truth_outcome": (
            "procedural_truth_outcome",
            "pt_outcome",
        ),
        "tier": ("tier", "computed_tier"),
    }
    for field, expected_value in expected.items():
        actual = _payload_value(payload, *aliases.get(field, (field,)))
        if actual != expected_value:
            failures.append(f"procedural_truth_evidence_mismatch:{field}")

    collective_digest = state.get("collective_signals", {}).get("digest")
    if _payload_value(
        payload, "collective_signal_digest", "collective_digest"
    ) != collective_digest:
        failures.append(
            "procedural_truth_evidence_mismatch:collective_signal_digest"
        )

    root_evidence = state.get("root_of_trust_evidence", {})
    root_evidence_digest = (
        _evidence_digest(
            root_evidence,
            "root_evidence_digest",
            "evidence_digest",
        )
        if isinstance(root_evidence, Mapping)
        else None
    )
    if payload.get("root_evidence_digest") != root_evidence_digest:
        failures.append(
            "procedural_truth_evidence_mismatch:root_evidence_digest"
        )

    envelope = state.get("pt_evidence_envelope", {})
    envelope = envelope if isinstance(envelope, Mapping) else {}
    source_records = envelope.get("source_records", [])
    source_records = source_records if isinstance(source_records, list) else []
    threshold_snapshot = state.get("governance_feedback", {}).get(
        "threshold_snapshot", {}
    )
    threshold_snapshot = (
        threshold_snapshot
        if isinstance(threshold_snapshot, Mapping)
        else {}
    )
    observed = threshold_snapshot.get(
        "qualified_evidence_count",
        envelope.get("qualifying_source_count"),
    )
    if payload.get("source_count_total") != len(source_records):
        failures.append(
            "procedural_truth_evidence_mismatch:source_count_total"
        )
    if payload.get("source_count_qualifying") != observed:
        failures.append(
            "procedural_truth_evidence_mismatch:source_count_qualifying"
        )
    if payload.get("corroboration_observed") != observed:
        failures.append(
            "procedural_truth_evidence_mismatch:corroboration_observed"
        )
    if payload.get("evidentiary_sufficiency_result") != "SUFFICIENT":
        failures.append(
            "procedural_truth_evidence_sufficiency_not_met"
        )
    if payload.get("timestamp_authority") != "CANONICAL_RUNTIME":
        failures.append(
            "procedural_truth_evidence_timestamp_authority_invalid"
        )
    if not isinstance(payload.get("timestamp"), int) or isinstance(
        payload.get("timestamp"), bool
    ):
        failures.append("procedural_truth_evidence_timestamp_invalid")
    if not isinstance(payload.get("nonce"), str) or not payload.get("nonce"):
        failures.append("procedural_truth_evidence_nonce_invalid")
    if not isinstance(payload.get("threshold_state_digest"), str) or not (
        payload.get("threshold_state_digest")
    ):
        failures.append("procedural_truth_threshold_state_digest_missing")
    return not failures, sorted(set(failures))


def validate_root_pt_eligibility(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Fail-closed Root/PT admission guard for Classification and later stages."""
    failures: list[str] = []
    if state.get("authority_first_result") != "PASS":
        failures.append("root_pt_ineligible:root_not_pass")

    # Imported lazily so the Root implementation remains the single owner of
    # Root evidence validation and no second Root engine is introduced here.
    from sbp_lex.shared import control_chain_validation

    root_validator = getattr(
        control_chain_validation, "validate_root_of_trust_evidence", None
    )
    if callable(root_validator):
        root_valid, root_failures = root_validator(state, require_pass=True)
    else:
        root_valid, root_failures = (
            control_chain_validation.validate_root_anchor_binding(state)
        )
    if not root_valid:
        failures.extend(
            f"root_pt_ineligible:{failure}" for failure in root_failures
        )

    if state.get("procedural_truth_result") != "PASS":
        failures.append("root_pt_ineligible:procedural_truth_not_pass")
    if state.get("procedural_truth_outcome") != "PT_PASS":
        failures.append("root_pt_ineligible:procedural_truth_outcome_not_pass")

    certification = state.get("procedural_truth_certification")
    if not isinstance(certification, Mapping):
        failures.append("root_pt_ineligible:procedural_truth_certification_missing")
        certification = {}
    if certification.get("procedural_truth_status") != "PASS":
        failures.append("root_pt_ineligible:procedural_truth_status_not_pass")
    if certification.get("certification_status") != "CERTIFIED":
        failures.append("root_pt_ineligible:procedural_truth_not_certified")
    if certification.get("root_of_trust_anchorage_status") != "VALID":
        failures.append("root_pt_ineligible:root_anchorage_not_valid")
    if certification.get("request_fingerprint") != state.get(
        "request_fingerprint"
    ):
        failures.append("root_pt_ineligible:pt_request_binding_mismatch")
    if certification.get("eie_hash") != state.get("eie_hash"):
        failures.append("root_pt_ineligible:pt_eie_binding_mismatch")
    if certification.get("traversal_id") != state.get("traversal_id"):
        failures.append("root_pt_ineligible:pt_traversal_binding_mismatch")

    # PT remains the sole owner of its signed evidence contract.  The local
    # validator is a compatibility fallback for fail-closed intermediate
    # states and older stored records.
    from sbp_lex.governance import procedural_truth_engine

    pt_validator = getattr(
        procedural_truth_engine,
        "validate_procedural_truth_evidence",
        None,
    )
    if callable(pt_validator):
        pt_evidence_valid, pt_evidence_failures = pt_validator(
            state, require_pass=True
        )
    else:
        pt_evidence_valid, pt_evidence_failures = (
            _validate_procedural_truth_evidence(state)
        )
    if not pt_evidence_valid:
        failures.extend(
            f"root_pt_ineligible:{failure}"
            for failure in pt_evidence_failures
        )

    tokens = state.get("tokens", {})
    if not isinstance(tokens, Mapping):
        tokens = {}
        failures.append("root_pt_ineligible:tokens_missing")
    for name, stage in (
        ("authority", "root_of_trust"),
        ("procedural_truth", "procedural_truth"),
    ):
        token = tokens.get(name)
        if not isinstance(token, Mapping):
            failures.append(f"root_pt_ineligible:missing_token:{name}")
            continue
        if token.get("issued_at_stage") != stage:
            failures.append(f"root_pt_ineligible:token_stage_mismatch:{name}")
            continue
        if not verify_token(
            token,
            expected_request_fingerprint=state.get("request_fingerprint"),
        ):
            failures.append(f"root_pt_ineligible:invalid_token:{name}")
            continue
        payload = token.get("payload", {})
        if not isinstance(payload, Mapping) or not _semantic_token_matches(
            state, name, payload
        ):
            failures.append(f"root_pt_ineligible:token_semantic_mismatch:{name}")

    tier = state.get("safety_profile", {}).get("computed_tier")
    corroboration_required = state.get("corroboration_required")
    pt_token = tokens.get("procedural_truth", {})
    if isinstance(pt_token, Mapping):
        if certification.get("pt_token_hash") != pt_token.get("digest"):
            failures.append("root_pt_ineligible:pt_certification_token_mismatch")
        if pt_token.get("tier") != tier:
            failures.append("root_pt_ineligible:pt_token_tier_mismatch")
        if pt_token.get("corroboration_required") != corroboration_required:
            failures.append(
                "root_pt_ineligible:pt_token_corroboration_mismatch"
            )
        if certification.get("state_hash") != pt_token.get("state_hash"):
            failures.append("root_pt_ineligible:pt_token_state_hash_mismatch")
        pt_payload = pt_token.get("payload", {})
        if isinstance(pt_payload, Mapping):
            required_payload_bindings = {
                "eie_digest": state.get("eie_hash"),
                "collective_signal_digest": state.get(
                    "collective_signals", {}
                ).get("digest"),
                "tier": tier,
                "corroboration_required": corroboration_required,
            }
            for field, expected_value in required_payload_bindings.items():
                if pt_payload.get(field) != expected_value:
                    failures.append(
                        f"root_pt_ineligible:pt_token_binding_mismatch:{field}"
                    )
            evidence = state.get("procedural_truth_evidence", {})
            evidence_digest = (
                _evidence_digest(
                    evidence,
                    "pt_evidence_digest",
                    "procedural_truth_evidence_digest",
                    "evidence_digest",
                )
                if isinstance(evidence, Mapping)
                else None
            )
            if pt_payload.get("pt_evidence_digest") != evidence_digest:
                failures.append(
                    "root_pt_ineligible:pt_token_binding_mismatch:pt_evidence_digest"
                )
            evidence_payload = (
                evidence.get("payload", {})
                if isinstance(evidence, Mapping)
                else {}
            )
            evidence_payload = (
                evidence_payload
                if isinstance(evidence_payload, Mapping)
                else {}
            )
            for field in (
                "root_evidence_digest",
                "corroboration_observed",
                "source_assessment_digest",
                "evidentiary_sufficiency_result",
                "threshold_state_digest",
                "threshold_bundle_digest",
                "threshold_token_digests",
                "timestamp",
                "timestamp_authority",
                "nonce",
            ):
                if pt_payload.get(field) != evidence_payload.get(field):
                    failures.append(
                        f"root_pt_ineligible:pt_token_binding_mismatch:{field}"
                    )
            if pt_payload.get("issuing_stage") != "procedural_truth":
                failures.append(
                    "root_pt_ineligible:pt_token_binding_mismatch:issuing_stage"
                )

    if certification.get("tier") != tier:
        failures.append("root_pt_ineligible:pt_certification_tier_mismatch")
    envelope = state.get("pt_evidence_envelope", {})
    if not isinstance(envelope, Mapping):
        failures.append("root_pt_ineligible:pt_envelope_missing")
        envelope = {}
    if envelope.get("threshold_tier") != tier:
        failures.append("root_pt_ineligible:active_tier_mismatch")
    if envelope.get("threshold_requirement") != corroboration_required:
        failures.append("root_pt_ineligible:active_corroboration_mismatch")
    if state.get("corroboration_met") is not True:
        failures.append("root_pt_ineligible:corroboration_not_met")

    threshold_valid, threshold_failures = verify_threshold_bundle(state)
    if not threshold_valid:
        failures.extend(
            f"root_pt_ineligible:{failure}"
            for failure in threshold_failures
        )
    return not failures, sorted(set(failures))


def verify_canonical_stage_lineage(
    state: Mapping[str, Any], *, required_tokens: tuple[str, ...]
) -> tuple[bool, list[str]]:
    order = state.get("integration_stage_order", [])
    if not isinstance(order, list):
        return False, ["traversal_bypass_detected:stage_order_missing"]
    required_stages = ["hard_ingress", "state_construction", "collective_attach", "ap_acf_precheck"]
    failures: list[str] = []
    if state.get("hard_entry_gate", {}).get("accepted") is not True:
        failures.append("traversal_bypass_detected:hard_entry_gate")
    for token_name in required_tokens:
        stage = TOKEN_STAGE.get(token_name)
        if stage and stage not in required_stages:
            required_stages.append(stage)
        if token_name == "governance" and "grc" not in required_stages:
            required_stages.append("grc")
    positions: list[int] = []
    for stage in required_stages:
        if order.count(stage) != 1:
            failures.append(f"traversal_bypass_detected:{stage}")
        else:
            positions.append(order.index(stage))
    if positions != sorted(positions):
        failures.append("traversal_bypass_detected:stage_order")
    canonical_positions = [CANONICAL_STAGE_SEQUENCE.index(stage) for stage in required_stages]
    if canonical_positions != sorted(canonical_positions):
        failures.append("traversal_bypass_detected:canonical_sequence")
    return not failures, sorted(set(failures))


def verify_request_identity_binding(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    snapshot = state.get("request_identity_snapshot")
    if not isinstance(snapshot, Mapping):
        return False, ["toctou_state_mismatch:request_snapshot_missing"]
    digest = generate_digest(dict(snapshot))
    if digest != state.get("request_identity_digest") or digest != state.get("request_fingerprint"):
        failures.append("toctou_state_mismatch:request_digest")
    for field in ("action", "payload", "context", "resolved_authority", "jurisdiction"):
        if state.get(field) != snapshot.get(field):
            failures.append(f"toctou_state_mismatch:{field}")
    return not failures, failures


def _semantic_token_matches(state: Mapping[str, Any], name: str, payload: Mapping[str, Any]) -> bool:
    if name == "authority":
        matches = (
            payload.get("authority_result") == state.get("authority_first_result")
            and payload.get("evidence_anchor_digest")
            == state.get("root_of_trust_evidence_anchor", {}).get("anchor_digest")
        )
        root_evidence = state.get("root_of_trust_evidence", {})
        if isinstance(root_evidence, Mapping) and root_evidence:
            matches = matches and payload.get("root_evidence_digest") == (
                _evidence_digest(
                    root_evidence,
                    "root_evidence_digest",
                    "evidence_digest",
                )
            )
        return matches
    if name == "procedural_truth":
        matches = (
            payload.get("procedural_truth_result") == state.get("procedural_truth_result")
            and payload.get("procedural_truth_outcome") == state.get("procedural_truth_outcome")
            and payload.get("pt_evidence_envelope_digest")
            == state.get("pt_evidence_envelope_digest")
        )
        evidence = state.get("procedural_truth_evidence", {})
        evidence_digest = (
            _evidence_digest(
                evidence,
                "pt_evidence_digest",
                "procedural_truth_evidence_digest",
                "evidence_digest",
            )
            if isinstance(evidence, Mapping)
            else None
        )
        return matches and (
            payload.get("eie_digest") == state.get("eie_hash")
            and payload.get("collective_signal_digest")
            == state.get("collective_signals", {}).get("digest")
            and payload.get("tier")
            == state.get("safety_profile", {}).get("computed_tier")
            and payload.get("corroboration_required")
            == state.get("corroboration_required")
            and payload.get("pt_evidence_digest") == evidence_digest
        )
    if name == "classification":
        classification = state.get("classification", {})
        return (
            state.get("classification_result") == "ALLOW"
            and payload.get("ap_acf_class") == classification.get("ap_acf_class")
            and payload.get("autonomy_level") == classification.get("autonomy_level")
            and payload.get("autonomy_ceiling") == classification.get("autonomy_ceiling")
            and payload.get("pipeline_mode") == state.get("pipeline_mode")
        )
    if name == "licensing":
        return payload.get("licensing_result") == state.get("licensing_result")
    if name == "governance":
        return (
            payload.get("governance_result") == state.get("governance_result")
            and payload.get("authority_first_result") == state.get("authority_first_result")
            and payload.get("procedural_truth_result") == state.get("procedural_truth_result")
            and payload.get("classification_result") == state.get("classification_result")
            and payload.get("licensing_result") == state.get("licensing_result")
        )
    if name == "grc":
        return (
            payload.get("grc_result") == state.get("grc_result")
            and payload.get("governance_result") == state.get("governance_result")
            and payload.get("reentry_digest") == generate_digest(state.get("governed_reentry", {}))
        )
    if name == "domain":
        return payload.get("domain_result") == state.get("domain_result")
    if name == "aurion":
        return (
            payload.get("aurion15_result") == state.get("aurion15_result")
            and payload.get("candidate_id") == state.get("current_candidate", {}).get("candidate_id")
        )
    return False


def validate_canonical_upstream(
    state: Mapping[str, Any], *, required_tokens: tuple[str, ...]
) -> tuple[bool, list[str]]:
    _, failures = verify_request_identity_binding(state)
    _, stage_failures = verify_canonical_stage_lineage(state, required_tokens=required_tokens)
    failures.extend(stage_failures)
    control_chain_valid, control_chain_failures = validate_control_chain_bindings(state)
    if not control_chain_valid:
        failures.extend(control_chain_failures)
    root_pt_valid, root_pt_failures = validate_root_pt_eligibility(state)
    if not root_pt_valid:
        failures.extend(root_pt_failures)
    if state.get("state_version") != STATE_VERSION:
        failures.append("protocol_downgrade_rejected:state_version")
    tokens = state.get("tokens", {})
    if not isinstance(tokens, Mapping):
        return False, sorted(set(failures + ["confused_deputy_rejected:tokens_missing"]))
    for name in required_tokens:
        token = tokens.get(name)
        if not isinstance(token, Mapping):
            failures.append(f"confused_deputy_rejected:missing_token:{name}")
            continue
        if token.get("name") != name or token.get("issued_at_stage") != TOKEN_STAGE.get(name):
            failures.append(f"signed_field_substitution_detected:{name}")
            continue
        if not verify_token(token, expected_request_fingerprint=state.get("request_fingerprint")):
            failures.append(f"signature_payload_mismatch:{name}")
            continue
        payload = token.get("payload", {})
        if not isinstance(payload, Mapping) or not _semantic_token_matches(state, name, payload):
            failures.append(f"validation_state_mismatch:{name}")
            continue
        matching_trace = [
            entry
            for entry in state.get("token_trace", [])
            if isinstance(entry, Mapping)
            and entry.get("event") == "ISSUED"
            and entry.get("name") == name
            and entry.get("stage") == token.get("issued_at_stage")
            and entry.get("issued_at") == token.get("issued_at")
            and entry.get("digest") == token.get("digest")
        ]
        if len(matching_trace) != 1:
            failures.append(f"token_lineage_mismatch:{name}")
    return not failures, sorted(set(failures))
