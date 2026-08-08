from __future__ import annotations

from typing import Any, Mapping

from sbp_lex.security.pqc import generate_digest, verify_signature
from sbp_lex.security.threshold_tokens import (
    required_threshold_token_names,
    verify_threshold_bundle,
)
from sbp_lex.security.token_stack import verify_token
from sbp_lex.config.security_config import STATE_VERSION
from sbp_lex.shared.control_chain_validation import validate_control_chain_bindings
from sbp_lex.security.governed_stage_evidence import (
    EVIDENCE_FIELD,
    live_state_hash_valid,
    validate_constraint_continuity,
    validate_governance_history,
    validate_stage_evidence,
    validate_stage_token_semantics,
)
from sbp_lex.security.domain_aurion_evidence import (
    CONTROLLED_REENTRY_USE_SCHEMA_VERSION,
    EVIDENCE_FIELD as DOMAIN_AURION_EVIDENCE_FIELD,
    PRE_EXECUTION_PERMISSION_FIELDS,
    controlled_denial_proof_details,
    normalized_governed_reentry,
    validate_handoff_evidence,
    validate_stage_evidence as validate_domain_aurion_stage_evidence,
    validate_stage_history as validate_domain_aurion_stage_history,
    validate_stage_token_semantics as validate_domain_aurion_token_semantics,
)

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


def _nested_permission_field_paths(
    value: object, *, path: tuple[str, ...] = ()
) -> list[str]:
    prohibited = set(PRE_EXECUTION_PERMISSION_FIELDS)
    paths: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            child_path = (*path, key_text)
            if path and key in prohibited:
                paths.append(".".join(child_path))
            paths.extend(
                _nested_permission_field_paths(item, path=child_path)
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(
                _nested_permission_field_paths(
                    item, path=(*path, f"[{index}]")
                )
            )
    return paths


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
        return (
            state.get("classification_result") == "ALLOW"
            and validate_stage_token_semantics(state, name, payload)
        )
    if name == "licensing":
        return (
            state.get("licensing_result") == "ALLOW"
            and validate_stage_token_semantics(state, name, payload)
        )
    if name == "governance":
        return (
            state.get("governance_result") == "ALLOW"
            and validate_stage_token_semantics(state, name, payload)
        )
    if name == "grc":
        return validate_stage_token_semantics(state, name, payload)
    if name == "domain":
        return (
            state.get("domain_result") == "pass"
            and validate_domain_aurion_token_semantics(
                state, name, payload
            )
        )
    if name == "aurion":
        return (
            state.get("aurion15_result") == "pass"
            and validate_domain_aurion_token_semantics(
                state, name, payload
            )
        )
    return False


def _verified_execution_boundary_present(
    state: Mapping[str, Any], tokens: Mapping[str, Any]
) -> bool:
    token = tokens.get("execution_boundary")
    if (
        not isinstance(token, Mapping)
        or token.get("name") != "execution_boundary"
        or token.get("issued_at_stage") != "execution_gate"
        or not verify_token(
            token,
            expected_request_fingerprint=state.get("request_fingerprint"),
        )
    ):
        return False
    order = state.get("integration_stage_order", [])
    if not isinstance(order, list) or order.count("execution_gate") != 1:
        return False
    matching_trace = [
        entry
        for entry in state.get("token_trace", [])
        if isinstance(entry, Mapping)
        and entry.get("event") == "ISSUED"
        and entry.get("name") == "execution_boundary"
        and entry.get("stage") == "execution_gate"
        and entry.get("issued_at") == token.get("issued_at")
        and entry.get("digest") == token.get("digest")
    ]
    return len(matching_trace) == 1


def _validate_canonical_upstream_unchecked(
    state: Mapping[str, Any], *, required_tokens: tuple[str, ...]
) -> tuple[bool, list[str]]:
    _, failures = verify_request_identity_binding(state)
    if not isinstance(state.get("audit_trace"), list):
        failures.append("canonical_upstream_audit_trace_invalid")
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
        evidence_field = (
            EVIDENCE_FIELD.get(name)
            or DOMAIN_AURION_EVIDENCE_FIELD.get(name)
        )
        if evidence_field:
            evidence = state.get(evidence_field, {})
            evidence_payload = (
                evidence.get("payload", {})
                if isinstance(evidence, Mapping)
                else {}
            )
            if (
                token.get("state_hash")
                != evidence_payload.get("state_hash_before_token")
                or token.get("tier")
                != state.get("safety_profile", {}).get("computed_tier")
                or token.get("corroboration_required")
                != state.get("corroboration_required")
            ):
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
    for stage in ("domain", "aurion"):
        if stage not in required_tokens:
            continue
        evidence_valid, evidence_failures = (
            validate_domain_aurion_stage_evidence(state, stage)
        )
        if not evidence_valid:
            failures.extend(evidence_failures)
        history_valid, history_failures = (
            validate_domain_aurion_stage_history(state, stage)
        )
        if not history_valid:
            failures.extend(history_failures)
    if "aurion" in required_tokens:
        handoff_valid, handoff_failures = validate_handoff_evidence(state)
        if not handoff_valid:
            failures.extend(handoff_failures)
        if not _verified_execution_boundary_present(state, tokens):
            failures.extend(
                _pre_execution_authority_failures(
                    state,
                    boundary="canonical_aurion_handoff",
                    expected_stage_order=CANONICAL_STAGE_SEQUENCE[:-1],
                    allowed_stage_tokens=(
                        "authority",
                        "procedural_truth",
                        "classification",
                        "licensing",
                        "governance",
                        "grc",
                        "domain",
                        "aurion",
                    ),
                    expected_chain_stage="aurion_runtime",
                    stage_evidence_field="aurion_evidence",
                )
            )
    return not failures, sorted(set(failures))


def validate_canonical_upstream(
    state: Mapping[str, Any], *, required_tokens: tuple[str, ...]
) -> tuple[bool, list[str]]:
    """Validate arbitrary public-boundary state without propagating errors."""
    try:
        return _validate_canonical_upstream_unchecked(
            state, required_tokens=required_tokens
        )
    except Exception:
        return False, ["canonical_upstream_structure_invalid"]


def validate_governed_stage_token(
    state: Mapping[str, Any], name: str
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    token = tokens.get(name)
    if not isinstance(token, Mapping):
        return False, [f"confused_deputy_rejected:missing_token:{name}"]
    if token.get("name") != name or token.get("issued_at_stage") != TOKEN_STAGE.get(name):
        failures.append(f"signed_field_substitution_detected:{name}")
    elif not verify_token(
        token, expected_request_fingerprint=state.get("request_fingerprint")
    ):
        failures.append(f"signature_payload_mismatch:{name}")
    else:
        payload = token.get("payload", {})
        if not isinstance(payload, Mapping) or not _semantic_token_matches(
            state, name, payload
        ):
            failures.append(f"validation_state_mismatch:{name}")
        evidence = state.get(EVIDENCE_FIELD.get(name, ""), {})
        evidence_payload = (
            evidence.get("payload", {})
            if isinstance(evidence, Mapping)
            else {}
        )
        if (
            token.get("state_hash")
            != evidence_payload.get("state_hash_before_token")
            or token.get("tier")
            != state.get("safety_profile", {}).get("computed_tier")
            or token.get("corroboration_required")
            != state.get("corroboration_required")
        ):
            failures.append(f"validation_state_mismatch:{name}")
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


def validate_governance_handoff_to_grc(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Validate the completed Governance outcome before GRC consumes it.

    The outer runner records the Governance/GRC integration markers only after
    the combined Governance pipeline returns, so this boundary uses signed
    Governance evidence/hash lineage rather than inventing an early marker.
    """
    failures: list[str] = []
    upstream_valid, upstream_failures = validate_canonical_upstream(
        state,
        required_tokens=(
            "authority",
            "procedural_truth",
            "classification",
            "licensing",
        ),
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    if not live_state_hash_valid(state):
        failures.append("grc_entry_state_hash_invalid")
    evidence_valid, evidence_failures = validate_stage_evidence(
        state, "governance"
    )
    if not evidence_valid:
        failures.extend(evidence_failures)
    history_valid, history_failures = validate_governance_history(state)
    if not history_valid:
        failures.extend(history_failures)
    constraints_valid, constraint_failures = validate_constraint_continuity(
        state, through_stage="governance"
    )
    if not constraints_valid:
        failures.extend(constraint_failures)
    governance_result = state.get("governance_result")
    if governance_result not in {"ALLOW", "DENY", "ESCALATE"}:
        failures.append("governance_result_invalid")
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    if governance_result == "ALLOW":
        token_valid, token_failures = validate_governed_stage_token(
            state, "governance"
        )
        if not token_valid:
            failures.extend(token_failures)
    elif isinstance(tokens.get("governance"), Mapping):
        failures.append("stale_governance_allow_token_present")
    return not failures, sorted(set(failures))


def _pre_execution_authority_failures(
    state: Mapping[str, Any],
    *,
    boundary: str,
    expected_stage_order: tuple[str, ...],
    allowed_stage_tokens: tuple[str, ...],
    expected_chain_stage: str,
    stage_evidence_field: str,
) -> list[str]:
    """Require a clean, non-authorizing state before Execution Convergence."""
    failures: list[str] = []
    if state.get("decision") != "UNSET":
        failures.append(f"{boundary}_pre_execution_decision_invalid")
    if state.get("execution_result") != "UNSET":
        failures.append(f"{boundary}_pre_execution_result_invalid")
    if state.get("operational_state") != "UNSET":
        failures.append(f"{boundary}_pre_execution_operational_state_invalid")
    neutral_fields = {
        "execution_reason": "",
        "token_stack_valid": False,
        "token_verification_failures": [],
        "persistent_inoperability": False,
        "controlled_return_required": False,
        "last_denied_fingerprint": None,
    }
    for field, expected in neutral_fields.items():
        if state.get(field) != expected:
            failures.append(f"{boundary}_pre_execution_field_invalid:{field}")

    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    expected_token_names = set(required_threshold_token_names()) | {
        "threshold_bundle",
        *allowed_stage_tokens,
    }
    actual_token_names = set(tokens)
    for name in sorted(actual_token_names - expected_token_names, key=str):
        failures.append(f"{boundary}_pre_execution_token_unexpected:{name}")
    for name in sorted(expected_token_names - actual_token_names):
        failures.append(f"{boundary}_pre_execution_token_missing:{name}")

    issued_trace = [
        entry
        for entry in state.get("token_trace", [])
        if isinstance(entry, Mapping) and entry.get("event") == "ISSUED"
    ]
    for name in expected_token_names:
        token = tokens.get(name)
        matches = [
            entry
            for entry in issued_trace
            if entry.get("name") == name
            and isinstance(token, Mapping)
            and entry.get("stage") == token.get("issued_at_stage")
            and entry.get("issued_at") == token.get("issued_at")
            and entry.get("digest") == token.get("digest")
        ]
        if len(matches) != 1:
            failures.append(
                f"{boundary}_pre_execution_token_trace_invalid:{name}"
            )
    if any(entry.get("name") not in expected_token_names for entry in issued_trace):
        failures.append(f"{boundary}_pre_execution_token_trace_unexpected")

    order = state.get("integration_stage_order", [])
    if order != list(expected_stage_order):
        failures.append(f"{boundary}_pre_execution_stage_order_invalid")
    chain = state.get("hash_chain", [])
    evidence = state.get(stage_evidence_field, {})
    evidence_payload = (
        evidence.get("payload", {}) if isinstance(evidence, Mapping) else {}
    )
    if (
        not isinstance(chain, list)
        or not chain
        or not isinstance(chain[-1], Mapping)
        or chain[-1].get("stage") != expected_chain_stage
        or evidence_payload.get("logical_index") != len(chain)
        or evidence_payload.get("chain_hash_entering_finalisation")
        != chain[-1].get("previous_hash")
    ):
        failures.append(f"{boundary}_pre_execution_chain_tail_invalid")

    for field in (
        "execution_verified",
        "execution_timestamp",
        "execution_attestation",
        "execution_convergence",
        "convergence_hash",
        "audit_record",
        "audit_hash",
        "audit_finalisation",
        "controlled_outcome",
        "final_outcome",
        "pipeline_convergence",
        "pipeline_b_summary",
        "pipeline_domain_aurion_parity",
        "execution_permission",
        "allow_execution",
        "runtime_authority",
        "final_admissibility",
        "external_allow",
        "external_deny",
        "external_escalate",
        "_".join(("external", "governance_result")),
    ):
        if field in state:
            failures.append(f"{boundary}_pre_execution_field_present:{field}")
    for path in sorted(set(_nested_permission_field_paths(state))):
        failures.append(
            f"{boundary}_pre_execution_nested_permission_field:{path}"
        )
    raw_reentry = state.get("governed_reentry")
    if not isinstance(raw_reentry, Mapping):
        failures.append(f"{boundary}_pre_execution_reentry_invalid")
    elif "reentry_completed" in raw_reentry:
        failures.append(f"{boundary}_pre_execution_reentry_completed")
    return failures


def _validate_governed_domain_handoff_unchecked(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Fail-closed Pass 5 admission check; Domain reasoning stays untouched."""
    failures: list[str] = []
    upstream_valid, upstream_failures = validate_canonical_upstream(
        state,
        required_tokens=(
            "authority",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
        ),
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    if not live_state_hash_valid(state):
        failures.append("domain_handoff_state_hash_invalid")
    for stage in ("classification", "licensing", "governance", "grc"):
        evidence_valid, evidence_failures = validate_stage_evidence(state, stage)
        if not evidence_valid:
            failures.extend(evidence_failures)
    history_valid, history_failures = validate_governance_history(state)
    if not history_valid:
        failures.extend(history_failures)
    constraints_valid, constraint_failures = validate_constraint_continuity(
        state, through_stage="grc"
    )
    if not constraints_valid:
        failures.extend(constraint_failures)
    if state.get("classification_result") != "ALLOW":
        failures.append("domain_handoff_classification_not_allowed")
    if state.get("licensing_result") != "ALLOW":
        failures.append("domain_handoff_licensing_not_allowed")
    if state.get("governance_result") != "ALLOW":
        failures.append("domain_handoff_governance_not_allowed")
    if state.get("grc_result") != "PASS":
        failures.append("domain_handoff_grc_not_pass")
    reentry_valid, reentry_failures = _validate_controlled_reentry(state)
    if not reentry_valid:
        failures.extend(reentry_failures)
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    if not _verified_execution_boundary_present(state, tokens):
        failures.extend(
            _pre_execution_authority_failures(
                state,
                boundary="domain_handoff",
                expected_stage_order=CANONICAL_STAGE_SEQUENCE[:10],
                allowed_stage_tokens=(
                    "authority",
                    "procedural_truth",
                    "classification",
                    "licensing",
                    "governance",
                    "grc",
                ),
                expected_chain_stage="grc",
                stage_evidence_field="grc_evidence",
            )
        )
    return not failures, sorted(set(failures))


def validate_governed_domain_handoff(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    """Fail closed for malformed governed-to-Domain public input."""
    try:
        return _validate_governed_domain_handoff_unchecked(state)
    except Exception:
        return False, ["domain_handoff_structure_invalid"]


def _validate_controlled_reentry(
    state: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    reentry = normalized_governed_reentry(state)
    context = state.get("context", {})
    context = context if isinstance(context, Mapping) else {}
    direct_target = context.get("reentry_target") or context.get("retry_stage")
    if direct_target not in (None, "", "full_traversal"):
        failures.append("controlled_reentry_direct_stage_jump_rejected")
    if any(
        context.get(field) is True
        for field in (
            "domain_direct_reentry",
            "aurion_direct_reentry",
            "execution_direct_reentry",
        )
    ):
        failures.append("controlled_reentry_direct_stage_jump_rejected")
    if reentry.get("retry_eligible") is True and reentry.get(
        "reentry_permitted"
    ) is not True:
        failures.append("controlled_reentry_eligibility_invalid")
    if reentry.get("reentry_permitted") is True:
        prior = reentry.get("prior_denied_fingerprint")
        current = reentry.get("current_request_fingerprint")
        if (
            not isinstance(prior, str)
            or not prior
            or not isinstance(current, str)
            or current != state.get("request_fingerprint")
            or current == prior
        ):
            failures.append("controlled_reentry_identity_invalid")
        reason = reentry.get("material_change_reason")
        if not isinstance(reason, str) or not reason.strip():
            failures.append("controlled_reentry_material_change_missing")
        if context.get("material_change_declared") is not True:
            failures.append("controlled_reentry_declaration_missing")
        proof_details = controlled_denial_proof_details(state)
        if proof_details.get("present_count") == 0:
            failures.append("controlled_reentry_prior_denial_proof_missing")
        elif proof_details.get("present_count") != 1 or proof_details.get(
            "valid"
        ) is not True:
            failures.append("controlled_reentry_prior_denial_proof_invalid")

        proof_use = state.get("controlled_reentry_proof_use")
        expected_use_fields = {
            "schema_version",
            "status",
            "proof_digest",
            "prior_denied_fingerprint",
            "current_request_fingerprint",
            "registry_scope",
            "single_use",
            "registry_capacity",
        }
        if not isinstance(proof_use, Mapping):
            failures.append("controlled_reentry_proof_use_missing")
        elif (
            set(proof_use) != expected_use_fields
            or proof_use.get("schema_version")
            != CONTROLLED_REENTRY_USE_SCHEMA_VERSION
            or proof_use.get("proof_digest")
            != proof_details.get("proof_digest")
            or proof_use.get("prior_denied_fingerprint") != prior
            or proof_use.get("current_request_fingerprint") != current
            or proof_use.get("registry_scope") != "DESKTOP_V1_PROCESS"
            or proof_use.get("single_use") is not True
            or not isinstance(proof_use.get("registry_capacity"), int)
            or isinstance(proof_use.get("registry_capacity"), bool)
            or proof_use.get("registry_capacity", 0) < 1
        ):
            failures.append("controlled_reentry_proof_use_invalid")
        elif proof_use.get("status") == "REPLAYED":
            failures.append("controlled_reentry_prior_denial_proof_replayed")
        elif proof_use.get("status") == "CAPACITY_EXHAUSTED":
            failures.append("controlled_reentry_replay_registry_exhausted")
        elif proof_use.get("status") != "ACCEPTED":
            failures.append("controlled_reentry_proof_use_invalid")
    return not failures, sorted(set(failures))


def _validate_domain_handoff_to_aurion_unchecked(
    state: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    """Validate the exact completed Domain state consumed by Aurion."""
    failures: list[str] = []
    upstream_valid, upstream_failures = validate_canonical_upstream(
        state,
        required_tokens=(
            "authority",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
            "domain",
        ),
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    if not live_state_hash_valid(state):
        failures.append("aurion_entry_state_hash_invalid")
    constraints_valid, constraint_failures = validate_constraint_continuity(
        state, through_stage="grc"
    )
    if not constraints_valid:
        failures.extend(constraint_failures)
    required_results = {
        "procedural_truth_result": "PASS",
        "procedural_truth_outcome": "PT_PASS",
        "classification_result": "ALLOW",
        "licensing_result": "ALLOW",
        "governance_result": "ALLOW",
        "grc_result": "PASS",
        "domain_result": "pass",
    }
    for field, expected in required_results.items():
        if state.get(field) != expected:
            failures.append(f"aurion_entry_invalid:{field}")
    domain_candidate = state.get("domain_candidate")
    if not isinstance(domain_candidate, Mapping) or not domain_candidate:
        failures.append("aurion_entry_domain_candidate_missing")
    order = state.get("integration_stage_order", [])
    if not isinstance(order, list) or order.count("domain_wrap") != 1:
        failures.append("aurion_entry_domain_stage_missing")
    if isinstance(order, list) and "aurion_runtime" in order:
        failures.append("aurion_entry_stage_already_present")
    reentry_valid, reentry_failures = _validate_controlled_reentry(state)
    if not reentry_valid:
        failures.extend(reentry_failures)
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    if not _verified_execution_boundary_present(state, tokens):
        failures.extend(
            _pre_execution_authority_failures(
                state,
                boundary="aurion_entry",
                expected_stage_order=CANONICAL_STAGE_SEQUENCE[:11],
                allowed_stage_tokens=(
                    "authority",
                    "procedural_truth",
                    "classification",
                    "licensing",
                    "governance",
                    "grc",
                    "domain",
                ),
                expected_chain_stage="domain_wrap",
                stage_evidence_field="domain_evidence",
            )
        )
    return not failures, sorted(set(failures))


def validate_domain_handoff_to_aurion(
    state: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    """Fail closed for malformed Domain-to-Aurion public input."""
    try:
        return _validate_domain_handoff_to_aurion_unchecked(state)
    except Exception:
        return False, ["aurion_handoff_structure_invalid"]


def _validate_execution_convergence_handoff_unchecked(
    state: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    """Validate Pass 6 output without changing Execution Convergence/Gate."""
    failures: list[str] = []
    upstream_valid, upstream_failures = validate_canonical_upstream(
        state,
        required_tokens=(
            "authority",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
            "domain",
            "aurion",
        ),
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    if not live_state_hash_valid(state):
        failures.append("execution_convergence_handoff_state_hash_invalid")
    constraints_valid, constraint_failures = validate_constraint_continuity(
        state, through_stage="grc"
    )
    if not constraints_valid:
        failures.extend(constraint_failures)
    for field, expected in (
        ("procedural_truth_result", "PASS"),
        ("procedural_truth_outcome", "PT_PASS"),
        ("classification_result", "ALLOW"),
        ("licensing_result", "ALLOW"),
        ("governance_result", "ALLOW"),
        ("grc_result", "PASS"),
        ("domain_result", "pass"),
        ("aurion15_result", "pass"),
    ):
        if state.get(field) != expected:
            failures.append(f"execution_convergence_handoff_invalid:{field}")
    order = state.get("integration_stage_order", [])
    if (
        not isinstance(order, list)
        or order.count("domain_wrap") != 1
        or order.count("aurion_runtime") != 1
        or order.index("domain_wrap") >= order.index("aurion_runtime")
    ):
        failures.append("execution_convergence_handoff_stage_order_invalid")
    reentry_valid, reentry_failures = _validate_controlled_reentry(state)
    if not reentry_valid:
        failures.extend(reentry_failures)
    tokens = state.get("tokens", {})
    tokens = tokens if isinstance(tokens, Mapping) else {}
    if not _verified_execution_boundary_present(state, tokens):
        failures.extend(
            _pre_execution_authority_failures(
                state,
                boundary="execution_convergence_handoff",
                expected_stage_order=CANONICAL_STAGE_SEQUENCE[:-1],
                allowed_stage_tokens=(
                    "authority",
                    "procedural_truth",
                    "classification",
                    "licensing",
                    "governance",
                    "grc",
                    "domain",
                    "aurion",
                ),
                expected_chain_stage="aurion_runtime",
                stage_evidence_field="aurion_evidence",
            )
        )
    return not failures, sorted(set(failures))


def validate_execution_convergence_handoff(
    state: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    """Fail closed for malformed Pass 6 execution-convergence handoff."""
    try:
        return _validate_execution_convergence_handoff_unchecked(state)
    except Exception:
        return False, ["execution_convergence_handoff_structure_invalid"]
