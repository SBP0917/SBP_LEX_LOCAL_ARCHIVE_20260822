from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.config.thresholds import validate_threshold_conditioning_state
from sbp_lex.security.pqc import (
    generate_digest,
    sign_payload,
    verify_signature,
)
from sbp_lex.security.threshold_tokens import (
    issue_threshold_bundle_token,
    issue_threshold_component_tokens,
    required_threshold_token_names,
    verify_threshold_bundle,
)
from sbp_lex.security.token_stack import issue_token, verify_token
from sbp_lex.shared.control_chain_validation import (
    validate_root_of_trust_evidence,
)
from sbp_lex.shared.hash_chain import (
    append_hash_entry,
    current_chain_hash,
    rebuild_state_hash,
    verify_hash_chain,
)


PT_EVIDENCE_SCHEMA_VERSION = "desktop-v1.procedural-truth-evidence.v1"
PT_EVIDENCE_TIMESTAMP_AUTHORITY = "PT_HASH_CHAIN_INDEX"


def _status_is_valid(value: object, *, ready_value: str = "VALID") -> bool:
    return str(value or "").upper() == ready_value


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _root_evidence_digest(state: Mapping[str, Any]) -> str | None:
    root = _mapping(
        state.get("root_of_trust_evidence")
        or state.get("root_of_trust_evidence_anchor")
    )
    return root.get("root_evidence_digest") or root.get("anchor_digest")


def _pt_nonce_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "request_fingerprint": payload.get("request_fingerprint"),
        "eie_digest": payload.get("eie_digest"),
        "collective_signal_digest": payload.get("collective_signal_digest"),
        "root_evidence_digest": payload.get("root_evidence_digest"),
        "state_hash": payload.get("state_hash"),
        "source_assessment_digest": payload.get("source_assessment_digest"),
        "evidentiary_sufficiency_digest": payload.get(
            "evidentiary_sufficiency_digest"
        ),
        "human_safety": payload.get("human_safety"),
        "irreversibility": payload.get("irreversibility"),
        "cascading_impact": payload.get("cascading_impact"),
        "financial_operational": payload.get("financial_operational"),
        "computed_tier": payload.get("computed_tier"),
        "corroboration_required": payload.get("corroboration_required"),
        "corroboration_observed": payload.get("corroboration_observed"),
        "threshold_state_digest": payload.get("threshold_state_digest"),
        "threshold_bundle_digest": payload.get("threshold_bundle_digest"),
        "threshold_token_digests": payload.get("threshold_token_digests"),
        "prior_hash_chain_head": payload.get("prior_hash_chain_head"),
        "timestamp": payload.get("timestamp"),
        "timestamp_authority": payload.get("timestamp_authority"),
    }


def _purge_threshold_tokens(state: Dict[str, Any]) -> None:
    tokens = state.setdefault("tokens", {})
    tokens.pop("threshold_bundle", None)
    for token_name in required_threshold_token_names():
        tokens.pop(token_name, None)


def _validate_pt_finalization_hash_binding(
    state: Mapping[str, Any],
    payload: Mapping[str, Any],
    pt_evidence_digest: Any,
) -> list[str]:
    if not verify_hash_chain(state):
        return ["procedural_truth_hash_chain_invalid"]

    issuing_stage = payload.get("issuing_stage")
    if issuing_stage == "procedural_truth_entry_preflight":
        feedback = _mapping(
            _mapping(state.get("governance_feedback")).get(
                "procedural_truth_entry_preflight"
            )
        )
        finalization_payload = {
            "substage": "procedural_truth_entry_preflight",
            "result": "FAIL",
            "failures": feedback.get("failures", []),
            "pt_evidence_digest": pt_evidence_digest,
            "request_fingerprint": payload.get("request_fingerprint"),
            "eie_digest": payload.get("eie_digest"),
            "state_hash": payload.get("state_hash"),
        }
    elif issuing_stage == "procedural_truth":
        matching_audit = next(
            (
                item
                for item in state.get("audit_trace", [])
                if isinstance(item, Mapping)
                and item.get("stage") == "procedural_truth_finalization"
                and item.get("pt_evidence_digest") == pt_evidence_digest
            ),
            {},
        )
        finalization_payload = {
            "substage": "procedural_truth_finalization",
            "result": payload.get("procedural_truth_result"),
            "failures": matching_audit.get("failures", []),
            "pt_outcome": payload.get("procedural_truth_outcome"),
            "deterministic_failure_reasons": payload.get("reason_codes", []),
            "failure_outcome": matching_audit.get("failure_outcome"),
            "pt_evidence_digest": pt_evidence_digest,
            "evidentiary_sufficiency_result": payload.get(
                "evidentiary_sufficiency_result"
            ),
            "qualifying_source_count": payload.get(
                "source_count_qualifying"
            ),
            "corroboration_required": payload.get("corroboration_required"),
            "computed_tier": payload.get("computed_tier"),
            "request_fingerprint": payload.get("request_fingerprint"),
            "eie_digest": payload.get("eie_digest"),
            "state_hash": payload.get("state_hash"),
        }
    else:
        return ["procedural_truth_evidence_issuing_stage_invalid"]

    expected_payload_hash = generate_digest(finalization_payload)
    prior_head = payload.get("prior_hash_chain_head")
    matching_entries = [
        entry
        for entry in state.get("hash_chain", [])
        if isinstance(entry, Mapping)
        and entry.get("stage") == "procedural_truth"
        and entry.get("previous_hash") == prior_head
        and entry.get("payload_hash") == expected_payload_hash
        and entry.get("request_fingerprint")
        == payload.get("request_fingerprint")
    ]
    return (
        []
        if len(matching_entries) == 1
        else ["procedural_truth_finalization_hash_binding_invalid"]
    )


def validate_procedural_truth_entry(
    state: Mapping[str, Any], *, require_pass: bool = True,
    require_current_state_hash: bool = False,
) -> tuple[bool, list[str]]:
    """Delegate PT entry to the authoritative Root validator."""

    root_valid, root_failures = validate_root_of_trust_evidence(
        state, require_pass=require_pass
    )
    failures = list(root_failures)
    if (
        require_pass
        and require_current_state_hash
        and state.get("state_hash") != rebuild_state_hash(state)
    ):
        failures.append("pt_entry_state_hash_mismatch")
    if require_pass and state.get("authority_first_result") != "PASS":
        failures.append("authority_first_result_not_pass")
    return root_valid and not failures, sorted(set(failures))


def validate_procedural_truth_evidence(
    state: Mapping[str, Any], *, require_pass: bool = True
) -> tuple[bool, list[str]]:
    """Verify the signed PT result and its Root/evidence/tier bindings."""

    failures: list[str] = []
    wrapper = state.get("procedural_truth_evidence")
    if not isinstance(wrapper, Mapping):
        return False, ["procedural_truth_evidence_missing"]
    payload = wrapper.get("payload")
    if not isinstance(payload, Mapping):
        return False, ["procedural_truth_evidence_payload_missing"]
    if payload.get("schema_version") != PT_EVIDENCE_SCHEMA_VERSION:
        failures.append("procedural_truth_evidence_schema_invalid")
    digest = generate_digest(dict(payload))
    if wrapper.get("pt_evidence_digest") != digest:
        failures.append("procedural_truth_evidence_digest_mismatch")
    if not verify_signature(payload, wrapper.get("signature", {})):
        failures.append("procedural_truth_evidence_signature_invalid")
    if wrapper.get("verified") is not True:
        failures.append("procedural_truth_evidence_verified_flag_invalid")

    root_valid, root_failures = validate_procedural_truth_entry(
        state, require_pass=require_pass
    )
    if not root_valid:
        failures.extend(f"pt_root_preflight:{reason}" for reason in root_failures)

    envelope = _mapping(state.get("pt_evidence_envelope"))
    assessment = _mapping(envelope.get("source_assessment"))
    threshold_state = _mapping(state.get("threshold_conditioning_state"))
    threshold_payload = _mapping(threshold_state.get("payload"))
    tokens = _mapping(state.get("tokens"))
    threshold_bundle = _mapping(tokens.get("threshold_bundle"))
    threshold_bundle_payload = _mapping(threshold_bundle.get("payload"))
    required_checks = [
        "evidence_validation",
        "corroboration",
        "threshold_conditioning",
        "procedural_consistency",
    ]
    expected = {
        "issuing_stage": (
            "procedural_truth" if require_pass else payload.get("issuing_stage")
        ),
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            state.get("collective_signal_evidence")
        ).get("signal_digest"),
        "root_evidence_digest": _root_evidence_digest(state),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "procedural_truth_outcome": state.get("procedural_truth_outcome"),
        "computed_tier": _mapping(state.get("safety_profile")).get(
            "computed_tier"
        ),
        "corroboration_required": state.get("corroboration_required"),
        "corroboration_observed": assessment.get(
            "source_count_qualifying"
        ),
        "source_count_total": assessment.get("source_count_total"),
        "source_count_qualifying": assessment.get(
            "source_count_qualifying"
        ),
        "evidentiary_sufficiency_result": assessment.get(
            "evidentiary_sufficiency_result"
        ),
        "evidentiary_sufficiency_digest": assessment.get(
            "evidentiary_sufficiency_digest"
        ),
        "source_assessment_digest": assessment.get(
            "source_assessment_digest"
        ),
        "human_safety": threshold_payload.get("human_safety"),
        "irreversibility": threshold_payload.get("irreversibility"),
        "cascading_impact": threshold_payload.get("cascading_impact"),
        "financial_operational": threshold_payload.get(
            "financial_operational"
        ),
        "threshold_state_digest": threshold_state.get(
            "threshold_state_digest"
        ),
        "threshold_bundle_digest": threshold_bundle.get("digest"),
        "threshold_token_digests": threshold_bundle_payload.get(
            "component_hashes", {}
        ),
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            failures.append(f"procedural_truth_evidence_mismatch:{field}")
    threshold_valid, threshold_failures = validate_threshold_conditioning_state(
        state,
        require_complete=require_pass,
        require_observation=require_pass,
    )
    if not threshold_valid:
        failures.extend(
            f"procedural_truth_threshold_state:{reason}"
            for reason in threshold_failures
        )
    if not isinstance(payload.get("timestamp"), int) or isinstance(
        payload.get("timestamp"), bool
    ) or payload.get("timestamp", 0) < 1:
        failures.append("procedural_truth_evidence_timestamp_invalid")
    if payload.get("timestamp_authority") != PT_EVIDENCE_TIMESTAMP_AUTHORITY:
        failures.append("procedural_truth_evidence_timestamp_authority_invalid")
    expected_nonce = generate_digest(_pt_nonce_payload(payload))[:32]
    if payload.get("nonce") != expected_nonce:
        failures.append("procedural_truth_evidence_nonce_invalid")
    failures.extend(
        _validate_pt_finalization_hash_binding(
            state,
            payload,
            wrapper.get("pt_evidence_digest"),
        )
    )

    certification = _mapping(state.get("procedural_truth_certification"))
    if certification.get("pt_evidence_digest") != wrapper.get(
        "pt_evidence_digest"
    ):
        failures.append("procedural_truth_certification_evidence_mismatch")

    if require_pass:
        if payload.get("procedural_truth_result") != "PASS":
            failures.append("procedural_truth_evidence_not_pass")
        if payload.get("procedural_truth_outcome") != "PT_PASS":
            failures.append("procedural_truth_evidence_outcome_not_pass")
        if payload.get("evidentiary_sufficiency_result") != "SUFFICIENT":
            failures.append("procedural_truth_evidence_not_sufficient")
        threshold_bundle_valid, threshold_bundle_failures = (
            verify_threshold_bundle(state)
        )
        if not threshold_bundle_valid:
            failures.extend(
                f"procedural_truth_{reason}"
                for reason in threshold_bundle_failures
            )
        if payload.get("corroboration_observed", 0) < payload.get(
            "corroboration_required", 0
        ):
            failures.append("procedural_truth_evidence_corroboration_not_met")
        token = _mapping(_mapping(state.get("tokens")).get("procedural_truth"))
        if not token:
            failures.append("procedural_truth_token_missing")
        elif not verify_token(
            token,
            expected_request_fingerprint=state.get("request_fingerprint"),
        ):
            failures.append("procedural_truth_token_invalid")
        else:
            token_payload = _mapping(token.get("payload"))
            if token.get("name") != "procedural_truth":
                failures.append("procedural_truth_token_name_mismatch")
            if token.get("issued_at_stage") != "procedural_truth":
                failures.append("procedural_truth_token_stage_mismatch")
            token_expected = {
                "procedural_truth_result": "PASS",
                "procedural_truth_outcome": "PT_PASS",
                "pt_evidence_envelope_digest": state.get(
                    "pt_evidence_envelope_digest"
                ),
                "eie_digest": payload.get("eie_digest"),
                "collective_signal_digest": payload.get(
                    "collective_signal_digest"
                ),
                "root_evidence_digest": payload.get("root_evidence_digest"),
                "tier": payload.get("computed_tier"),
                "corroboration_required": payload.get(
                    "corroboration_required"
                ),
                "corroboration_observed": payload.get(
                    "corroboration_observed"
                ),
                "pt_evidence_digest": wrapper.get("pt_evidence_digest"),
                "source_assessment_digest": payload.get(
                    "source_assessment_digest"
                ),
                "evidentiary_sufficiency_result": "SUFFICIENT",
                "evidentiary_sufficiency_digest": payload.get(
                    "evidentiary_sufficiency_digest"
                ),
                "human_safety": payload.get("human_safety"),
                "irreversibility": payload.get("irreversibility"),
                "cascading_impact": payload.get("cascading_impact"),
                "financial_operational": payload.get(
                    "financial_operational"
                ),
                "threshold_state_digest": payload.get(
                    "threshold_state_digest"
                ),
                "threshold_bundle_digest": payload.get(
                    "threshold_bundle_digest"
                ),
                "threshold_token_digests": payload.get(
                    "threshold_token_digests"
                ),
                "prior_hash_chain_head": payload.get(
                    "prior_hash_chain_head"
                ),
                "issuing_stage": "procedural_truth",
                "timestamp": payload.get("timestamp"),
                "timestamp_authority": payload.get("timestamp_authority"),
                "nonce": payload.get("nonce"),
                "checks": required_checks,
            }
            for field, expected_value in token_expected.items():
                if token_payload.get(field) != expected_value:
                    failures.append(
                        f"procedural_truth_token_binding_mismatch:{field}"
                    )
            if token.get("tier") != payload.get("computed_tier"):
                failures.append("procedural_truth_token_tier_mismatch")
            if token.get("corroboration_required") != payload.get(
                "corroboration_required"
            ):
                failures.append("procedural_truth_token_threshold_mismatch")
            if token.get("state_hash") != payload.get("state_hash"):
                failures.append("procedural_truth_token_state_hash_mismatch")
            if threshold_bundle.get("state_hash") != payload.get("state_hash"):
                failures.append("threshold_bundle_state_hash_mismatch")
            for token_name in required_threshold_token_names():
                component = _mapping(tokens.get(token_name))
                if component.get("state_hash") != payload.get("state_hash"):
                    failures.append(
                        f"threshold_component_state_hash_mismatch:{token_name}"
                    )
    return not failures, sorted(set(failures))


def _build_certification_result(
    working_state: Mapping[str, Any],
    *,
    checks_passed: bool,
    failures: list[str],
    threshold_failures: list[str],
    root_valid: bool,
    root_failures: list[str],
) -> Dict[str, Any]:
    envelope = _mapping(working_state.get("pt_evidence_envelope"))
    assessment = _mapping(envelope.get("source_assessment"))
    skg_metadata = _mapping(envelope.get("skg_truth_foundation_metadata"))
    dtn_metadata = _mapping(
        envelope.get("dtn_contextual_verification_metadata")
    )
    threshold_state = _mapping(working_state.get("threshold_conditioning_state"))
    threshold_payload = _mapping(threshold_state.get("payload"))

    source_floor_met = working_state.get("corroboration_met") is True
    verification_met = assessment.get("verification_result") == "VALID"
    independence_met = assessment.get("source_independence_result") == "VALID"
    provenance_met = assessment.get("provenance_result") == "VALID"
    integrity_met = assessment.get("integrity_result") == "VALID"
    attestation_met = assessment.get("attestation_result") == "VALID"
    authority_met = assessment.get("authority_result") == "VALID"
    jurisdiction_met = assessment.get("jurisdiction_result") == "VALID"
    freshness_met = assessment.get("freshness_result") == "VALID"
    consistency_met = assessment.get("consistency_result") == "VALID"
    runtime_validity_met = (
        assessment.get("runtime_validity_result") == "VALID"
    )
    relevance_met = assessment.get("relevance_result") == "VALID"
    evidence_complete = assessment.get("evidence_completeness_result") == "PASS"
    evidence_sufficient = (
        assessment.get("evidentiary_sufficiency_result") == "SUFFICIENT"
    )
    material_contradictions = assessment.get("material_contradictions") is True
    unresolved_contradictions = (
        assessment.get("unresolved_contradictions") is True
    )
    skg_valid = skg_metadata.get("skg_verification_status") == "VALID"
    dtn_valid = (
        dtn_metadata.get("dtn_contextualisation_status") == "VALID"
    )
    tier_monotonic = threshold_payload.get("tier_monotonic") is True
    threshold_state_valid, threshold_state_failures = (
        validate_threshold_conditioning_state(
            working_state,
            require_complete=root_valid,
            require_observation=True,
        )
    )
    threshold_valid = (
        threshold_state_valid
        and not threshold_payload.get("validation_failures")
        and tier_monotonic
    )

    consequence_burden_met = all(
        (
            source_floor_met,
            verification_met,
            independence_met,
            provenance_met,
            integrity_met,
            attestation_met,
            authority_met,
            jurisdiction_met,
            freshness_met,
            consistency_met,
            runtime_validity_met,
            relevance_met,
            evidence_complete,
            evidence_sufficient,
            not unresolved_contradictions,
            skg_valid,
            dtn_valid,
            root_valid,
            threshold_valid,
        )
    )
    factor_failures: list[str] = []
    for name, met in (
        ("source_floor_not_met", source_floor_met),
        ("source_verification_not_met", verification_met),
        ("source_independence_not_met", independence_met),
        ("provenance_not_met", provenance_met),
        ("integrity_not_met", integrity_met),
        ("attestation_not_met", attestation_met),
        ("authority_not_met", authority_met),
        ("jurisdiction_not_met", jurisdiction_met),
        ("freshness_not_met", freshness_met),
        ("consistency_not_met", consistency_met),
        ("runtime_validity_not_met", runtime_validity_met),
        ("relevance_not_met", relevance_met),
        ("evidence_completeness_not_met", evidence_complete),
        ("evidentiary_sufficiency_not_met", evidence_sufficient),
        ("skg_verification_not_valid", skg_valid),
        ("dtn_contextualisation_not_valid", dtn_valid),
        ("root_of_trust_anchorage_not_valid", root_valid),
        ("threshold_conditioning_not_valid", threshold_valid),
    ):
        if not met:
            factor_failures.append(name)
    if unresolved_contradictions:
        factor_failures.append("unresolved_material_contradiction")
    factor_failures.extend(f"root_preflight:{reason}" for reason in root_failures)
    factor_failures.extend(
        f"threshold_state:{reason}" for reason in threshold_state_failures
    )

    certified = checks_passed and consequence_burden_met and not factor_failures
    tier = str(
        _mapping(working_state.get("safety_profile")).get(
            "computed_tier", envelope.get("threshold_tier", "LOW")
        )
    ).upper()
    reason_codes = sorted(
        set(
            failures
            + threshold_failures
            + factor_failures
            + list(envelope.get("deterministic_failure_reasons", []))
            + list(assessment.get("sufficiency_reasons", []))
        )
    )
    if certified:
        procedural_truth_status = "PASS"
        required_action = "ALLOW_CONTINUE"
        procedural_truth_reason = "procedural_truth_certified"
    elif unresolved_contradictions or not integrity_met or not root_valid:
        procedural_truth_status = "DENY"
        required_action = "DENY_EXECUTION"
        procedural_truth_reason = "procedural_truth_foundation_invalid"
    elif tier in {"TOP", "EXTREME"} and (
        not source_floor_met
        or not authority_met
        or not jurisdiction_met
        or material_contradictions
    ):
        procedural_truth_status = "ESCALATE"
        required_action = "ESCALATE_AUTHORITY"
        procedural_truth_reason = "procedural_truth_escalation_required"
    else:
        procedural_truth_status = "REFINE"
        required_action = "REFINE_EVIDENCE"
        procedural_truth_reason = "procedural_truth_evidence_refinement_required"

    return {
        "procedural_truth_status": procedural_truth_status,
        "procedural_truth_reason": procedural_truth_reason,
        "certification_status": "CERTIFIED" if certified else "NOT_CERTIFIED",
        "tier": "EXTREME" if tier == "EXTREME" else tier,
        "source_floor_met": source_floor_met,
        "verification_met": verification_met,
        "independence_met": independence_met,
        "provenance_met": provenance_met,
        "integrity_met": integrity_met,
        "attestation_met": attestation_met,
        "authority_met": authority_met,
        "jurisdiction_met": jurisdiction_met,
        "freshness_met": freshness_met,
        "consistency_met": consistency_met,
        "runtime_validity_met": runtime_validity_met,
        "relevance_met": relevance_met,
        "evidence_complete": evidence_complete,
        "evidentiary_sufficiency_result": assessment.get(
            "evidentiary_sufficiency_result", "INSUFFICIENT"
        ),
        "consequence_burden_met": consequence_burden_met,
        "material_contradictions": material_contradictions,
        "unresolved_contradictions": unresolved_contradictions,
        "source_count_total": assessment.get("source_count_total", 0),
        "source_count_qualifying": assessment.get(
            "source_count_qualifying", 0
        ),
        "source_identity_summary": deepcopy(
            assessment.get("source_identity_summary", [])
        ),
        "source_assessment_digest": assessment.get(
            "source_assessment_digest"
        ),
        "evidentiary_sufficiency_digest": assessment.get(
            "evidentiary_sufficiency_digest"
        ),
        "human_safety": threshold_payload.get("human_safety"),
        "irreversibility": threshold_payload.get("irreversibility"),
        "cascading_impact": threshold_payload.get("cascading_impact"),
        "financial_operational": threshold_payload.get(
            "financial_operational"
        ),
        "corroboration_required": working_state.get("corroboration_required"),
        "corroboration_observed": assessment.get(
            "source_count_qualifying", 0
        ),
        "previous_tier": threshold_payload.get("previous_tier"),
        "current_tier": threshold_payload.get("current_tier"),
        "high_water_tier": threshold_payload.get("high_water_tier"),
        "tier_monotonic": tier_monotonic,
        "threshold_state_digest": threshold_state.get(
            "threshold_state_digest"
        ),
        "threshold_bundle_digest": None,
        "threshold_token_digests": {},
        "skg_verification_status": skg_metadata.get(
            "skg_verification_status", "MISSING"
        ),
        "dtn_contextualisation_status": dtn_metadata.get(
            "dtn_contextualisation_status", "MISSING"
        ),
        "root_of_trust_anchorage_status": (
            "VALID" if root_valid else "INVALID"
        ),
        "root_evidence_digest": _root_evidence_digest(working_state),
        "reason_codes": reason_codes,
        "required_action": required_action,
        "pt_token_required": True,
        "pt_token_hash": None,
        "pt_evidence_digest": None,
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_hash": working_state.get("eie_hash"),
        "eie_digest": working_state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            working_state.get("collective_signal_evidence")
        ).get("signal_digest"),
        "state_hash": working_state.get("state_hash"),
        "traversal_id": working_state.get("traversal_id"),
    }


def fail_procedural_truth_entry(
    state: Mapping[str, object], *, failures: list[str]
) -> Dict[str, object]:
    """Record a signed PT denial without running any PT evaluation substage."""

    working_state = deepcopy(dict(state))
    deterministic_entry_failures = sorted(set(failures))
    working_state.setdefault("tokens", {}).pop("procedural_truth", None)
    _purge_threshold_tokens(working_state)

    certification = _build_certification_result(
        working_state,
        checks_passed=False,
        failures=["root_of_trust_preflight"],
        threshold_failures=[],
        root_valid=False,
        root_failures=deterministic_entry_failures,
    )
    certification["procedural_truth_status"] = "DENY"
    certification["procedural_truth_reason"] = (
        "procedural_truth_root_preflight_failed"
    )
    certification["certification_status"] = "NOT_CERTIFIED"
    certification["required_action"] = "FULL_RETRAVERSAL"
    certification["pt_token_required"] = False
    certification["reason_codes"] = sorted(
        set(
            certification.get("reason_codes", [])
            + ["root_of_trust_preflight"]
            + [
                f"root_preflight:{reason}"
                for reason in deterministic_entry_failures
            ]
        )
    )

    working_state["procedural_truth_result"] = "FAIL"
    working_state["procedural_truth_outcome"] = "PT_FAIL"
    working_state["procedural_truth_reason"] = certification[
        "procedural_truth_reason"
    ]
    working_state["procedural_truth_failure_reasons"] = deepcopy(
        certification["reason_codes"]
    )
    working_state["procedural_truth_failure_outcome"] = "FAIL"

    envelope = _mapping(working_state.get("pt_evidence_envelope"))
    assessment = _mapping(envelope.get("source_assessment"))
    threshold_state = _mapping(working_state.get("threshold_conditioning_state"))
    timestamp = len(working_state.get("hash_chain", [])) + 1
    pt_evidence_payload = {
        "schema_version": PT_EVIDENCE_SCHEMA_VERSION,
        "issuing_stage": "procedural_truth_entry_preflight",
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            working_state.get("collective_signal_evidence")
        ).get("signal_digest"),
        "root_evidence_digest": _root_evidence_digest(working_state),
        "state_hash": working_state.get("state_hash"),
        "procedural_truth_result": "FAIL",
        "procedural_truth_outcome": "PT_FAIL",
        "procedural_truth_reason": certification["procedural_truth_reason"],
        "source_count_total": assessment.get("source_count_total", 0),
        "source_count_qualifying": assessment.get(
            "source_count_qualifying", 0
        ),
        "source_identity_summary": deepcopy(
            assessment.get("source_identity_summary", [])
        ),
        "source_assessment_digest": assessment.get(
            "source_assessment_digest"
        ),
        "verification_result": assessment.get("verification_result"),
        "attestation_result": assessment.get("attestation_result"),
        "freshness_result": assessment.get("freshness_result"),
        "provenance_result": assessment.get("provenance_result"),
        "consistency_result": assessment.get("consistency_result"),
        "relevance_result": assessment.get("relevance_result"),
        "evidence_completeness_result": assessment.get(
            "evidence_completeness_result"
        ),
        "evidentiary_sufficiency_result": assessment.get(
            "evidentiary_sufficiency_result", "INSUFFICIENT"
        ),
        "evidentiary_sufficiency_digest": assessment.get(
            "evidentiary_sufficiency_digest"
        ),
        "human_safety": _mapping(threshold_state.get("payload")).get(
            "human_safety"
        ),
        "irreversibility": _mapping(threshold_state.get("payload")).get(
            "irreversibility"
        ),
        "cascading_impact": _mapping(threshold_state.get("payload")).get(
            "cascading_impact"
        ),
        "financial_operational": _mapping(
            threshold_state.get("payload")
        ).get("financial_operational"),
        "computed_tier": certification["tier"],
        "previous_tier": certification.get("previous_tier"),
        "current_tier": certification.get("current_tier"),
        "high_water_tier": certification.get("high_water_tier"),
        "tier_monotonic": certification.get("tier_monotonic"),
        "corroboration_required": working_state.get("corroboration_required"),
        "corroboration_observed": assessment.get(
            "source_count_qualifying", 0
        ),
        "threshold_state_digest": threshold_state.get(
            "threshold_state_digest"
        ),
        "threshold_bundle_digest": None,
        "threshold_token_digests": {},
        "prior_hash_chain_head": current_chain_hash(working_state),
        "reason_codes": deepcopy(certification["reason_codes"]),
        "timestamp": timestamp,
        "timestamp_authority": PT_EVIDENCE_TIMESTAMP_AUTHORITY,
    }
    pt_evidence_payload["nonce"] = generate_digest(
        _pt_nonce_payload(pt_evidence_payload)
    )[:32]
    pt_evidence_digest = generate_digest(pt_evidence_payload)
    signature = sign_payload(pt_evidence_payload)
    working_state["procedural_truth_evidence"] = {
        "payload": pt_evidence_payload,
        "pt_evidence_digest": pt_evidence_digest,
        "signature": signature,
        "verified": verify_signature(pt_evidence_payload, signature),
    }
    certification["pt_evidence_digest"] = pt_evidence_digest
    working_state["procedural_truth_certification"] = certification
    working_state.setdefault("governance_feedback", {})[
        "procedural_truth_entry_preflight"
    ] = {
        "result": "FAIL",
        "failures": deterministic_entry_failures,
        "required_action": "full_retraversal_after_correction",
        "pt_evidence_digest": pt_evidence_digest,
    }
    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "procedural_truth_entry_preflight",
            "result": "FAIL",
            "failures": deterministic_entry_failures,
            "pt_evidence_digest": pt_evidence_digest,
        }
    )
    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "procedural_truth_entry_preflight",
            "result": "FAIL",
            "failures": deterministic_entry_failures,
            "pt_evidence_digest": pt_evidence_digest,
            "request_fingerprint": working_state.get("request_fingerprint"),
            "eie_digest": working_state.get("eie_hash"),
            "state_hash": pt_evidence_payload.get("state_hash"),
        },
    )


def finalize_procedural_truth(
    state: Mapping[str, object],
) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    working_state.setdefault("tokens", {}).pop("procedural_truth", None)
    _purge_threshold_tokens(working_state)
    governance_feedback = _mapping(working_state.get("governance_feedback"))
    failures: list[str] = []
    required_checks = [
        "evidence_validation",
        "corroboration",
        "threshold_conditioning",
        "procedural_consistency",
    ]
    for check in required_checks:
        result = _mapping(governance_feedback.get(check)).get("result")
        if result != "PASS":
            failures.append(check)

    root_valid, root_failures = validate_procedural_truth_entry(working_state)
    if not root_valid:
        failures.append("root_of_trust_preflight")

    threshold_failures = list(
        _mapping(governance_feedback.get("threshold_conditioning")).get(
            "failures", []
        )
    )
    certification = _build_certification_result(
        working_state,
        checks_passed=not failures,
        failures=failures,
        threshold_failures=threshold_failures,
        root_valid=root_valid,
        root_failures=root_failures,
    )
    certified = certification["certification_status"] == "CERTIFIED"
    if certified:
        working_state = issue_threshold_component_tokens(
            working_state,
            issued_at_stage="procedural_truth",
        )
        working_state = issue_threshold_bundle_token(
            working_state,
            issued_at_stage="procedural_truth",
        )
        threshold_bundle_valid, threshold_bundle_failures = (
            verify_threshold_bundle(working_state)
        )
        if threshold_bundle_valid:
            threshold_bundle = _mapping(
                _mapping(working_state.get("tokens")).get(
                    "threshold_bundle"
                )
            )
            certification["threshold_bundle_digest"] = (
                threshold_bundle.get("digest")
            )
            certification["threshold_token_digests"] = deepcopy(
                _mapping(threshold_bundle.get("payload")).get(
                    "component_hashes", {}
                )
            )
        else:
            _purge_threshold_tokens(working_state)
            certified = False
            failures.append("threshold_token_finalization")
            certification["certification_status"] = "NOT_CERTIFIED"
            certification["procedural_truth_status"] = "DENY"
            certification["procedural_truth_reason"] = (
                "procedural_truth_threshold_token_finalization_failed"
            )
            certification["required_action"] = "DENY_EXECUTION"
            certification["threshold_bundle_digest"] = None
            certification["threshold_token_digests"] = {}
            certification["reason_codes"] = sorted(
                set(
                    certification.get("reason_codes", [])
                    + ["threshold_token_finalization"]
                    + [
                        f"threshold_token_finalization:{reason}"
                        for reason in threshold_bundle_failures
                    ]
                )
            )
    if certified:
        procedural_truth_result = "PASS"
        pt_outcome = "PT_PASS"
        failure_outcome = None
    else:
        procedural_truth_result = "FAIL"
        pt_outcome = {
            "REFINE": "PT_REFINE",
            "ESCALATE": "PT_ESCALATE",
            "DENY": "PT_FAIL",
        }.get(str(certification["procedural_truth_status"]), "PT_FAIL")
        failure_outcome = {
            "REFINE": "REFINE",
            "ESCALATE": "ESCALATE",
            "DENY": "FAIL",
        }.get(str(certification["procedural_truth_status"]), "FAIL")

    deterministic_failures = sorted(set(certification["reason_codes"]))
    working_state["procedural_truth_result"] = procedural_truth_result
    working_state["procedural_truth_outcome"] = pt_outcome
    working_state["procedural_truth_reason"] = certification[
        "procedural_truth_reason"
    ]
    working_state["procedural_truth_failure_reasons"] = deterministic_failures
    working_state["procedural_truth_failure_outcome"] = failure_outcome

    envelope = _mapping(working_state.get("pt_evidence_envelope"))
    assessment = _mapping(envelope.get("source_assessment"))
    threshold_state = _mapping(working_state.get("threshold_conditioning_state"))
    timestamp = len(working_state.get("hash_chain", [])) + 1
    pt_evidence_payload = {
        "schema_version": PT_EVIDENCE_SCHEMA_VERSION,
        "issuing_stage": "procedural_truth",
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            working_state.get("collective_signal_evidence")
        ).get("signal_digest"),
        "root_evidence_digest": _root_evidence_digest(working_state),
        "state_hash": working_state.get("state_hash"),
        "procedural_truth_result": procedural_truth_result,
        "procedural_truth_outcome": pt_outcome,
        "procedural_truth_reason": certification["procedural_truth_reason"],
        "source_count_total": assessment.get("source_count_total", 0),
        "source_count_qualifying": assessment.get(
            "source_count_qualifying", 0
        ),
        "source_identity_summary": deepcopy(
            assessment.get("source_identity_summary", [])
        ),
        "source_assessment_digest": assessment.get(
            "source_assessment_digest"
        ),
        "verification_result": assessment.get("verification_result"),
        "attestation_result": assessment.get("attestation_result"),
        "freshness_result": assessment.get("freshness_result"),
        "provenance_result": assessment.get("provenance_result"),
        "consistency_result": assessment.get("consistency_result"),
        "relevance_result": assessment.get("relevance_result"),
        "evidence_completeness_result": assessment.get(
            "evidence_completeness_result"
        ),
        "evidentiary_sufficiency_result": assessment.get(
            "evidentiary_sufficiency_result", "INSUFFICIENT"
        ),
        "evidentiary_sufficiency_digest": assessment.get(
            "evidentiary_sufficiency_digest"
        ),
        "human_safety": _mapping(threshold_state.get("payload")).get(
            "human_safety"
        ),
        "irreversibility": _mapping(threshold_state.get("payload")).get(
            "irreversibility"
        ),
        "cascading_impact": _mapping(threshold_state.get("payload")).get(
            "cascading_impact"
        ),
        "financial_operational": _mapping(
            threshold_state.get("payload")
        ).get("financial_operational"),
        "computed_tier": certification["tier"],
        "previous_tier": certification.get("previous_tier"),
        "current_tier": certification.get("current_tier"),
        "high_water_tier": certification.get("high_water_tier"),
        "tier_monotonic": certification.get("tier_monotonic"),
        "corroboration_required": working_state.get("corroboration_required"),
        "corroboration_observed": assessment.get(
            "source_count_qualifying", 0
        ),
        "threshold_state_digest": threshold_state.get(
            "threshold_state_digest"
        ),
        "threshold_bundle_digest": certification.get(
            "threshold_bundle_digest"
        ),
        "threshold_token_digests": deepcopy(
            certification.get("threshold_token_digests", {})
        ),
        "prior_hash_chain_head": current_chain_hash(working_state),
        "reason_codes": deterministic_failures,
        "timestamp": timestamp,
        "timestamp_authority": PT_EVIDENCE_TIMESTAMP_AUTHORITY,
    }
    pt_evidence_payload["nonce"] = generate_digest(
        _pt_nonce_payload(pt_evidence_payload)
    )[:32]
    pt_evidence_digest = generate_digest(pt_evidence_payload)
    pt_evidence_signature = sign_payload(pt_evidence_payload)
    working_state["procedural_truth_evidence"] = {
        "payload": pt_evidence_payload,
        "pt_evidence_digest": pt_evidence_digest,
        "signature": pt_evidence_signature,
        "verified": verify_signature(
            pt_evidence_payload, pt_evidence_signature
        ),
    }
    certification["pt_evidence_digest"] = pt_evidence_digest
    working_state["procedural_truth_certification"] = certification

    working_state.setdefault("tokens", {}).pop("procedural_truth", None)
    if certified:
        working_state = issue_token(
            working_state,
            name="procedural_truth",
            issued_at_stage="procedural_truth",
            payload={
                "procedural_truth_result": "PASS",
                "procedural_truth_outcome": "PT_PASS",
                "pt_evidence_envelope_digest": working_state.get(
                    "pt_evidence_envelope_digest"
                ),
                "eie_digest": working_state.get("eie_hash"),
                "collective_signal_digest": pt_evidence_payload.get(
                    "collective_signal_digest"
                ),
                "root_evidence_digest": pt_evidence_payload.get(
                    "root_evidence_digest"
                ),
                "tier": certification["tier"],
                "corroboration_required": working_state.get(
                    "corroboration_required"
                ),
                "corroboration_observed": pt_evidence_payload.get(
                    "corroboration_observed"
                ),
                "pt_evidence_digest": pt_evidence_digest,
                "source_assessment_digest": assessment.get(
                    "source_assessment_digest"
                ),
                "evidentiary_sufficiency_result": "SUFFICIENT",
                "evidentiary_sufficiency_digest": assessment.get(
                    "evidentiary_sufficiency_digest"
                ),
                "human_safety": pt_evidence_payload.get("human_safety"),
                "irreversibility": pt_evidence_payload.get(
                    "irreversibility"
                ),
                "cascading_impact": pt_evidence_payload.get(
                    "cascading_impact"
                ),
                "financial_operational": pt_evidence_payload.get(
                    "financial_operational"
                ),
                "threshold_state_digest": threshold_state.get(
                    "threshold_state_digest"
                ),
                "threshold_bundle_digest": pt_evidence_payload.get(
                    "threshold_bundle_digest"
                ),
                "threshold_token_digests": deepcopy(
                    pt_evidence_payload.get("threshold_token_digests", {})
                ),
                "prior_hash_chain_head": pt_evidence_payload.get(
                    "prior_hash_chain_head"
                ),
                "issuing_stage": "procedural_truth",
                "timestamp": timestamp,
                "timestamp_authority": PT_EVIDENCE_TIMESTAMP_AUTHORITY,
                "nonce": pt_evidence_payload["nonce"],
                "checks": required_checks,
            },
        )
        certification["pt_token_hash"] = _mapping(
            _mapping(working_state.get("tokens")).get("procedural_truth")
        ).get("digest")
        working_state["procedural_truth_certification"] = certification

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "procedural_truth_finalization",
            "result": procedural_truth_result,
            "failures": failures,
            "pt_outcome": pt_outcome,
            "deterministic_failure_reasons": deterministic_failures,
            "failure_outcome": failure_outcome,
            "pt_evidence_digest": pt_evidence_digest,
            "qualifying_source_count": assessment.get(
                "source_count_qualifying", 0
            ),
            "corroboration_required": working_state.get(
                "corroboration_required"
            ),
            "computed_tier": certification["tier"],
        }
    )
    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "procedural_truth_finalization",
            "result": procedural_truth_result,
            "failures": failures,
            "pt_outcome": pt_outcome,
            "deterministic_failure_reasons": deterministic_failures,
            "failure_outcome": failure_outcome,
            "pt_evidence_digest": pt_evidence_digest,
            "evidentiary_sufficiency_result": assessment.get(
                "evidentiary_sufficiency_result"
            ),
            "qualifying_source_count": assessment.get(
                "source_count_qualifying", 0
            ),
            "corroboration_required": working_state.get(
                "corroboration_required"
            ),
            "computed_tier": certification["tier"],
            "request_fingerprint": working_state.get("request_fingerprint"),
            "eie_digest": working_state.get("eie_hash"),
            "state_hash": pt_evidence_payload.get("state_hash"),
        },
    )
