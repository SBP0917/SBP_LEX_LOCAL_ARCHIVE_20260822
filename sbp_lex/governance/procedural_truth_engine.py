from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.hash_chain import append_hash_entry


def _status_is_valid(value: object, *, ready_value: str = "VALID") -> bool:
    return str(value or "").upper() == ready_value


def _build_certification_result(
    working_state: Mapping[str, Any],
    *,
    checks_passed: bool,
    failures: list[str],
    threshold_failures: list[str],
) -> Dict[str, Any]:
    envelope = working_state.get("pt_evidence_envelope", {})
    envelope = envelope if isinstance(envelope, Mapping) else {}
    skg_metadata = envelope.get("skg_truth_foundation_metadata", {})
    skg_metadata = skg_metadata if isinstance(skg_metadata, Mapping) else {}
    dtn_metadata = envelope.get("dtn_contextual_verification_metadata", {})
    dtn_metadata = dtn_metadata if isinstance(dtn_metadata, Mapping) else {}
    root_anchor = working_state.get("root_of_trust_evidence_anchor", {})
    root_anchor = root_anchor if isinstance(root_anchor, Mapping) else {}
    token = working_state.get("tokens", {}).get("procedural_truth", {})

    source_floor_met = working_state.get("corroboration_met") is True
    independence_met = envelope.get("source_independence_status") == "VALID"
    provenance_met = envelope.get("provenance_status") == "VALID"
    integrity_met = envelope.get("integrity_status") == "VALID"
    attestation_met = envelope.get("attestation_status") == "VALID"
    authority_met = envelope.get("authority_status") == "VALID"
    jurisdiction_met = envelope.get("jurisdiction_status") == "VALID"
    freshness_met = envelope.get("freshness_status") == "VALID"
    consistency_met = envelope.get("consistency_status") == "VALID"
    runtime_validity_met = envelope.get("runtime_validity_status") == "VALID"
    material_contradictions = envelope.get("material_contradictions") is True
    unresolved_contradictions = envelope.get("unresolved_contradictions") is True
    skg_valid = skg_metadata.get("skg_verification_status") == "VALID"
    dtn_valid = dtn_metadata.get("dtn_contextualisation_status") == "VALID"
    root_valid = root_anchor.get("valid") is True and root_anchor.get("anchorage_status") == "VALID"

    consequence_burden_met = all(
        [
            source_floor_met,
            independence_met,
            provenance_met,
            integrity_met,
            attestation_met,
            authority_met,
            jurisdiction_met,
            freshness_met,
            consistency_met,
            runtime_validity_met,
            not unresolved_contradictions,
            skg_valid,
            dtn_valid,
            root_valid,
        ]
    )
    factor_failures = []
    for name, met in (
        ("source_floor_not_met", source_floor_met),
        ("source_independence_not_met", independence_met),
        ("provenance_not_met", provenance_met),
        ("integrity_not_met", integrity_met),
        ("attestation_not_met", attestation_met),
        ("authority_not_met", authority_met),
        ("jurisdiction_not_met", jurisdiction_met),
        ("freshness_not_met", freshness_met),
        ("consistency_not_met", consistency_met),
        ("runtime_validity_not_met", runtime_validity_met),
        ("skg_verification_not_valid", skg_valid),
        ("dtn_contextualisation_not_valid", dtn_valid),
        ("root_of_trust_anchorage_not_valid", root_valid),
    ):
        if not met:
            factor_failures.append(name)
    if unresolved_contradictions:
        factor_failures.append("unresolved_material_contradiction")

    certified = checks_passed and consequence_burden_met and not factor_failures
    tier = str(working_state.get("safety_profile", {}).get("computed_tier", envelope.get("threshold_tier", "LOW"))).upper()
    reason_codes = sorted(set(failures + threshold_failures + factor_failures + list(envelope.get("deterministic_failure_reasons", []))))
    if certified:
        procedural_truth_status = "PASS"
        required_action = "ALLOW_CONTINUE"
    elif unresolved_contradictions or not integrity_met or not root_valid:
        procedural_truth_status = "DENY"
        required_action = "DENY_EXECUTION"
    elif tier in {"TOP", "EXTREME"} and (
        not source_floor_met
        or not authority_met
        or not jurisdiction_met
        or material_contradictions
    ):
        procedural_truth_status = "ESCALATE"
        required_action = "ESCALATE_AUTHORITY"
    else:
        procedural_truth_status = "REFINE"
        required_action = "REFINE_EVIDENCE"

    return {
        "procedural_truth_status": procedural_truth_status,
        "certification_status": "CERTIFIED" if certified else "NOT_CERTIFIED",
        "tier": "EXTREME" if tier == "EXTREME" else tier,
        "source_floor_met": source_floor_met,
        "independence_met": independence_met,
        "provenance_met": provenance_met,
        "integrity_met": integrity_met,
        "attestation_met": attestation_met,
        "authority_met": authority_met,
        "jurisdiction_met": jurisdiction_met,
        "freshness_met": freshness_met,
        "consistency_met": consistency_met,
        "runtime_validity_met": runtime_validity_met,
        "consequence_burden_met": consequence_burden_met,
        "material_contradictions": material_contradictions,
        "unresolved_contradictions": unresolved_contradictions,
        "skg_verification_status": skg_metadata.get("skg_verification_status", "MISSING"),
        "dtn_contextualisation_status": dtn_metadata.get("dtn_contextualisation_status", "MISSING"),
        "root_of_trust_anchorage_status": root_anchor.get("anchorage_status", "INVALID"),
        "reason_codes": reason_codes,
        "required_action": required_action,
        "pt_token_required": certified,
        "pt_token_hash": token.get("digest") if isinstance(token, Mapping) else None,
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_hash": working_state.get("eie_hash"),
        "state_hash": working_state.get("state_hash"),
        "traversal_id": working_state.get("traversal_id"),
    }


def finalize_procedural_truth(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))

    governance_feedback = working_state.get("governance_feedback", {})

    failures: list[str] = []

    required_checks = [
        "evidence_validation",
        "corroboration",
        "threshold_conditioning",
        "procedural_consistency",
    ]

    for check in required_checks:
        result = governance_feedback.get(check, {}).get("result")
        if result != "PASS":
            failures.append(check)

    passed = len(failures) == 0
    corroboration = governance_feedback.get("corroboration", {})
    threshold_failures = governance_feedback.get("threshold_conditioning", {}).get("failures", [])
    if passed:
        pt_outcome = "PT_PASS"
        failure_outcome = None
    elif threshold_failures:
        pt_outcome = "PT_FAIL"
        failure_outcome = "FAIL"
    else:
        failure_outcome = corroboration.get("failure_outcome", "REFINE")
        pt_outcome = "PT_ESCALATE" if failure_outcome == "ESCALATE" else "PT_REFINE"

    deterministic_failures = sorted(
        set(
            failures
            + list(threshold_failures)
            + ([] if passed else list(working_state.get("pt_evidence_envelope", {}).get("deterministic_failure_reasons", [])))
        )
    )

    if passed:
        working_state = issue_token(
            working_state,
            name="procedural_truth",
            issued_at_stage="procedural_truth",
            payload={
                "procedural_truth_result": "PASS",
                "procedural_truth_outcome": pt_outcome,
                "pt_evidence_envelope_digest": working_state.get("pt_evidence_envelope_digest"),
                "checks": required_checks,
            },
        )

    certification = _build_certification_result(
        working_state,
        checks_passed=passed,
        failures=failures,
        threshold_failures=list(threshold_failures),
    )
    if certification["certification_status"] != "CERTIFIED":
        passed = False
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
        working_state.get("tokens", {}).pop("procedural_truth", None)
        certification["pt_token_required"] = True
        certification["pt_token_hash"] = None
    else:
        certification["pt_token_hash"] = working_state.get("tokens", {}).get("procedural_truth", {}).get("digest")

    working_state["procedural_truth_result"] = "PASS" if passed else "FAIL"
    working_state["procedural_truth_outcome"] = pt_outcome
    working_state["procedural_truth_failure_reasons"] = deterministic_failures
    working_state["procedural_truth_failure_outcome"] = failure_outcome
    working_state["procedural_truth_certification"] = certification

    working_state.setdefault("audit_trace", []).append(
        {
            "stage": "procedural_truth_finalization",
            "result": working_state["procedural_truth_result"],
            "failures": failures,
            "pt_outcome": pt_outcome,
            "deterministic_failure_reasons": deterministic_failures,
            "failure_outcome": failure_outcome,
        }
    )

    return append_hash_entry(
        working_state,
        stage="procedural_truth",
        payload={
            "substage": "procedural_truth_finalization",
            "result": working_state["procedural_truth_result"],
            "failures": failures,
            "pt_outcome": pt_outcome,
            "deterministic_failure_reasons": deterministic_failures,
            "failure_outcome": failure_outcome,
        },
    )
