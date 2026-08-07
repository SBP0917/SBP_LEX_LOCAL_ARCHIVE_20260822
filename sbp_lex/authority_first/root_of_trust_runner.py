from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.authority_first.anchor_validation_engine import run_anchor_validation
from sbp_lex.authority_first.attestation_engine import run_attestation
from sbp_lex.authority_first.attestation_consensus_engine import (
    run_attestation_consensus,
)
from sbp_lex.authority_first.truth_anchor_engine import run_truth_anchor
from sbp_lex.authority_first.truth_continuity_engine import run_truth_continuity
from sbp_lex.authority_first.truth_expiry_engine import run_truth_expiry
from sbp_lex.authority_first.truth_revocation_engine import run_truth_revocation
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.control_chain_validation import validate_root_input_bindings
from sbp_lex.shared.hash_chain import append_hash_entry


ROOT_OF_TRUST_ORDER = [
    run_anchor_validation,
    run_attestation,
    run_attestation_consensus,
    run_truth_anchor,
    run_truth_continuity,
    run_truth_expiry,
    run_truth_revocation,
]
ROOT_STAGE_NAMES = tuple(
    engine.__name__.replace("run_", "") for engine in ROOT_OF_TRUST_ORDER
)

FAIL_KEYS = {stage: stage for stage in ROOT_STAGE_NAMES}

ROOT_ELIGIBILITY_TOKENS = {
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain",
    "aurion",
    "execution_boundary",
    "threshold_bundle",
    "token_bundle",
    "master_convergence",
    "execution_attestation",
}

ROOT_AND_DOWNSTREAM_TOKEN_STAGES = {
    "root_of_trust",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain_wrap",
    "aurion_runtime",
    "execution_gate",
    "threshold_bundle",
    "token_bundle",
}


def _root_context(state: Mapping[str, Any]) -> Dict[str, Any]:
    signals = state.get("collective_signals", {})
    signals = signals if isinstance(signals, Mapping) else {}
    attachment = state.get("collective_attachment", {})
    material = attachment.get("root_trust_material", {}) if isinstance(
        attachment, Mapping
    ) else {}
    authority = material.get("authority", {}) if isinstance(
        material, Mapping
    ) else {}
    attestations = material.get("attestations", []) if isinstance(
        material, Mapping
    ) else []
    payload = {
        "schema_version": "desktop-v1.root-context.v1",
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "canonical_request_identity": state.get("request_identity_digest"),
        "state_hash_entering_root": state.get("state_hash"),
        "collective_signal_digest": signals.get("digest"),
        "collective_attachment_hash": attachment.get("attachment_hash")
        if isinstance(attachment, Mapping)
        else None,
        "root_trust_material_digest": material.get("material_digest")
        if isinstance(material, Mapping)
        else None,
        "authority_identity": authority.get("authority_identity")
        if isinstance(authority, Mapping)
        else None,
        "jurisdiction": authority.get("jurisdiction")
        if isinstance(authority, Mapping)
        else None,
        "attestation_identities": [
            item.get("attestation_identity")
            for item in attestations
            if isinstance(item, Mapping)
        ],
        "logical_timestamp": attachment.get("logical_timestamp")
        if isinstance(attachment, Mapping)
        else None,
        "nonce": signals.get("nonce"),
        "validation_basis": material.get("validation_basis", {})
        if isinstance(material, Mapping)
        else {},
        "token_chain_reference_entering_root": generate_digest(
            state.get("token_trace", [])
        ),
        "audit_chain_reference_entering_root": generate_digest(
            state.get("audit_trace", [])
        ),
    }
    return {**payload, "context_digest": generate_digest(payload)}


def _stage_results(state: Mapping[str, Any]) -> Dict[str, str]:
    feedback = state.get("governance_feedback", {})
    return {
        stage: str(feedback.get(stage, {}).get("result", "NOT_RUN"))
        for stage in ROOT_STAGE_NAMES
    }


def _stage_evidence_digests(state: Mapping[str, Any]) -> Dict[str, str | None]:
    feedback = state.get("governance_feedback", {})
    return {
        stage: (
            generate_digest(feedback.get(stage, {}))
            if isinstance(feedback.get(stage), Mapping)
            else None
        )
        for stage in ROOT_STAGE_NAMES
    }


def _root_evidence_payload(
    state: Mapping[str, Any],
    *,
    result: str,
    reason: str,
    failures: list[str],
    stopped_stage: str | None,
) -> Dict[str, Any]:
    context = state.get("root_of_trust_context", {})
    envelope = state.get("pt_evidence_envelope", {})
    envelope = envelope if isinstance(envelope, Mapping) else {}
    eie = state.get("eie", {})
    eie = eie if isinstance(eie, Mapping) else {}
    skg_metadata = envelope.get("skg_truth_foundation_metadata", {})
    skg_metadata = skg_metadata if isinstance(skg_metadata, Mapping) else {}
    dtn_metadata = envelope.get("dtn_contextual_verification_metadata", {})
    dtn_metadata = dtn_metadata if isinstance(dtn_metadata, Mapping) else {}
    attachment = state.get("collective_attachment", {})
    attachment = attachment if isinstance(attachment, Mapping) else {}
    material = attachment.get("root_trust_material", {})
    material = material if isinstance(material, Mapping) else {}
    truth_anchor = state.get("governance_feedback", {}).get("truth_anchor", {})
    truth_anchor = truth_anchor if isinstance(truth_anchor, Mapping) else {}
    return {
        "schema_version": "desktop-v1.root-evidence-payload.v1",
        "result": result,
        "reason": reason,
        "failures": sorted(set(failures)),
        "stopped_stage": stopped_stage,
        "eie_identity": {
            "object_type": eie.get("object_type"),
            "eie_version": eie.get("eie_version"),
            "request_fingerprint": state.get("request_fingerprint"),
        },
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
        "authority_reference_hash": generate_digest(skg_metadata),
        "pt_evidence_envelope_digest": state.get(
            "pt_evidence_envelope_digest"
        ),
        "state_hash": context.get("state_hash_entering_root"),
        "state_hash_entering_root": context.get("state_hash_entering_root"),
        "state_hash_after_root_chain": state.get("state_hash"),
        "traversal_id": state.get("traversal_id"),
        "timestamp_freshness_reference": envelope.get("freshness_status"),
        "token_chain_reference": context.get(
            "token_chain_reference_entering_root"
        ),
        "audit_chain_reference": context.get(
            "audit_chain_reference_entering_root"
        ),
        "collective_digest": context.get("collective_signal_digest"),
        "collective_signal_digest": context.get("collective_signal_digest"),
        "collective_attachment_hash": context.get(
            "collective_attachment_hash"
        ),
        "root_trust_material_digest": context.get(
            "root_trust_material_digest"
        ),
        "authority_identity": context.get("authority_identity"),
        "jurisdiction": context.get("jurisdiction"),
        "attestation_identities": context.get("attestation_identities", []),
        "logical_timestamp": context.get("logical_timestamp"),
        "nonce": context.get("nonce"),
        "root_context_digest": context.get("context_digest"),
        "validation_basis": deepcopy(context.get("validation_basis", {})),
        "stage_results": _stage_results(state),
        "stage_evidence_digests": _stage_evidence_digests(state),
        "truth_anchor_digest": truth_anchor.get("truth_anchor_hash"),
    }


def _root_record(
    state: Mapping[str, Any],
    *,
    result: str,
    reason: str,
    failures: list[str],
    stopped_stage: str | None,
) -> Dict[str, Any]:
    payload = _root_evidence_payload(
        state,
        result=result,
        reason=reason,
        failures=failures,
        stopped_stage=stopped_stage,
    )
    digest = generate_digest(payload)
    signature = sign_payload(payload)
    verified = verify_signature(payload, signature)
    passed = result == "PASS" and not failures and verified
    return {
        "schema_version": "desktop-v1.root-evidence.v1",
        "valid": passed,
        "anchorage_status": "VALID" if passed else "INVALID",
        "result": result,
        "reason": reason,
        "root_evidence_digest": digest,
        "anchor_digest": digest,
        "payload": payload,
        "signature": signature,
        "verified": verified,
        "authority": "CANONICAL_RUNTIME_ROOT_OF_TRUST",
        "failures": sorted(set(failures)),
    }


def _clear_root_and_downstream_eligibility(state: Dict[str, Any]) -> None:
    tokens = state.get("tokens", {})
    if isinstance(tokens, dict):
        for name, token in list(tokens.items()):
            issued_at_stage = (
                token.get("issued_at_stage")
                if isinstance(token, Mapping)
                else None
            )
            if (
                name in ROOT_ELIGIBILITY_TOKENS
                or issued_at_stage in ROOT_AND_DOWNSTREAM_TOKEN_STAGES
            ):
                tokens.pop(name, None)
    trace = state.get("token_trace", [])
    if isinstance(trace, list):
        state["token_trace"] = [
            item for item in trace
            if not (
                isinstance(item, Mapping)
                and (
                    item.get("name") in ROOT_ELIGIBILITY_TOKENS
                    or item.get("stage") in ROOT_AND_DOWNSTREAM_TOKEN_STAGES
                )
            )
        ]
    state["procedural_truth_result"] = "UNSET"
    state["procedural_truth_outcome"] = "UNSET"
    state["procedural_truth_reason"] = ""
    state["procedural_truth_failure_reasons"] = []
    state["procedural_truth_failure_outcome"] = None
    state["procedural_truth_certification"] = {}
    state["corroboration_met"] = False
    state.pop("threshold_conditioning_state", None)
    state.pop("procedural_truth_evidence", None)
    state.pop("evidentiary_sufficiency", None)
    state.pop("evidentiary_sufficiency_result", None)
    for field in (
        "pt_evidence_digest",
        "procedural_truth_evidence_digest",
        "pt_token_hash",
        "procedural_truth_token_hash",
    ):
        state.pop(field, None)
    feedback = state.get("governance_feedback", {})
    if isinstance(feedback, dict):
        for key in (
            "evidence_validation",
            "threshold_conditioning",
            "corroboration",
            "procedural_consistency",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
            "domain",
            "aurion15",
            "execution_gate",
        ):
            feedback.pop(key, None)
    for field in (
        "classification_result",
        "licensing_result",
        "governance_result",
        "grc_result",
        "domain_result",
        "aurion15_result",
    ):
        state[field] = "UNSET"


def _fail_root(
    state: Dict[str, Any], *, failed_stage: str, failures: list[str]
) -> Dict[str, Any]:
    unique_failures = sorted(set(str(item) for item in failures if item))
    reason = f"{failed_stage}:" + ",".join(unique_failures or ["root_stage_failed"])
    state["authority_first_result"] = "FAIL"
    state["authority_first_reason"] = reason
    state["decision"] = "DENY"
    state["execution_result"] = "HALT"
    state["execution_verified"] = False
    state["token_stack_valid"] = False
    state["persistent_inoperability"] = True
    state["controlled_return_required"] = True
    _clear_root_and_downstream_eligibility(state)
    state["governed_reentry"] = {
        "reentry_permitted": False,
        "retry_eligible": False,
        "reason": "root_of_trust_failure_requires_corrected_state",
        "required_action": "full_retraversal_after_correction",
        "required_corrections": [
            "corrected_authority_or_attestation_material",
            "renewed_eie_validation",
            "renewed_skg_dtn_validation",
            "renewed_hard_entry",
            "renewed_state_construction",
            "renewed_collective_attachment",
            "renewed_root_anchorage",
        ],
    }
    record = _root_record(
        state,
        result="FAIL",
        reason=reason,
        failures=unique_failures,
        stopped_stage=failed_stage,
    )
    state["root_of_trust_evidence"] = record
    state["root_of_trust_evidence_anchor"] = deepcopy(record)
    state.setdefault("governance_feedback", {})["root_of_trust"] = {
        "result": "FAIL",
        "reason": reason,
        "failed_stage": failed_stage,
        "failures": unique_failures,
        "root_evidence_digest": record["root_evidence_digest"],
    }
    state["governance_feedback"]["root_of_trust_evidence_anchor"] = {
        "result": "FAIL",
        "reason": reason,
        "failed_stage": failed_stage,
        "failures": unique_failures,
        "root_evidence_digest": record["root_evidence_digest"],
        "anchor_digest": record["anchor_digest"],
    }
    state.setdefault("audit_trace", []).append({
        "stage": "root_of_trust_runner",
        "event": "ROOT_OF_TRUST_FAILURE",
        "result": "FAIL",
        "reason": reason,
        "failed_engine": failed_stage,
        "failures": unique_failures,
        "root_evidence_digest": record["root_evidence_digest"],
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "state_hash_entering_root": state.get(
            "root_of_trust_context", {}
        ).get("state_hash_entering_root"),
    })
    return append_hash_entry(
        state,
        stage="root_of_trust",
        payload={
            "substage": "root_of_trust_finalization",
            "result": "FAIL",
            "reason": reason,
            "root_evidence_digest": record["root_evidence_digest"],
            "request_fingerprint": state.get("request_fingerprint"),
            "eie_digest": state.get("eie_hash"),
            "state_hash_entering_root": state.get(
                "root_of_trust_context", {}
            ).get("state_hash_entering_root"),
        },
    )


def run_root_of_trust(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    root_input_valid, root_input_failures = validate_root_input_bindings(
        working_state
    )
    context = _root_context(working_state)
    feedback = working_state.get("governance_feedback", {})
    if isinstance(feedback, dict):
        for stage in (*ROOT_STAGE_NAMES, "root_of_trust"):
            feedback.pop(stage, None)
        feedback.pop("root_of_trust_evidence_anchor", None)
    working_state.pop("root_of_trust_evidence", None)
    working_state.pop("root_of_trust_evidence_anchor", None)
    working_state["root_of_trust_context"] = context
    working_state["root_anchor_bound_state_hash"] = context.get(
        "state_hash_entering_root"
    )
    if not root_input_valid:
        return _fail_root(
            working_state,
            failed_stage="root_input_validation",
            failures=root_input_failures,
        )

    for engine in ROOT_OF_TRUST_ORDER:
        working_state = engine(working_state)
        engine_name = engine.__name__.replace("run_", "")
        engine_feedback = working_state.get("governance_feedback", {}).get(
            engine_name, {}
        )
        if engine_feedback.get("result") != "PASS":
            return _fail_root(
                working_state,
                failed_stage=engine_name,
                failures=list(engine_feedback.get("failures", [])),
            )

    working_state["authority_first_result"] = "PASS"
    working_state["authority_first_reason"] = "root_of_trust_chain_complete"
    record = _root_record(
        working_state,
        result="PASS",
        reason="root_of_trust_chain_complete",
        failures=[],
        stopped_stage=None,
    )
    working_state["root_of_trust_evidence"] = record
    working_state["root_of_trust_evidence_anchor"] = deepcopy(record)
    working_state = issue_token(
        working_state,
        name="authority",
        issued_at_stage="root_of_trust",
        payload={
            "authority_result": "PASS",
            "root_chain_complete": True,
            "evidence_anchor_digest": record["root_evidence_digest"],
            "root_evidence_digest": record["root_evidence_digest"],
            "request_fingerprint": working_state.get("request_fingerprint"),
            "eie_digest": working_state.get("eie_hash"),
            "state_hash_entering_root": context.get("state_hash_entering_root"),
            "collective_signal_digest": context.get(
                "collective_signal_digest"
            ),
            "collective_attachment_hash": context.get(
                "collective_attachment_hash"
            ),
            "authority_identity": context.get("authority_identity"),
            "jurisdiction": context.get("jurisdiction"),
            "attestation_identities": context.get(
                "attestation_identities", []
            ),
            "logical_timestamp": context.get("logical_timestamp"),
            "nonce": context.get("nonce"),
        },
    )
    working_state.setdefault("governance_feedback", {})["root_of_trust"] = {
        "result": "PASS",
        "reason": "root_of_trust_chain_complete",
        "stage_results": _stage_results(working_state),
        "root_evidence_digest": record["root_evidence_digest"],
    }
    working_state.setdefault("audit_trace", []).append({
        "stage": "root_of_trust_runner",
        "event": "ROOT_OF_TRUST_COMPLETE",
        "result": "PASS",
        "root_evidence_digest": record["root_evidence_digest"],
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "state_hash_entering_root": context.get("state_hash_entering_root"),
        "collective_signal_digest": context.get("collective_signal_digest"),
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={
            "substage": "root_of_trust_finalization",
            "result": "PASS",
            "root_evidence_digest": record["root_evidence_digest"],
            "request_fingerprint": working_state.get("request_fingerprint"),
            "eie_digest": working_state.get("eie_hash"),
            "state_hash_entering_root": context.get("state_hash_entering_root"),
            "collective_signal_digest": context.get(
                "collective_signal_digest"
            ),
        },
    )
