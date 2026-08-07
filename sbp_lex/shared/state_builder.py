from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import STATE_VERSION
from sbp_lex.runtime.boundary_types import HardEntryAdmission
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.control_chain_validation import canonical_eie_digest


EIE_SCHEMA_VERSION = "desktop-v1.eie.v1"
CANONICAL_STATE_SCHEMA_VERSION = "desktop-v1.canonical-state.v1"
EIE_FRESHNESS_WINDOW_SECONDS = 300
PROTECTED_STATE_FIELDS = (
    "state_version",
    "state_schema_version",
    "request_fingerprint",
    "request_identity_digest",
    "request_identity_snapshot",
    "traversal_id",
    "active_traversal_state_type",
    "eie",
    "eie_hash",
    "source_payload_hash",
    "action",
    "payload",
    "context",
    "resolved_authority",
    "jurisdiction",
    "verified_substrate_references",
    "hard_entry_gate",
)


def _safe_factor(value: Any) -> int:
    try:
        factor = int(value)
    except (TypeError, ValueError):
        return 0
    return factor if factor >= 0 else 0


def build_execution_intent_envelope(
    request: Mapping[str, Any],
) -> Dict[str, Any]:
    """Construct the one immutable EIE before any substrate package."""
    request_dict = deepcopy(dict(request))
    request_fingerprint = generate_digest(request_dict)
    source_payload_hash = generate_digest(request_dict.get("payload", {}))
    context = (
        request_dict.get("context", {})
        if isinstance(request_dict.get("context"), Mapping)
        else {}
    )
    payload = (
        request_dict.get("payload", {})
        if isinstance(request_dict.get("payload"), Mapping)
        else {}
    )
    classification = (
        payload.get("classification", {})
        if isinstance(payload.get("classification"), Mapping)
        else {}
    )
    logical_issued_at = int(request_fingerprint[:12], 16)
    logical_valid_until = logical_issued_at + EIE_FRESHNESS_WINDOW_SECONDS
    substrate_references = {
        "skg_package_reference": generate_digest({
            "package_type": "synthetic_skg_package",
            "schema_version": "desktop-v1.synthetic.skg.v1",
            "request_fingerprint": request_fingerprint,
        }),
        "dtn_package_reference": generate_digest({
            "package_type": "synthetic_dtn_package",
            "schema_version": "desktop-v1.synthetic.dtn.v1",
            "request_fingerprint": request_fingerprint,
        }),
        "skg_package_reference_digest": generate_digest({
            "package_type": "synthetic_skg_package",
            "schema_version": "desktop-v1.synthetic.skg.v1",
            "request_fingerprint": request_fingerprint,
        }),
        "dtn_package_reference_digest": generate_digest({
            "package_type": "synthetic_dtn_package",
            "schema_version": "desktop-v1.synthetic.dtn.v1",
            "request_fingerprint": request_fingerprint,
        }),
        "signature_mode": "CONTROLLED_LOCAL_HMAC_SHA256_V1",
        "provider_mode": "synthetic_local",
    }
    actor = request_dict.get("actor", {})
    principal = request_dict.get("principal", {})
    authority_claims = request_dict.get("authority_claims", {})
    environment_modifiers = classification.get(
        "environment_modifiers",
        context.get("environment_modifiers", []),
    )
    eie: Dict[str, Any] = {
        "object_type": "ExecutionIntentEnvelope",
        "eie_version": "1.0",
        "schema_version": EIE_SCHEMA_VERSION,
        "canonical_traversal_state": True,
        "adapter_identity": request_dict.get(
            "adapter_identity", "LOCAL_RUNTIME_ADAPTER"
        ),
        "source_system_identity": request_dict.get(
            "source_system_identity", "LOCAL_RUNTIME"
        ),
        "native_format": request_dict.get("native_format", "runtime_request"),
        "source_payload_hash": source_payload_hash,
        "request_fingerprint": request_fingerprint,
        "traversal_id": generate_digest({
            "request_fingerprint": request_fingerprint,
            "source_payload_hash": source_payload_hash,
            "adapter_identity": request_dict.get(
                "adapter_identity", "LOCAL_RUNTIME_ADAPTER"
            ),
        }),
        "intent": request_dict.get("action", ""),
        "action": request_dict.get("action", ""),
        "objective": request_dict.get(
            "objective", context.get("objective", request_dict.get("action", ""))
        ),
        "actor": deepcopy(dict(actor)) if isinstance(actor, Mapping) else {},
        "principal": (
            deepcopy(dict(principal)) if isinstance(principal, Mapping) else {}
        ),
        "authority_claim_inputs": {
            "resolved_authority_declaration": request_dict.get(
                "resolved_authority", ""
            ),
            "claims": (
                deepcopy(dict(authority_claims))
                if isinstance(authority_claims, Mapping)
                else {}
            ),
            "validation_status": "UNVALIDATED_INPUT",
        },
        "autonomy": classification.get(
            "autonomy_level", request_dict.get("autonomy", 0)
        ),
        "deployment": context.get(
            "operational_scope", request_dict.get("deployment", "local")
        ),
        "environment": context.get(
            "environment", request_dict.get("environment", "local")
        ),
        "consequence": deepcopy(
            request_dict.get(
                "safety_profile", context.get("consequence", {})
            )
        ),
        "ap_acf_deployment_declarations": {
            "ap_acf_class": classification.get(
                "ap_acf_class", classification.get("class", "")
            ),
            "autonomy_level": classification.get("autonomy_level", 0),
            "autonomy_ceiling": classification.get("autonomy_ceiling", 0),
            "operational_scope": classification.get(
                "operational_scope", context.get("operational_scope", "")
            ),
            "deployment_restrictions": deepcopy(
                classification.get("deployment_restrictions", [])
            ),
        },
        "environment_modifiers": deepcopy(environment_modifiers),
        "payload": deepcopy(payload),
        "context": deepcopy(context),
        "resolved_authority": request_dict.get("resolved_authority", ""),
        "jurisdiction": request_dict.get("jurisdiction", ""),
        "external_substrate_references": substrate_references,
        "freshness": {
            "clock": "REQUEST_FINGERPRINT_LOGICAL_CLOCK_V1",
            "issued_at": logical_issued_at,
            "valid_until": logical_valid_until,
            "max_age_seconds": EIE_FRESHNESS_WINDOW_SECONDS,
        },
        "replay": {
            "nonce": generate_digest({
                "request_fingerprint": request_fingerprint,
                "traversal_id": generate_digest({
                    "request_fingerprint": request_fingerprint,
                    "source_payload_hash": source_payload_hash,
                    "adapter_identity": request_dict.get(
                        "adapter_identity", "LOCAL_RUNTIME_ADAPTER"
                    ),
                }),
                "logical_issued_at": logical_issued_at,
            })[:32],
            "scope": "DESKTOP_V1_HARD_ENTRY",
        },
    }
    eie["eie_hash"] = canonical_eie_digest(eie)
    return eie


def build_state(
    admission: HardEntryAdmission,
) -> Dict[str, Any]:
    """The sole canonical state constructor; requires a sealed Hard Entry proof."""
    if not isinstance(admission, HardEntryAdmission):
        raise TypeError("hard_entry_admission_required")
    admission_valid, admission_failures = admission.validate_seal()
    if not admission_valid:
        raise ValueError(
            "hard_entry_admission_invalid:" + ",".join(admission_failures)
        )
    request_dict = admission.adapter.normalized_request()
    request_fingerprint = admission.adapter.request_fingerprint
    eie = admission.eie()
    if request_fingerprint != eie.get("request_fingerprint"):
        raise ValueError("hard_entry_request_eie_binding_invalid")
    source_payload_hash = eie["source_payload_hash"]
    substrate_evidence = admission.substrate_evidence()

    state = {
        "state_version": STATE_VERSION,
        "state_schema_version": CANONICAL_STATE_SCHEMA_VERSION,
        "request_fingerprint": request_fingerprint,
        "traversal_id": eie["traversal_id"],
        "active_traversal_state_type": "EIE",
        "eie": eie,
        "eie_hash": eie["eie_hash"],
        "source_payload_hash": source_payload_hash,
        "request_identity_snapshot": request_dict,
        "request_identity_digest": request_fingerprint,
        "action": request_dict.get("action", ""),
        "payload": request_dict.get("payload", {}),
        "context": request_dict.get("context", {}),
        "resolved_authority": request_dict.get("resolved_authority", ""),
        "jurisdiction": request_dict.get("jurisdiction", ""),
        "collective_signals": {},
        "collective_signal_status": "UNATTACHED",
        "collective_signal_evidence": {},
        "collective_attachment": {},
        "verified_substrate_references": {
            "skg_package_reference": substrate_evidence.get(
                "skg_package_reference"
            ),
            "skg_package_digest": substrate_evidence.get(
                "skg_package_digest"
            ),
            "skg_validation_status": substrate_evidence.get(
                "skg_validation_status"
            ),
            "dtn_package_reference": substrate_evidence.get(
                "dtn_package_reference"
            ),
            "dtn_package_digest": substrate_evidence.get(
                "dtn_package_digest"
            ),
            "dtn_validation_status": substrate_evidence.get(
                "dtn_validation_status"
            ),
            "bridge_validation_status": substrate_evidence.get(
                "bridge_validation_status"
            ),
            "bridge_result_digest": admission.bridge_result_digest,
        },
        "safety_profile": {
            "human_safety": _safe_factor(request_dict.get("safety_profile", {}).get("human_safety")),
            "irreversibility": _safe_factor(request_dict.get("safety_profile", {}).get("irreversibility")),
            "cascading_impact": _safe_factor(request_dict.get("safety_profile", {}).get("cascading_impact")),
            "financial_operational": _safe_factor(request_dict.get("safety_profile", {}).get("financial_operational")),
            "computed_tier": "LOW",
            "financial_tier": "LOW",
        },
        "corroboration_required": 2,
        "corroboration_met": False,
        "authority_first_result": "UNSET",
        "authority_first_reason": "",
        "procedural_truth_result": "UNSET",
        "procedural_truth_outcome": "UNSET",
        "procedural_truth_failure_reasons": [],
        "procedural_truth_certification": {},
        "pt_evidence_envelope": {},
        "pt_evidence_envelope_digest": "",
        "root_of_trust_evidence_anchor": {},
        "classification_result": "UNSET",
        "classification_reason": "",
        "licensing_result": "UNSET",
        "licensing_reason": "",
        "governance_result": "UNSET",
        "governance_reason": "",
        "governance_feedback": {},
        "hard_entry_gate": {
            "accepted": True,
            "failures": [],
            "request_fingerprint": request_fingerprint,
            "normalized_request_digest": (
                admission.adapter.normalized_request_digest
            ),
            "eie_digest": admission.eie_digest,
            "signal_digest": admission.collective_signal_digest,
            "skg_package_digest": substrate_evidence.get(
                "skg_package_digest"
            ),
            "dtn_package_digest": substrate_evidence.get(
                "dtn_package_digest"
            ),
            "bridge_result_digest": admission.bridge_result_digest,
            "admission_digest": admission.admission_digest,
        },
        "integration_stage_order": [],
        "ap_acf_precheck_result": "UNSET",
        "ap_acf_declaration": {},
        "ap_acf_declaration_hash": "",
        "grc_result": "UNSET",
        "domain_result": "UNSET",
        "aurion15_result": "UNSET",
        "candidate_attempt_count": 0,
        "current_candidate": {},
        "execution_result": "UNSET",
        "execution_reason": "",
        "decision": "UNSET",
        "tokens": {},
        "token_stack_valid": False,
        "token_verification_failures": [],
        "token_trace": [],
        "hash_chain": [],
        "state_hash": "",
        "audit_trace": [],
        "audit_record": {},
        "audit_hash": "",
        "audit_ledger": [],
        "last_denied_fingerprint": None,
        "operational_state": "UNSET",
        "persistent_inoperability": False,
        "controlled_return_required": False,
        "governed_reentry": {},
        "pipeline_mode": "UNSELECTED",
        "pipeline_convergence": {},
    }
    protected_payload = _protected_state_payload(state)
    state["boundary_protection"] = {
        "schema_version": "desktop-v1.boundary-protection.v1",
        "protected_fields": list(PROTECTED_STATE_FIELDS),
        "protected_values_digest": generate_digest(protected_payload),
        "hard_entry_admission_digest": admission.admission_digest,
    }
    construction_basis = {
        key: deepcopy(value)
        for key, value in state.items()
        if key not in {"state_hash", "state_construction_hash"}
    }
    state["state_construction_hash"] = generate_digest(construction_basis)
    state["state_hash"] = generate_digest(_state_for_hashing(state))
    return state


def _protected_state_payload(state: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        field: deepcopy(state.get(field))
        for field in PROTECTED_STATE_FIELDS
    }


def validate_boundary_protection(
    state: Mapping[str, Any],
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    protection = state.get("boundary_protection")
    if not isinstance(protection, Mapping):
        return False, ["boundary_protection_missing"]
    if protection.get("schema_version") != "desktop-v1.boundary-protection.v1":
        failures.append("boundary_protection_schema_invalid")
    if protection.get("protected_fields") != list(PROTECTED_STATE_FIELDS):
        failures.append("boundary_protected_field_manifest_invalid")
    if protection.get("protected_values_digest") != generate_digest(
        _protected_state_payload(state)
    ):
        failures.append("protected_state_field_mutation")
    if state.get("request_fingerprint") != state.get("request_identity_digest"):
        failures.append("request_fingerprint_immutable_binding_invalid")
    eie = state.get("eie")
    if not isinstance(eie, Mapping):
        failures.append("eie_missing_or_malformed")
    else:
        if state.get("eie_hash") != eie.get("eie_hash"):
            failures.append("eie_digest_immutable_binding_invalid")
        if eie.get("eie_hash") != canonical_eie_digest(eie):
            failures.append("eie_mutation_after_digest")
    return not failures, sorted(set(failures))


def _state_for_hashing(state: Mapping[str, Any]) -> Dict[str, Any]:
    excluded = {"state_hash", "audit_hash"}
    return {key: value for key, value in dict(state).items() if key not in excluded}


def clone_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    return deepcopy(dict(state))
