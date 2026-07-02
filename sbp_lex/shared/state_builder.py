from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.config.security_config import STATE_VERSION
from sbp_lex.governance.procedural_truth_envelope import build_pt_evidence_envelope
from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.control_chain_validation import canonical_eie_digest


def _safe_factor(value: Any) -> int:
    try:
        factor = int(value)
    except (TypeError, ValueError):
        return 0
    return factor if factor >= 0 else 0


def build_state(
    request: Mapping[str, Any],
    admitted_pre_context: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    request_dict = deepcopy(dict(request))
    request_fingerprint = generate_digest(request_dict)
    source_payload_hash = generate_digest(request_dict.get("payload", {}))
    eie = {
        "object_type": "ExecutionIntentEnvelope",
        "eie_version": "1.0",
        "canonical_traversal_state": True,
        "adapter_identity": request_dict.get("adapter_identity", "LOCAL_RUNTIME_ADAPTER"),
        "source_system_identity": request_dict.get("source_system_identity", "LOCAL_RUNTIME"),
        "native_format": request_dict.get("native_format", "runtime_request"),
        "source_payload_hash": source_payload_hash,
        "request_fingerprint": request_fingerprint,
        "traversal_id": generate_digest(
            {
                "request_fingerprint": request_fingerprint,
                "source_payload_hash": source_payload_hash,
                "adapter_identity": request_dict.get("adapter_identity", "LOCAL_RUNTIME_ADAPTER"),
            }
        ),
        "intent": request_dict.get("action", ""),
        "payload": request_dict.get("payload", {}),
        "context": request_dict.get("context", {}),
        "resolved_authority": request_dict.get("resolved_authority", ""),
        "jurisdiction": request_dict.get("jurisdiction", ""),
        "skg_truth_foundation": {},
        "dtn_contextual_verification": {},
        "root_of_trust_anchorage": {},
        "procedural_truth_certification": {},
    }
    eie["eie_hash"] = canonical_eie_digest(eie)
    pt_envelope, pt_envelope_digest = build_pt_evidence_envelope(
        request_dict, admitted_pre_context, eie=eie
    )

    state = {
        "state_version": STATE_VERSION,
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
        "pt_evidence_envelope": pt_envelope,
        "pt_evidence_envelope_digest": pt_envelope_digest,
        "root_of_trust_evidence_anchor": {},
        "classification_result": "UNSET",
        "classification_reason": "",
        "licensing_result": "UNSET",
        "licensing_reason": "",
        "governance_result": "UNSET",
        "governance_reason": "",
        "governance_feedback": {},
        "hard_entry_gate": {},
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

    state["state_hash"] = generate_digest(_state_for_hashing(state))
    return state


def _state_for_hashing(state: Mapping[str, Any]) -> Dict[str, Any]:
    excluded = {"state_hash", "audit_hash"}
    return {key: value for key, value in dict(state).items() if key not in excluded}


def clone_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    return deepcopy(dict(state))
