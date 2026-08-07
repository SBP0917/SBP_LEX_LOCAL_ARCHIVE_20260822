from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


VALID_RESULTS = {"PASS", "FAIL", "ESCALATE"}


def run_anchor_validation(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    attachment = working_state.get("collective_attachment", {})
    material = attachment.get("root_trust_material", {}) if isinstance(
        attachment, Mapping
    ) else {}
    authority_material = material.get("authority", {}) if isinstance(
        material, Mapping
    ) else {}
    context = working_state.get("root_of_trust_context", {})

    authority = str(working_state.get("resolved_authority", "")).strip()
    jurisdiction = str(working_state.get("jurisdiction", "")).strip()
    failures: list[str] = []
    if not isinstance(context, Mapping) or not context.get("context_digest"):
        failures.append("root_context_missing")
    if not authority:
        failures.append("authority_missing")
    if not jurisdiction:
        failures.append("jurisdiction_missing")
    if working_state.get("collective_signal_status") != "ATTACHED":
        failures.append("collective_signals_not_attached")
    if not isinstance(authority_material, Mapping):
        failures.append("authority_material_missing")
        authority_material = {}
    if authority_material.get("authority_identity") != authority:
        failures.append("authority_identity_mismatch")
    if authority_material.get("jurisdiction") != jurisdiction:
        failures.append("authority_jurisdiction_mismatch")
    if authority_material.get("legitimacy_status") != "VALID":
        failures.append("authority_legitimacy_invalid")
    if authority_material.get("authority_status") not in {
        "ACTIVE", "REVOKED", "EXPIRED"
    }:
        failures.append("authority_status_malformed")
    if material.get("skg_validation_status") != "VALID":
        failures.append("authority_skg_validation_invalid")
    if material.get("validation_basis") != context.get("validation_basis"):
        failures.append("authority_validation_basis_mismatch")

    result = "PASS" if not failures else "FAIL"
    evidence = {
        "result": result,
        "failures": sorted(set(failures)),
        "authority_identity": authority,
        "jurisdiction": jurisdiction,
        "authority_evidence_digest": authority_material.get(
            "authority_evidence_digest"
        ),
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "state_hash_entering_root": context.get("state_hash_entering_root"),
    }
    working_state["authority_first_result"] = result
    working_state["authority_first_reason"] = (
        "anchor_validation_complete" if result == "PASS" else ",".join(evidence["failures"])
    )
    working_state.setdefault("governance_feedback", {})[
        "anchor_validation"
    ] = evidence
    working_state.setdefault("audit_trace", []).append({
        "stage": "anchor_validation",
        **evidence,
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={"substage": "anchor_validation", **evidence},
    )
