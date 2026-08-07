from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping

from sbp_lex.shared.hash_chain import append_hash_entry


def run_truth_revocation(state: Mapping[str, object]) -> Dict[str, object]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []
    if working_state.get("governance_feedback", {}).get(
        "truth_expiry", {}
    ).get("result") != "PASS":
        failures.append("truth_expiry_not_passed")
    material = working_state.get("collective_attachment", {}).get(
        "root_trust_material", {}
    )
    authority = material.get("authority", {}) if isinstance(
        material, Mapping
    ) else {}
    if authority.get("revoked") is not False or authority.get(
        "authority_status"
    ) == "REVOKED":
        failures.append("authority_revoked")
    attestations = material.get("attestations", []) if isinstance(
        material, Mapping
    ) else []
    for index, attestation in enumerate(attestations):
        if not isinstance(attestation, Mapping) or attestation.get(
            "revoked"
        ) is not False or attestation.get("status") == "REVOKED":
            failures.append(f"attestation_revoked:{index}")
    truth = material.get("truth", {}) if isinstance(material, Mapping) else {}
    if truth.get("revoked") is not False or truth.get("status") == "REVOKED":
        failures.append("truth_revoked")
    result = "PASS" if not failures else "FAIL"
    evidence = {
        "result": result,
        "authority_identity": authority.get("authority_identity"),
        "attestation_identities": [
            item.get("attestation_identity") for item in attestations
            if isinstance(item, Mapping)
        ],
        "truth_identity": truth.get("truth_identity")
        if isinstance(truth, Mapping)
        else None,
        "failures": sorted(set(failures)),
    }
    working_state.setdefault("governance_feedback", {})[
        "truth_revocation"
    ] = evidence
    working_state.setdefault("audit_trace", []).append({
        "stage": "truth_revocation",
        **evidence,
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={"substage": "truth_revocation", **evidence},
    )
