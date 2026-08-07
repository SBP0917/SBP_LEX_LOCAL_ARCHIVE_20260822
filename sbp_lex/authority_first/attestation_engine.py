from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.shared.control_chain_validation import (
    validate_collective_attachment_binding,
)
from sbp_lex.shared.hash_chain import append_hash_entry


def run_attestation(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    failures: list[str] = []
    if working_state.get("governance_feedback", {}).get(
        "anchor_validation", {}
    ).get("result") != "PASS":
        failures.append("anchor_validation_not_passed")
    attachment_valid, attachment_failures = validate_collective_attachment_binding(
        working_state
    )
    if not attachment_valid:
        failures.extend(attachment_failures)
    material = working_state.get("collective_attachment", {}).get(
        "root_trust_material", {}
    )
    attestations = material.get("attestations", []) if isinstance(
        material, Mapping
    ) else []
    if not isinstance(attestations, list) or not attestations:
        failures.append("attestation_missing")
        attestations = []
    identities: list[str] = []
    for index, attestation in enumerate(attestations):
        if not isinstance(attestation, Mapping):
            failures.append(f"attestation_malformed:{index}")
            continue
        identity = attestation.get("attestation_identity")
        if not isinstance(identity, str) or not identity:
            failures.append(f"attestation_identity_missing:{index}")
        else:
            identities.append(identity)
        if attestation.get("status") not in {"VALID", "REVOKED", "EXPIRED"}:
            failures.append(f"attestation_invalid:{index}")
        expected_digest = generate_digest({
            key: deepcopy(value)
            for key, value in dict(attestation).items()
            if key != "attestation_digest"
        })
        if attestation.get("attestation_digest") != expected_digest:
            failures.append(f"attestation_digest_invalid:{index}")
    attestation_hash = generate_digest(attestations)
    result = "PASS" if not failures else "FAIL"
    evidence = {
        "result": result,
        "attestation_hash": attestation_hash,
        "attestation_identities": identities,
        "attestation_count": len(attestations),
        "collective_attachment_attestation_digest": working_state.get(
            "collective_attachment", {}
        ).get("attestation", {}).get("attestation_digest"),
        "failures": sorted(set(failures)),
    }
    working_state.setdefault("governance_feedback", {})["attestation"] = evidence
    working_state.setdefault("audit_trace", []).append({
        "stage": "attestation",
        **evidence,
    })
    return append_hash_entry(
        working_state,
        stage="root_of_trust",
        payload={"substage": "attestation", **evidence},
    )
