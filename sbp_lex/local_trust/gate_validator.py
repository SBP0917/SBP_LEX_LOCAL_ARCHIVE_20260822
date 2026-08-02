from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.gate_policy import GATE_STATUSES, REQUIRED_GATE_IDS
from sbp_lex.local_trust.git_provenance import (
    current_git_commit,
    generated_evidence_lineage_is_bounded,
)
from sbp_lex.local_trust.signing import verify_local_trust_digest

CONSTITUTIONAL_GATES_PASS = "CONSTITUTIONAL_GATES_PASS"
CONSTITUTIONAL_GATES_FAIL = "CONSTITUTIONAL_GATES_FAIL"
CONSTITUTIONAL_GATES_INCOMPLETE = "CONSTITUTIONAL_GATES_INCOMPLETE"
CONSTITUTIONAL_GATES_STALE = "CONSTITUTIONAL_GATES_STALE"
CONSTITUTIONAL_GATES_DIRTY = "CONSTITUTIONAL_GATES_DIRTY"

GATE_RESULT_STATUSES = {
    CONSTITUTIONAL_GATES_PASS,
    CONSTITUTIONAL_GATES_FAIL,
    CONSTITUTIONAL_GATES_INCOMPLETE,
    CONSTITUTIONAL_GATES_STALE,
    CONSTITUTIONAL_GATES_DIRTY,
}

REQUIRED_SECTIONS = {
    "gate_result_type",
    "gate_result_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "bound_manifest_digest",
    "bound_execution_envelope_digest",
    "bound_evidence_chain_digest",
    "bound_regression_matrix_digest",
    "gate_policy_version",
    "gate_results",
    "gate_summary",
    "gate_payload_digest",
    "gate_digest",
    "gate_signature",
    "signature_mode",
    "gate_status",
    "validation_failures",
}

REQUIRED_GATE_RESULT_FIELDS = {
    "gate_id",
    "gate_name",
    "gate_category",
    "required",
    "input_artifact",
    "expected_condition",
    "observed_condition",
    "status",
    "reason",
}

FORBIDDEN_KEYS = {
    "execution_permission",
    "governance_result",
    "runtime_authority",
    "allow_execution",
    "external_allow",
    "external_deny",
    "external_escalate",
    "external_" + "governance_result",
}


def validate_constitutional_gate_result(
    gate_result: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.constitutional_gates import (
        CONSTITUTIONAL_GATE_SIGNATURE_DOMAIN,
        CONSTITUTIONAL_GATE_SIGNATURE_MODE,
        gate_digest_for,
        hash_gate_payload,
    )
    from sbp_lex.local_trust.manifest import canonicalise_manifest

    failures: list[str] = []
    if not isinstance(gate_result, Mapping):
        return {"gate_status": CONSTITUTIONAL_GATES_FAIL, "validation_failures": ["gate_result_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(gate_result))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"gate_status": CONSTITUTIONAL_GATES_INCOMPLETE, "validation_failures": failures}

    if gate_result.get("gate_result_type") != "local_trust_constitutional_enforcement_gates":
        failures.append("invalid_gate_result_type")
    if gate_result.get("signature_mode") != CONSTITUTIONAL_GATE_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if gate_result.get("gate_status") not in GATE_RESULT_STATUSES:
        failures.append("invalid_gate_status")

    failures.extend(_binding_failures(gate_result))
    failures.extend(_gate_structure_failures(gate_result.get("gate_results")))
    failures.extend(_summary_failures(gate_result))
    failures.extend(_forbidden_failures(gate_result))

    try:
        canonicalise_manifest(gate_result)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_gate_payload(gate_result)
    if not hmac.compare_digest(str(gate_result.get("gate_payload_digest")), expected_payload_digest):
        failures.append("gate_payload_digest_mismatch")

    signature = gate_result.get("gate_signature")
    if not verify_local_trust_digest(
        CONSTITUTIONAL_GATE_SIGNATURE_DOMAIN, expected_payload_digest, signature,
    ):
        failures.append("gate_signature_mismatch")

    expected_gate_digest = (
        gate_digest_for(expected_payload_digest, signature)
        if isinstance(signature, Mapping)
        else ""
    )
    if not hmac.compare_digest(str(gate_result.get("gate_digest")), expected_gate_digest):
        failures.append("gate_digest_mismatch")

    if failures:
        incomplete_markers = ("missing_required_section:", "missing_required_gate:", "bound_artifact_missing:")
        status = (
            CONSTITUTIONAL_GATES_INCOMPLETE
            if any(any(failure.startswith(marker) for marker in incomplete_markers) for failure in failures)
            else CONSTITUTIONAL_GATES_FAIL
        )
        return {"gate_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        recorded_commit = gate_result.get("git_commit")
        if (
            current_commit
            and recorded_commit != current_commit
            and not generated_evidence_lineage_is_bounded(
                repository_root,
                str(recorded_commit),
                current_commit=current_commit,
            )
        ):
            return {"gate_status": CONSTITUTIONAL_GATES_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and gate_result.get("gate_summary", {}).get("working_tree_clean") is not True:
        return {"gate_status": CONSTITUTIONAL_GATES_DIRTY, "validation_failures": ["working_tree_dirty"]}

    gate_statuses = [gate.get("status") for gate in gate_result.get("gate_results", []) if isinstance(gate, Mapping)]
    if any(status in {"GATE_FAIL", "GATE_ERROR"} for status in gate_statuses):
        return {"gate_status": CONSTITUTIONAL_GATES_FAIL, "validation_failures": ["required_gate_failed_or_error"]}

    return {"gate_status": CONSTITUTIONAL_GATES_PASS, "validation_failures": []}


def _binding_failures(gate_result: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for field in (
        "bound_manifest_digest",
        "bound_execution_envelope_digest",
        "bound_evidence_chain_digest",
        "bound_regression_matrix_digest",
    ):
        digest = str(gate_result.get(field))
        if not digest or digest == "None" or digest.endswith("_MISSING") or digest.endswith("_INVALID"):
            failures.append(f"bound_artifact_missing:{field}")
    return failures


def _gate_structure_failures(value: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, list):
        return ["gate_results_not_list"]
    seen_ids: set[str] = set()
    for index, gate in enumerate(value):
        if not isinstance(gate, Mapping):
            failures.append(f"gate_result_not_mapping:{index}")
            continue
        missing = sorted(REQUIRED_GATE_RESULT_FIELDS - set(gate))
        failures.extend(f"gate_result_missing_field:{index}:{field}" for field in missing)
        gate_id = str(gate.get("gate_id"))
        seen_ids.add(gate_id)
        if gate.get("status") not in GATE_STATUSES:
            failures.append(f"gate_result_invalid_status:{index}")
    for gate_id in sorted(REQUIRED_GATE_IDS - seen_ids):
        failures.append(f"missing_required_gate:{gate_id}")
    return failures


def _summary_failures(gate_result: Mapping[str, Any]) -> list[str]:
    summary = gate_result.get("gate_summary")
    gates = gate_result.get("gate_results")
    if not isinstance(summary, Mapping) or not isinstance(gates, list):
        return ["gate_summary_invalid"]
    statuses = [gate.get("status") for gate in gates if isinstance(gate, Mapping)]
    expected = {
        "total_gates": len(statuses),
        "passed_gates": statuses.count("GATE_PASS"),
        "failed_gates": statuses.count("GATE_FAIL"),
        "skipped_gates": statuses.count("GATE_SKIPPED"),
        "error_gates": statuses.count("GATE_ERROR"),
    }
    return [f"gate_summary_mismatch:{key}" for key, value in expected.items() if summary.get(key) != value]


def _forbidden_failures(value: Any, path: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_path = f"{path}.{key_text}"
            if key_text in FORBIDDEN_KEYS:
                failures.append(f"forbidden_authority_key:{next_path}")
            failures.extend(_forbidden_failures(item, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_forbidden_failures(item, f"{path}[{index}]"))
    return failures
