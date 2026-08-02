from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.git_provenance import (
    current_git_commit,
    generated_evidence_lineage_is_bounded,
)
from sbp_lex.local_trust.regression_cases import REGRESSION_CASE_STATUSES, REQUIRED_REGRESSION_CASE_IDS
from sbp_lex.local_trust.signing import verify_local_trust_digest

REGRESSION_MATRIX_VALID = "REGRESSION_MATRIX_VALID"
REGRESSION_MATRIX_INVALID = "REGRESSION_MATRIX_INVALID"
REGRESSION_MATRIX_INCOMPLETE = "REGRESSION_MATRIX_INCOMPLETE"
REGRESSION_MATRIX_STALE = "REGRESSION_MATRIX_STALE"
REGRESSION_MATRIX_DIRTY = "REGRESSION_MATRIX_DIRTY"
REGRESSION_MATRIX_FAILED = "REGRESSION_MATRIX_FAILED"

MATRIX_STATUSES = {
    REGRESSION_MATRIX_VALID,
    REGRESSION_MATRIX_INVALID,
    REGRESSION_MATRIX_INCOMPLETE,
    REGRESSION_MATRIX_STALE,
    REGRESSION_MATRIX_DIRTY,
    REGRESSION_MATRIX_FAILED,
}

REQUIRED_SECTIONS = {
    "matrix_type",
    "matrix_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "git_status_short",
    "working_tree_clean",
    "bound_manifest_digest",
    "bound_execution_envelope_digest",
    "bound_evidence_chain_digest",
    "regression_cases",
    "regression_summary",
    "matrix_payload_digest",
    "matrix_digest",
    "matrix_signature",
    "signature_mode",
    "matrix_status",
    "validation_failures",
}

REQUIRED_CASE_FIELDS = {
    "case_id",
    "case_name",
    "risk_category",
    "target_artifact",
    "mutation_type",
    "expected_detection",
    "actual_detection",
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


def validate_local_trust_regression_matrix(
    matrix: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.manifest import canonicalise_manifest
    from sbp_lex.local_trust.regression_matrix import (
        REGRESSION_MATRIX_SIGNATURE_DOMAIN,
        REGRESSION_MATRIX_SIGNATURE_MODE,
        hash_matrix_payload,
        matrix_digest_for,
    )

    failures: list[str] = []
    if not isinstance(matrix, Mapping):
        return {"matrix_status": REGRESSION_MATRIX_INVALID, "validation_failures": ["matrix_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(matrix))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"matrix_status": REGRESSION_MATRIX_INCOMPLETE, "validation_failures": failures}

    if matrix.get("matrix_type") != "local_trust_regression_matrix":
        failures.append("invalid_matrix_type")
    if matrix.get("signature_mode") != REGRESSION_MATRIX_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if matrix.get("matrix_status") not in MATRIX_STATUSES:
        failures.append("invalid_matrix_status")

    failures.extend(_binding_failures(matrix))
    failures.extend(_case_structure_failures(matrix.get("regression_cases")))
    failures.extend(_summary_failures(matrix))
    failures.extend(_forbidden_failures(matrix))

    try:
        canonicalise_manifest(matrix)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_matrix_payload(matrix)
    if not hmac.compare_digest(str(matrix.get("matrix_payload_digest")), expected_payload_digest):
        failures.append("matrix_payload_digest_mismatch")

    signature = matrix.get("matrix_signature")
    if not verify_local_trust_digest(
        REGRESSION_MATRIX_SIGNATURE_DOMAIN, expected_payload_digest, signature,
    ):
        failures.append("matrix_signature_mismatch")

    expected_matrix_digest = (
        matrix_digest_for(expected_payload_digest, signature)
        if isinstance(signature, Mapping)
        else ""
    )
    if not hmac.compare_digest(str(matrix.get("matrix_digest")), expected_matrix_digest):
        failures.append("matrix_digest_mismatch")

    if failures:
        incomplete_markers = (
            "missing_bound_manifest",
            "missing_bound_execution_envelope",
            "missing_bound_evidence_chain",
            "missing_required_case:",
        )
        status = (
            REGRESSION_MATRIX_INCOMPLETE
            if any(any(failure.startswith(marker) for marker in incomplete_markers) for failure in failures)
            else REGRESSION_MATRIX_INVALID
        )
        return {"matrix_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        recorded_commit = matrix.get("git_commit")
        if (
            current_commit
            and recorded_commit != current_commit
            and not generated_evidence_lineage_is_bounded(
                repository_root,
                str(recorded_commit),
                current_commit=current_commit,
            )
        ):
            return {"matrix_status": REGRESSION_MATRIX_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and matrix.get("working_tree_clean") is not True:
        return {"matrix_status": REGRESSION_MATRIX_DIRTY, "validation_failures": ["working_tree_dirty"]}

    case_statuses = [case.get("status") for case in matrix.get("regression_cases", [])]
    if any(status in {"REGRESSION_CASE_FAIL", "REGRESSION_CASE_ERROR"} for status in case_statuses):
        return {"matrix_status": REGRESSION_MATRIX_FAILED, "validation_failures": ["regression_case_failed_or_error"]}

    return {"matrix_status": REGRESSION_MATRIX_VALID, "validation_failures": []}


def _binding_failures(matrix: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    if matrix.get("bound_manifest_digest") in {None, "", "LOCAL_TRUST_MANIFEST_MISSING", "LOCAL_TRUST_MANIFEST_INVALID"}:
        failures.append("missing_bound_manifest")
    if matrix.get("bound_execution_envelope_digest") in {None, "", "EXECUTION_ENVELOPE_MISSING", "EXECUTION_ENVELOPE_INVALID"}:
        failures.append("missing_bound_execution_envelope")
    if matrix.get("bound_evidence_chain_digest") in {None, "", "EVIDENCE_CHAIN_MISSING", "EVIDENCE_CHAIN_INVALID"}:
        failures.append("missing_bound_evidence_chain")
    return failures


def _case_structure_failures(value: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, list):
        return ["regression_cases_not_list"]
    seen_ids: set[str] = set()
    for index, case in enumerate(value):
        if not isinstance(case, Mapping):
            failures.append(f"regression_case_not_mapping:{index}")
            continue
        missing = sorted(REQUIRED_CASE_FIELDS - set(case))
        failures.extend(f"regression_case_missing_field:{index}:{field}" for field in missing)
        case_id = str(case.get("case_id"))
        seen_ids.add(case_id)
        if case.get("status") not in REGRESSION_CASE_STATUSES:
            failures.append(f"regression_case_invalid_status:{index}")
    for case_id in sorted(REQUIRED_REGRESSION_CASE_IDS - seen_ids):
        failures.append(f"missing_required_case:{case_id}")
    return failures


def _summary_failures(matrix: Mapping[str, Any]) -> list[str]:
    summary = matrix.get("regression_summary")
    cases = matrix.get("regression_cases")
    if not isinstance(summary, Mapping) or not isinstance(cases, list):
        return ["regression_summary_invalid"]
    statuses = [case.get("status") for case in cases if isinstance(case, Mapping)]
    expected = {
        "total_cases": len(statuses),
        "passed_cases": statuses.count("REGRESSION_CASE_PASS"),
        "failed_cases": statuses.count("REGRESSION_CASE_FAIL"),
        "skipped_cases": statuses.count("REGRESSION_CASE_SKIPPED"),
        "error_cases": statuses.count("REGRESSION_CASE_ERROR"),
    }
    return [
        f"regression_summary_mismatch:{key}"
        for key, value in expected.items()
        if summary.get(key) != value
    ]


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
