from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.git_provenance import (
    current_git_commit,
    generated_evidence_lineage_is_bounded,
)
from sbp_lex.local_trust.signing import verify_local_trust_digest
from sbp_lex.local_trust.toolchain_policy import REQUIRED_TOOLCHAIN_CHECK_IDS, TOOLCHAIN_CHECK_STATUSES

TOOLCHAIN_GUARD_PASS = "TOOLCHAIN_GUARD_PASS"
TOOLCHAIN_GUARD_FAIL = "TOOLCHAIN_GUARD_FAIL"
TOOLCHAIN_GUARD_INCOMPLETE = "TOOLCHAIN_GUARD_INCOMPLETE"
TOOLCHAIN_GUARD_STALE = "TOOLCHAIN_GUARD_STALE"
TOOLCHAIN_GUARD_DIRTY = "TOOLCHAIN_GUARD_DIRTY"
TOOLCHAIN_GUARD_UNSUPPORTED = "TOOLCHAIN_GUARD_UNSUPPORTED"

TOOLCHAIN_GUARD_STATUSES = {
    TOOLCHAIN_GUARD_PASS,
    TOOLCHAIN_GUARD_FAIL,
    TOOLCHAIN_GUARD_INCOMPLETE,
    TOOLCHAIN_GUARD_STALE,
    TOOLCHAIN_GUARD_DIRTY,
    TOOLCHAIN_GUARD_UNSUPPORTED,
}

REQUIRED_SECTIONS = {
    "toolchain_guard_type",
    "toolchain_guard_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "python_executable",
    "python_version",
    "python_prefix",
    "python_base_prefix",
    "platform",
    "pytest_version",
    "pip_version_if_available",
    "dependency_files",
    "dependency_file_digests",
    "installed_package_snapshot",
    "verification_command_policy",
    "pytest_collection_policy",
    "ignored_output_paths",
    "ignored_temp_paths",
    "bound_manifest_digest",
    "bound_execution_envelope_digest",
    "bound_evidence_chain_digest",
    "bound_regression_matrix_digest",
    "bound_constitutional_gates_digest",
    "toolchain_checks",
    "toolchain_summary",
    "toolchain_payload_digest",
    "toolchain_digest",
    "toolchain_signature",
    "signature_mode",
    "toolchain_status",
    "validation_failures",
}

REQUIRED_CHECK_FIELDS = {
    "check_id",
    "check_name",
    "check_category",
    "required",
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


def validate_toolchain_guard(
    guard: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.manifest import canonicalise_manifest
    from sbp_lex.local_trust.toolchain_guard import (
        TOOLCHAIN_GUARD_SIGNATURE_DOMAIN,
        TOOLCHAIN_GUARD_SIGNATURE_MODE,
        hash_toolchain_payload,
        toolchain_digest_for,
    )

    failures: list[str] = []
    if not isinstance(guard, Mapping):
        return {"toolchain_status": TOOLCHAIN_GUARD_FAIL, "validation_failures": ["toolchain_guard_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(guard))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"toolchain_status": TOOLCHAIN_GUARD_INCOMPLETE, "validation_failures": failures}

    if guard.get("toolchain_guard_type") != "local_trust_dependency_toolchain_guard":
        failures.append("invalid_toolchain_guard_type")
    if guard.get("signature_mode") != TOOLCHAIN_GUARD_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if guard.get("toolchain_status") not in TOOLCHAIN_GUARD_STATUSES:
        failures.append("invalid_toolchain_status")

    failures.extend(_binding_failures(guard))
    failures.extend(_check_structure_failures(guard.get("toolchain_checks")))
    failures.extend(_summary_failures(guard))
    failures.extend(_forbidden_failures(guard))

    try:
        canonicalise_manifest(guard)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_toolchain_payload(guard)
    if not hmac.compare_digest(str(guard.get("toolchain_payload_digest")), expected_payload_digest):
        failures.append("toolchain_payload_digest_mismatch")

    signature = guard.get("toolchain_signature")
    if not verify_local_trust_digest(
        TOOLCHAIN_GUARD_SIGNATURE_DOMAIN, expected_payload_digest, signature,
    ):
        failures.append("toolchain_signature_mismatch")

    expected_digest = (
        toolchain_digest_for(expected_payload_digest, signature)
        if isinstance(signature, Mapping)
        else ""
    )
    if not hmac.compare_digest(str(guard.get("toolchain_digest")), expected_digest):
        failures.append("toolchain_digest_mismatch")

    if failures:
        incomplete_markers = ("missing_required_section:", "missing_required_check:", "bound_artifact_missing:")
        status = (
            TOOLCHAIN_GUARD_INCOMPLETE
            if any(any(failure.startswith(marker) for marker in incomplete_markers) for failure in failures)
            else TOOLCHAIN_GUARD_FAIL
        )
        return {"toolchain_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        recorded_commit = guard.get("git_commit")
        if (
            current_commit
            and recorded_commit != current_commit
            and not generated_evidence_lineage_is_bounded(
                repository_root,
                str(recorded_commit),
                current_commit=current_commit,
            )
        ):
            return {"toolchain_status": TOOLCHAIN_GUARD_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and guard.get("toolchain_summary", {}).get("working_tree_clean") is not True:
        return {"toolchain_status": TOOLCHAIN_GUARD_DIRTY, "validation_failures": ["working_tree_dirty"]}

    statuses = [check.get("status") for check in guard.get("toolchain_checks", []) if isinstance(check, Mapping)]
    if any(status in {"TOOLCHAIN_CHECK_FAIL", "TOOLCHAIN_CHECK_ERROR"} for status in statuses):
        return {"toolchain_status": TOOLCHAIN_GUARD_FAIL, "validation_failures": ["required_toolchain_check_failed_or_error"]}

    return {"toolchain_status": TOOLCHAIN_GUARD_PASS, "validation_failures": []}


def _binding_failures(guard: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for field in (
        "bound_manifest_digest",
        "bound_execution_envelope_digest",
        "bound_evidence_chain_digest",
        "bound_regression_matrix_digest",
        "bound_constitutional_gates_digest",
    ):
        digest = str(guard.get(field))
        if not digest or digest == "None" or digest.endswith("_MISSING") or digest.endswith("_INVALID"):
            failures.append(f"bound_artifact_missing:{field}")
    return failures


def _check_structure_failures(value: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, list):
        return ["toolchain_checks_not_list"]
    seen: set[str] = set()
    for index, check in enumerate(value):
        if not isinstance(check, Mapping):
            failures.append(f"toolchain_check_not_mapping:{index}")
            continue
        missing = sorted(REQUIRED_CHECK_FIELDS - set(check))
        failures.extend(f"toolchain_check_missing_field:{index}:{field}" for field in missing)
        check_id = str(check.get("check_id"))
        seen.add(check_id)
        if check.get("status") not in TOOLCHAIN_CHECK_STATUSES:
            failures.append(f"toolchain_check_invalid_status:{index}")
    for check_id in sorted(REQUIRED_TOOLCHAIN_CHECK_IDS - seen):
        failures.append(f"missing_required_check:{check_id}")
    return failures


def _summary_failures(guard: Mapping[str, Any]) -> list[str]:
    summary = guard.get("toolchain_summary")
    checks = guard.get("toolchain_checks")
    if not isinstance(summary, Mapping) or not isinstance(checks, list):
        return ["toolchain_summary_invalid"]
    statuses = [check.get("status") for check in checks if isinstance(check, Mapping)]
    expected = {
        "total_checks": len(statuses),
        "passed_checks": statuses.count("TOOLCHAIN_CHECK_PASS"),
        "failed_checks": statuses.count("TOOLCHAIN_CHECK_FAIL"),
        "skipped_checks": statuses.count("TOOLCHAIN_CHECK_SKIPPED"),
        "error_checks": statuses.count("TOOLCHAIN_CHECK_ERROR"),
    }
    return [
        f"toolchain_summary_mismatch:{key}"
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
