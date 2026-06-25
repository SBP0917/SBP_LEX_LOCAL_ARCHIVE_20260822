from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.adversarial_cases import (
    ADVERSARIAL_CASE_STATUSES,
    ADVERSARIAL_CASE_PASS,
    required_adversarial_case_ids,
)
from sbp_lex.local_trust.git_provenance import current_git_commit

ADVERSARIAL_NEGATIVE_HARNESS_PASS = "ADVERSARIAL_NEGATIVE_HARNESS_PASS"
ADVERSARIAL_NEGATIVE_HARNESS_FAIL = "ADVERSARIAL_NEGATIVE_HARNESS_FAIL"
ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE = "ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE"
ADVERSARIAL_NEGATIVE_HARNESS_STALE = "ADVERSARIAL_NEGATIVE_HARNESS_STALE"
ADVERSARIAL_NEGATIVE_HARNESS_DIRTY = "ADVERSARIAL_NEGATIVE_HARNESS_DIRTY"

ADVERSARIAL_HARNESS_STATUSES = {
    ADVERSARIAL_NEGATIVE_HARNESS_PASS,
    ADVERSARIAL_NEGATIVE_HARNESS_FAIL,
    ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE,
    ADVERSARIAL_NEGATIVE_HARNESS_STALE,
    ADVERSARIAL_NEGATIVE_HARNESS_DIRTY,
}

REQUIRED_SECTIONS = {
    "adversarial_harness_type",
    "adversarial_harness_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "github_remote",
    "github_sync_status",
    "source_phase",
    "bound_manifest_digest",
    "bound_execution_envelope_digest",
    "bound_evidence_chain_digest",
    "bound_regression_matrix_digest",
    "bound_constitutional_gates_digest",
    "bound_toolchain_guard_digest",
    "bound_capstone_digest",
    "bound_release_integrity_digest",
    "adversarial_case_results",
    "adversarial_summary",
    "boundary_confirmation_summary",
    "next_phase_readiness",
    "adversarial_payload_digest",
    "adversarial_digest",
    "adversarial_signature",
    "signature_mode",
    "adversarial_status",
    "validation_failures",
}

REQUIRED_CASE_FIELDS = {
    "case_id",
    "case_name",
    "case_category",
    "target_artifact",
    "attack_type",
    "mutation_method",
    "expected_detection",
    "actual_detection",
    "expected_result",
    "actual_result",
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


def validate_adversarial_harness(
    harness: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.adversarial_negative_harness import (
        ADVERSARIAL_HARNESS_SIGNATURE_MODE,
        adversarial_digest_for,
        adversarial_signature_for,
        hash_adversarial_payload,
    )
    from sbp_lex.local_trust.manifest import canonicalise_manifest

    failures: list[str] = []
    if not isinstance(harness, Mapping):
        return {"adversarial_status": ADVERSARIAL_NEGATIVE_HARNESS_FAIL, "validation_failures": ["harness_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(harness))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"adversarial_status": ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE, "validation_failures": failures}

    if harness.get("adversarial_harness_type") != "adversarial_local_trust_negative_test_harness":
        failures.append("invalid_adversarial_harness_type")
    if harness.get("adversarial_harness_version") != "18.7G":
        failures.append("invalid_adversarial_harness_version")
    if harness.get("source_phase") != "18.7G":
        failures.append("invalid_source_phase")
    if harness.get("signature_mode") != ADVERSARIAL_HARNESS_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if harness.get("adversarial_status") not in ADVERSARIAL_HARNESS_STATUSES:
        failures.append("invalid_adversarial_status")

    failures.extend(_binding_failures(harness))
    failures.extend(_case_failures(harness.get("adversarial_case_results")))
    failures.extend(_summary_failures(harness))
    failures.extend(_boundary_failures(harness.get("boundary_confirmation_summary")))
    failures.extend(_next_phase_failures(harness.get("next_phase_readiness")))
    failures.extend(_forbidden_failures(harness))

    try:
        canonicalise_manifest(harness)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload = hash_adversarial_payload(harness)
    if not hmac.compare_digest(str(harness.get("adversarial_payload_digest")), expected_payload):
        failures.append("adversarial_payload_digest_mismatch")

    expected_signature = adversarial_signature_for(expected_payload)
    if not hmac.compare_digest(str(harness.get("adversarial_signature")), expected_signature):
        failures.append("adversarial_signature_mismatch")

    expected_digest = adversarial_digest_for(expected_payload, expected_signature)
    if not hmac.compare_digest(str(harness.get("adversarial_digest")), expected_digest):
        failures.append("adversarial_digest_mismatch")

    if failures:
        incomplete_markers = ("missing_required_section:", "missing_required_case:")
        status = (
            ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE
            if any(any(failure.startswith(marker) for marker in incomplete_markers) for failure in failures)
            else ADVERSARIAL_NEGATIVE_HARNESS_FAIL
        )
        return {"adversarial_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        if current_commit and harness.get("git_commit") != current_commit:
            return {"adversarial_status": ADVERSARIAL_NEGATIVE_HARNESS_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and harness.get("github_sync_status", {}).get("tracked_working_tree_clean") is not True:
        return {"adversarial_status": ADVERSARIAL_NEGATIVE_HARNESS_DIRTY, "validation_failures": ["working_tree_dirty"]}

    return {"adversarial_status": ADVERSARIAL_NEGATIVE_HARNESS_PASS, "validation_failures": []}


def _binding_failures(harness: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for field in (
        "bound_manifest_digest",
        "bound_execution_envelope_digest",
        "bound_evidence_chain_digest",
        "bound_regression_matrix_digest",
        "bound_constitutional_gates_digest",
        "bound_toolchain_guard_digest",
        "bound_capstone_digest",
        "bound_release_integrity_digest",
    ):
        digest = str(harness.get(field))
        if len(digest) != 64:
            failures.append(f"bound_digest_invalid:{field}")
    return failures


def _case_failures(value: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, list):
        return ["adversarial_cases_not_list"]
    seen_ids: set[str] = set()
    for index, case in enumerate(value):
        if not isinstance(case, Mapping):
            failures.append(f"adversarial_case_not_mapping:{index}")
            continue
        missing = sorted(REQUIRED_CASE_FIELDS - set(case))
        failures.extend(f"adversarial_case_missing_field:{index}:{field}" for field in missing)
        case_id = str(case.get("case_id"))
        seen_ids.add(case_id)
        if case.get("status") not in ADVERSARIAL_CASE_STATUSES:
            failures.append(f"adversarial_case_invalid_status:{case_id}")
        if case.get("status") != ADVERSARIAL_CASE_PASS:
            failures.append(f"adversarial_case_not_passed:{case_id}")
    for case_id in sorted(required_adversarial_case_ids() - seen_ids):
        failures.append(f"missing_required_case:{case_id}")
    return failures


def _summary_failures(harness: Mapping[str, Any]) -> list[str]:
    summary = harness.get("adversarial_summary")
    cases = harness.get("adversarial_case_results")
    if not isinstance(summary, Mapping) or not isinstance(cases, list):
        return ["adversarial_summary_invalid"]
    statuses = [case.get("status") for case in cases if isinstance(case, Mapping)]
    categories = [case.get("case_category") for case in cases if isinstance(case, Mapping)]
    expected = {
        "total_cases": len(statuses),
        "passed_cases": statuses.count("ADVERSARIAL_CASE_PASS"),
        "failed_cases": statuses.count("ADVERSARIAL_CASE_FAIL"),
        "skipped_cases": statuses.count("ADVERSARIAL_CASE_SKIPPED"),
        "error_cases": statuses.count("ADVERSARIAL_CASE_ERROR"),
        "artifact_mutation_cases": categories.count("artifact_mutation"),
        "release_integrity_mutation_cases": categories.count("release_integrity_mutation"),
        "boundary_violation_cases": categories.count("boundary_violation"),
        "forbidden_authority_leakage_cases": categories.count("forbidden_authority_leakage"),
        "phase_19_boundary_cases": categories.count("phase_boundary"),
    }
    return [f"adversarial_summary_mismatch:{key}" for key, value in expected.items() if summary.get(key) != value]


def _boundary_failures(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["boundary_confirmation_summary_not_mapping"]
    failures: list[str] = []
    must_be_false = (
        "runtimeActivationIntroduced",
        "sbpLexRuntimeAuthorityChanged",
        "governanceBehaviorChanged",
        "proceduralTruthBehaviorChanged",
        "executionGateBehaviorChanged",
        "hardEntryGateBehaviorChanged",
        "skgDtnAuthorityAdded",
        "futureDistributedOrMobileRuntimeWorkIntroduced",
        "phase19Started",
        "externalValidationClaimed",
        "certificationClaimed",
    )
    for key in must_be_false:
        if value.get(key) is not False:
            failures.append(f"boundary_summary_not_false:{key}")
    if value.get("skgDtnExternalNonAuthoritative") is not True:
        failures.append("boundary_summary_skg_dtn_not_external")
    return failures


def _next_phase_failures(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["next_phase_readiness_not_mapping"]
    failures: list[str] = []
    if value.get("phase_id") != "18.8":
        failures.append("next_phase_not_18_8")
    if value.get("readiness_marker_only") is not True:
        failures.append("next_phase_readiness_marker_not_true")
    if value.get("implemented_in_this_phase") is not False:
        failures.append("next_phase_implemented_inside_phase")
    return failures


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

