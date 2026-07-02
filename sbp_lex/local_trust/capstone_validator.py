from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.capstone_report import required_capstone_command_ids
from sbp_lex.local_trust.git_provenance import current_git_commit

LOCAL_TRUST_CAPSTONE_PASS = "LOCAL_TRUST_CAPSTONE_PASS"
LOCAL_TRUST_CAPSTONE_FAIL = "LOCAL_TRUST_CAPSTONE_FAIL"
LOCAL_TRUST_CAPSTONE_INCOMPLETE = "LOCAL_TRUST_CAPSTONE_INCOMPLETE"
LOCAL_TRUST_CAPSTONE_STALE = "LOCAL_TRUST_CAPSTONE_STALE"
LOCAL_TRUST_CAPSTONE_DIRTY = "LOCAL_TRUST_CAPSTONE_DIRTY"

CAPSTONE_STATUSES = {
    LOCAL_TRUST_CAPSTONE_PASS,
    LOCAL_TRUST_CAPSTONE_FAIL,
    LOCAL_TRUST_CAPSTONE_INCOMPLETE,
    LOCAL_TRUST_CAPSTONE_STALE,
    LOCAL_TRUST_CAPSTONE_DIRTY,
}

REQUIRED_SECTIONS = {
    "capstone_type",
    "capstone_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "github_remote",
    "github_sync_status",
    "phase_scope",
    "completed_phases",
    "bound_manifest_digest",
    "bound_execution_envelope_digest",
    "bound_evidence_chain_digest",
    "bound_regression_matrix_digest",
    "bound_constitutional_gates_digest",
    "bound_toolchain_guard_digest",
    "artifact_index",
    "verification_command_index",
    "verification_result_summary",
    "local_trust_completion_summary",
    "boundary_confirmation_summary",
    "next_phase_readiness",
    "capstone_payload_digest",
    "capstone_digest",
    "capstone_signature",
    "signature_mode",
    "capstone_status",
    "validation_failures",
}

REQUIRED_PHASE_IDS = {"18.7D.1", "18.7E.1", "18.7E.2", "18.7E.3", "18.7E.4"}
REQUIRED_ARTIFACT_IDS = {
    "manifest",
    "execution_envelope",
    "evidence_chain",
    "regression_matrix",
    "constitutional_gates",
    "toolchain_guard",
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


def validate_local_trust_capstone(
    capstone: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.local_trust_capstone import (
        CAPSTONE_SIGNATURE_MODE,
        capstone_digest_for,
        capstone_signature_for,
        hash_capstone_payload,
    )
    from sbp_lex.local_trust.manifest import canonicalise_manifest

    failures: list[str] = []
    if not isinstance(capstone, Mapping):
        return {"capstone_status": LOCAL_TRUST_CAPSTONE_FAIL, "validation_failures": ["capstone_not_mapping"]}

    missing = sorted(REQUIRED_SECTIONS - set(capstone))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"capstone_status": LOCAL_TRUST_CAPSTONE_INCOMPLETE, "validation_failures": failures}

    if capstone.get("capstone_type") != "local_trust_25_year_completion_lock":
        failures.append("invalid_capstone_type")
    if capstone.get("capstone_version") != "18.7E.4":
        failures.append("invalid_capstone_version")
    if capstone.get("signature_mode") != CAPSTONE_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if capstone.get("capstone_status") not in CAPSTONE_STATUSES:
        failures.append("invalid_capstone_status")

    failures.extend(_artifact_failures(capstone))
    failures.extend(_phase_failures(capstone.get("completed_phases")))
    failures.extend(_command_failures(capstone.get("verification_command_index")))
    failures.extend(_completion_failures(capstone.get("local_trust_completion_summary")))
    failures.extend(_boundary_failures(capstone.get("boundary_confirmation_summary")))
    failures.extend(_next_phase_failures(capstone.get("next_phase_readiness")))
    failures.extend(_forbidden_failures(capstone))

    try:
        canonicalise_manifest(capstone)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_capstone_payload(capstone)
    if not hmac.compare_digest(str(capstone.get("capstone_payload_digest")), expected_payload_digest):
        failures.append("capstone_payload_digest_mismatch")

    expected_signature = capstone_signature_for(expected_payload_digest)
    if not hmac.compare_digest(str(capstone.get("capstone_signature")), expected_signature):
        failures.append("capstone_signature_mismatch")

    expected_digest = capstone_digest_for(expected_payload_digest, expected_signature)
    if not hmac.compare_digest(str(capstone.get("capstone_digest")), expected_digest):
        failures.append("capstone_digest_mismatch")

    if failures:
        incomplete_markers = (
            "missing_required_section:",
            "missing_required_artifact:",
            "artifact_missing:",
            "missing_required_phase:",
            "missing_required_command:",
        )
        status = (
            LOCAL_TRUST_CAPSTONE_INCOMPLETE
            if any(any(failure.startswith(marker) for marker in incomplete_markers) for failure in failures)
            else LOCAL_TRUST_CAPSTONE_FAIL
        )
        return {"capstone_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        if current_commit and capstone.get("git_commit") != current_commit:
            return {"capstone_status": LOCAL_TRUST_CAPSTONE_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and capstone.get("github_sync_status", {}).get("tracked_working_tree_clean") is not True:
        return {"capstone_status": LOCAL_TRUST_CAPSTONE_DIRTY, "validation_failures": ["working_tree_dirty"]}

    return {"capstone_status": LOCAL_TRUST_CAPSTONE_PASS, "validation_failures": []}


def _artifact_failures(capstone: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    index = capstone.get("artifact_index")
    if not isinstance(index, list):
        return ["artifact_index_not_list"]
    by_id = {str(item.get("artifact_id")): item for item in index if isinstance(item, Mapping)}
    for artifact_id in sorted(REQUIRED_ARTIFACT_IDS - set(by_id)):
        failures.append(f"missing_required_artifact:{artifact_id}")
    binding_fields = {
        "manifest": "bound_manifest_digest",
        "execution_envelope": "bound_execution_envelope_digest",
        "evidence_chain": "bound_evidence_chain_digest",
        "regression_matrix": "bound_regression_matrix_digest",
        "constitutional_gates": "bound_constitutional_gates_digest",
        "toolchain_guard": "bound_toolchain_guard_digest",
    }
    for artifact_id, field in binding_fields.items():
        item = by_id.get(artifact_id)
        if item is None:
            continue
        digest = str(item.get("digest"))
        if item.get("presence_status") != "PRESENT":
            failures.append(f"artifact_missing:{artifact_id}")
        if item.get("validation_status") != item.get("expected_status"):
            failures.append(f"artifact_validation_not_expected:{artifact_id}")
        if len(digest) != 64:
            failures.append(f"artifact_digest_invalid:{artifact_id}")
        if capstone.get(field) != digest:
            failures.append(f"bound_digest_mismatch:{field}")
    return failures


def _phase_failures(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["completed_phases_not_list"]
    seen = {str(item.get("phase_id")) for item in value if isinstance(item, Mapping)}
    return [f"missing_required_phase:{phase_id}" for phase_id in sorted(REQUIRED_PHASE_IDS - seen)]


def _command_failures(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["verification_command_index_not_mapping"]
    commands = value.get("commands")
    if not isinstance(commands, list):
        return ["verification_command_index_commands_not_list"]
    seen = {str(item.get("command_id")) for item in commands if isinstance(item, Mapping)}
    return [f"missing_required_command:{command_id}" for command_id in sorted(required_capstone_command_ids() - seen)]


def _completion_failures(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["completion_summary_not_mapping"]
    failures: list[str] = []
    required_true = (
        "all_required_artifacts_present",
        "all_bound_artifacts_valid",
        "evidence_chain_unchanged",
        "local_trust_completion_locked",
        "phase_19_not_started",
    )
    for key in required_true:
        if value.get(key) is not True:
            failures.append(f"completion_summary_not_true:{key}")
    if value.get("completed_phase_count") != 5:
        failures.append("completion_phase_count_mismatch")
    if value.get("bound_artifact_count") != 6:
        failures.append("artifact_count_mismatch")
    if value.get("next_phase_id") != "18.7F":
        failures.append("next_phase_not_18_7f")
    return failures


def _boundary_failures(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["boundary_summary_not_mapping"]
    failures: list[str] = []
    must_be_false = (
        "runtimeActivationIntroduced",
        "sbpLexRuntimeAuthorityChanged",
        "governanceBehaviorChanged",
        "proceduralTruthBehaviorChanged",
        "executionGateBehaviorChanged",
        "hardEntryGateBehaviorChanged",
        "futureRuntimeSurfacesIntroduced",
        "phase19Started",
        "capstoneIsExecutionAuthority",
    )
    for key in must_be_false:
        if value.get(key) is not False:
            failures.append(f"boundary_not_false:{key}")
    if value.get("skgDtnRemainExternalNonAuthoritative") is not True:
        failures.append("skg_dtn_boundary_not_preserved")
    if value.get("unauthorizedProtectedRuntimePathChanges"):
        failures.append("protected_runtime_path_changes_present")
    if value.get("activeBoundaryScanMatches"):
        failures.append("active_boundary_scan_matches_present")
    return failures


def _next_phase_failures(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["next_phase_readiness_not_mapping"]
    failures: list[str] = []
    if value.get("next_phase_id") != "18.7F":
        failures.append("next_phase_id_invalid")
    if value.get("readiness_status") != "READY_MARKER_ONLY":
        failures.append("next_phase_readiness_status_invalid")
    if value.get("implemented_in_this_phase") is not False:
        failures.append("next_phase_implemented_inside_capstone")
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
