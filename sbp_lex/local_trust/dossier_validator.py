from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.claims_to_evidence import (
    CLAIM_STATUSES,
    required_claim_ids,
    required_reviewer_command_ids,
)
from sbp_lex.local_trust.git_provenance import current_git_commit
from sbp_lex.local_trust.release_hash_index import file_sha256
from sbp_lex.local_trust.validation_questions import required_validation_question_ids

VALIDATION_DOSSIER_READY = "VALIDATION_DOSSIER_READY"
VALIDATION_DOSSIER_FAIL = "VALIDATION_DOSSIER_FAIL"
VALIDATION_DOSSIER_INCOMPLETE = "VALIDATION_DOSSIER_INCOMPLETE"
VALIDATION_DOSSIER_STALE = "VALIDATION_DOSSIER_STALE"
VALIDATION_DOSSIER_DIRTY = "VALIDATION_DOSSIER_DIRTY"

DOSSIER_STATUSES = {
    VALIDATION_DOSSIER_READY,
    VALIDATION_DOSSIER_FAIL,
    VALIDATION_DOSSIER_INCOMPLETE,
    VALIDATION_DOSSIER_STALE,
    VALIDATION_DOSSIER_DIRTY,
}

REQUIRED_MANIFEST_SECTIONS = {
    "dossier_manifest_type",
    "dossier_manifest_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "github_remote",
    "github_sync_status",
    "source_phase",
    "dossier_scope",
    "bound_manifest_digest",
    "bound_execution_envelope_digest",
    "bound_evidence_chain_digest",
    "bound_regression_matrix_digest",
    "bound_constitutional_gates_digest",
    "bound_toolchain_guard_digest",
    "bound_capstone_digest",
    "bound_release_integrity_digest",
    "bound_adversarial_harness_digest",
    "claims_to_evidence_reference",
    "validation_questions_reference",
    "evidence_artifact_index_reference",
    "scope_and_exclusions_reference",
    "reviewer_commands_reference",
    "dossier_payload_digest",
    "dossier_digest",
    "dossier_signature",
    "signature_mode",
    "dossier_status",
    "validation_failures",
}

REQUIRED_CLAIM_FIELDS = {
    "claim_id",
    "claim_text",
    "claim_category",
    "claim_scope",
    "claim_status",
    "supporting_evidence_artifacts",
    "supporting_verification_commands",
    "expected_validation_answer",
    "reviewer_validation_question",
    "exclusions",
    "notes",
}

REQUIRED_QUESTION_FIELDS = {
    "question_id",
    "question_text",
    "related_claim_ids",
    "evidence_artifacts",
    "verification_commands",
    "expected_answer",
    "reviewer_notes",
}

REQUIRED_ARTIFACT_FIELDS = {
    "artifact_id",
    "artifact_group",
    "path",
    "exists",
    "size_bytes",
    "sha256",
    "required",
    "related_claim_ids",
    "reason",
}

REQUIRED_COMMAND_FIELDS = {
    "command_id",
    "command",
    "purpose",
    "expected_result",
    "required",
    "related_claim_ids",
}

REQUIRED_EVIDENCE_PATHS = {
    "outputs/local_trust_root_manifest.json",
    "outputs/local_execution_environment_trust_envelope.json",
    "outputs/local_evidence_chain.json",
    "outputs/local_trust_regression_matrix.json",
    "outputs/local_constitutional_gates.json",
    "outputs/local_toolchain_guard.json",
    "outputs/local_trust_25_year_capstone.json",
    "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
    "outputs/release_integrity_bundle/ARTIFACT_HASH_INDEX.json",
    "outputs/release_integrity_bundle/VERIFICATION_COMMANDS.json",
    "outputs/release_integrity_bundle/CLAIMS_TO_EVIDENCE_SEED.json",
    "outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json",
    "outputs/adversarial_local_trust_negative_harness.json",
    "reports/PHASE_18_8B_REPOSITORY_HARDENING_INSPECTION_MAP.md",
    "reports/PHASE_18_8B_EXTERNAL_PRODUCTION_READINESS_GAP_REPORT.md",
    "reports/PHASE_18_8B_MAXIMUM_REPOSITORY_HARDENING_BASELINE_REPORT.md",
    "docs/canonical_blueprint_series/00_CANONICAL_BLUEPRINT_SERIES_INDEX.md",
    "docs/canonical_blueprint_series/BLUEPRINT_SOURCE_AND_SUPERSESSION_MAP.md",
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


def validate_dossier_manifest(
    manifest: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    claims_index: Mapping[str, Any] | None = None,
    validation_questions: Mapping[str, Any] | None = None,
    evidence_artifact_index: Mapping[str, Any] | None = None,
    scope_lock: Mapping[str, Any] | None = None,
    reviewer_commands: Mapping[str, Any] | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.dossier_manifest import (
        DOSSIER_SIGNATURE_MODE,
        dossier_digest_for,
        dossier_signature_for,
        hash_dossier_payload,
    )
    from sbp_lex.local_trust.manifest import canonicalise_manifest

    failures: list[str] = []
    if not isinstance(manifest, Mapping):
        return {"dossier_status": VALIDATION_DOSSIER_FAIL, "validation_failures": ["dossier_manifest_not_mapping"]}

    missing = sorted(REQUIRED_MANIFEST_SECTIONS - set(manifest))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"dossier_status": VALIDATION_DOSSIER_INCOMPLETE, "validation_failures": failures}

    if manifest.get("dossier_manifest_type") != "university_validation_dossier_manifest":
        failures.append("invalid_dossier_manifest_type")
    if manifest.get("dossier_manifest_version") != "18.8":
        failures.append("invalid_dossier_manifest_version")
    if manifest.get("source_phase") != "18.8":
        failures.append("invalid_source_phase")
    if manifest.get("signature_mode") != DOSSIER_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if manifest.get("dossier_status") not in DOSSIER_STATUSES:
        failures.append("invalid_dossier_status")

    failures.extend(_digest_binding_failures(manifest))
    failures.extend(_file_reference_failures(manifest, repository_root))
    failures.extend(_claims_failures(claims_index))
    failures.extend(_questions_failures(validation_questions, claims_index, reviewer_commands))
    failures.extend(_artifact_index_failures(evidence_artifact_index, repository_root))
    failures.extend(_scope_lock_failures(scope_lock))
    failures.extend(_reviewer_command_failures(reviewer_commands, claims_index))
    failures.extend(_forbidden_failures(manifest))

    try:
        canonicalise_manifest(manifest)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload = hash_dossier_payload(manifest)
    if not hmac.compare_digest(str(manifest.get("dossier_payload_digest")), expected_payload):
        failures.append("dossier_payload_digest_mismatch")

    expected_signature = dossier_signature_for(expected_payload)
    if not hmac.compare_digest(str(manifest.get("dossier_signature")), expected_signature):
        failures.append("dossier_signature_mismatch")

    expected_digest = dossier_digest_for(expected_payload, expected_signature)
    if not hmac.compare_digest(str(manifest.get("dossier_digest")), expected_digest):
        failures.append("dossier_digest_mismatch")

    if failures:
        incomplete_markers = (
            "missing_required_section:",
            "missing_required_claim:",
            "missing_required_question:",
            "missing_required_evidence_path:",
            "missing_required_command:",
            "artifact_missing:",
            "dossier_reference_missing:",
        )
        status = (
            VALIDATION_DOSSIER_INCOMPLETE
            if any(any(failure.startswith(marker) for marker in incomplete_markers) for failure in failures)
            else VALIDATION_DOSSIER_FAIL
        )
        return {"dossier_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        if current_commit and manifest.get("git_commit") != current_commit:
            return {"dossier_status": VALIDATION_DOSSIER_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and manifest.get("github_sync_status", {}).get("tracked_working_tree_clean") is not True:
        return {"dossier_status": VALIDATION_DOSSIER_DIRTY, "validation_failures": ["working_tree_dirty"]}

    return {"dossier_status": VALIDATION_DOSSIER_READY, "validation_failures": []}


def _digest_binding_failures(manifest: Mapping[str, Any]) -> list[str]:
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
        "bound_adversarial_harness_digest",
    ):
        if len(str(manifest.get(field))) != 64:
            failures.append(f"bound_digest_invalid:{field}")
    return failures


def _file_reference_failures(manifest: Mapping[str, Any], repository_root: Path | None) -> list[str]:
    if repository_root is None:
        return []
    failures: list[str] = []
    for key in (
        "claims_to_evidence_reference",
        "validation_questions_reference",
        "evidence_artifact_index_reference",
        "scope_and_exclusions_reference",
        "reviewer_commands_reference",
        "handoff_readme_reference",
    ):
        reference = manifest.get(key)
        if reference is None and key == "handoff_readme_reference":
            continue
        if not isinstance(reference, Mapping):
            failures.append(f"dossier_reference_not_mapping:{key}")
            continue
        path_text = str(reference.get("path"))
        candidate = Path(path_text)
        path = candidate if candidate.is_absolute() else repository_root / candidate
        if not path.exists() or not path.is_file():
            failures.append(f"dossier_reference_missing:{key}")
            continue
        if reference.get("exists") is not True:
            failures.append(f"dossier_reference_exists_flag_false:{key}")
        if reference.get("size_bytes") != path.stat().st_size:
            failures.append(f"dossier_reference_size_mismatch:{key}")
        if reference.get("sha256") != file_sha256(path):
            failures.append(f"dossier_reference_hash_mismatch:{key}")
    return failures


def _claims_failures(index: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(index, Mapping):
        return ["claims_index_not_mapping"]
    claims = index.get("claims")
    if not isinstance(claims, list):
        return ["claims_not_list"]
    failures: list[str] = []
    seen: set[str] = set()
    for claim in claims:
        if not isinstance(claim, Mapping):
            failures.append("claim_not_mapping")
            continue
        missing = sorted(REQUIRED_CLAIM_FIELDS - set(claim))
        failures.extend(f"claim_missing_field:{claim.get('claim_id')}:{field}" for field in missing)
        claim_id = str(claim.get("claim_id"))
        seen.add(claim_id)
        if claim.get("claim_status") not in CLAIM_STATUSES:
            failures.append(f"claim_invalid_status:{claim_id}")
        failures.extend(_false_claim_failures(claim, f"claim:{claim_id}"))
    for claim_id in sorted(required_claim_ids() - seen):
        failures.append(f"missing_required_claim:{claim_id}")
    return failures


def _questions_failures(
    questions_index: Mapping[str, Any] | None,
    claims_index: Mapping[str, Any] | None,
    commands_index: Mapping[str, Any] | None,
) -> list[str]:
    if not isinstance(questions_index, Mapping):
        return ["validation_questions_not_mapping"]
    questions = questions_index.get("questions")
    if not isinstance(questions, list):
        return ["validation_questions_not_list"]
    claim_ids = _claim_ids(claims_index)
    command_ids = _command_ids(commands_index)
    failures: list[str] = []
    seen: set[str] = set()
    for question in questions:
        if not isinstance(question, Mapping):
            failures.append("validation_question_not_mapping")
            continue
        missing = sorted(REQUIRED_QUESTION_FIELDS - set(question))
        failures.extend(f"validation_question_missing_field:{question.get('question_id')}:{field}" for field in missing)
        question_id = str(question.get("question_id"))
        seen.add(question_id)
        for claim_id in question.get("related_claim_ids", []):
            if str(claim_id) not in claim_ids:
                failures.append(f"validation_question_unknown_claim:{question_id}:{claim_id}")
        for command_id in question.get("verification_commands", []):
            if str(command_id) not in command_ids:
                failures.append(f"validation_question_unknown_command:{question_id}:{command_id}")
    for question_id in sorted(required_validation_question_ids() - seen):
        failures.append(f"missing_required_question:{question_id}")
    return failures


def _artifact_index_failures(index: Mapping[str, Any] | None, repository_root: Path | None) -> list[str]:
    if not isinstance(index, Mapping):
        return ["evidence_artifact_index_not_mapping"]
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list):
        return ["evidence_artifacts_not_list"]
    failures: list[str] = []
    seen_paths: set[str] = set()
    required = [artifact for artifact in artifacts if isinstance(artifact, Mapping) and artifact.get("required") is True]
    missing = [artifact for artifact in required if artifact.get("exists") is not True]
    summary = index.get("artifact_summary", {})
    if isinstance(summary, Mapping):
        if summary.get("evidence_artifact_count") != len(artifacts):
            failures.append("evidence_artifact_count_mismatch")
        if summary.get("required_artifact_count") != len(required):
            failures.append("required_artifact_count_mismatch")
        if summary.get("missing_artifact_count") != len(missing):
            failures.append("missing_artifact_count_mismatch")
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            failures.append("evidence_artifact_not_mapping")
            continue
        missing_fields = sorted(REQUIRED_ARTIFACT_FIELDS - set(artifact))
        failures.extend(f"evidence_artifact_missing_field:{artifact.get('artifact_id')}:{field}" for field in missing_fields)
        path_text = str(artifact.get("path"))
        seen_paths.add(path_text)
        if artifact.get("required") is True and artifact.get("exists") is not True:
            failures.append(f"artifact_missing:{artifact.get('artifact_id')}")
        if repository_root is not None and artifact.get("exists") is True:
            candidate = Path(path_text)
            path = candidate if candidate.is_absolute() else repository_root / candidate
            if not path.exists() or not path.is_file():
                failures.append(f"artifact_missing_on_disk:{artifact.get('artifact_id')}")
            else:
                if artifact.get("size_bytes") != path.stat().st_size:
                    failures.append(f"artifact_size_mismatch:{artifact.get('artifact_id')}")
                if artifact.get("sha256") != file_sha256(path):
                    failures.append(f"artifact_hash_mismatch:{artifact.get('artifact_id')}")
    missing_paths = sorted(REQUIRED_EVIDENCE_PATHS - seen_paths)
    failures.extend(f"missing_required_evidence_path:{path}" for path in missing_paths)
    return failures


def _scope_lock_failures(lock: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(lock, Mapping):
        return ["scope_lock_not_mapping"]
    failures: list[str] = []
    required_true = (
        "review_readiness_only",
        "not_production_certification",
        "not_university_validation_result",
        "not_legal_advice",
        "not_patent_validity_confirmation",
        "not_security_certification",
        "not_government_approval",
        "notRuntimeActivation",
        "not_phase_19",
        "not_multi_node_implementation",
        "not_active_future_distributed_or_mobile_implementation",
        "not_external_skg_dtn_runtime_deployment",
        "not_cloud_implementation",
        "not_apk_implementation",
        "not_v2_or_v3_implementation",
        "runtime_authority_rebuilt_for_eie_pt_alignment",
        "governance_unchanged",
        "procedural_truth_rebuilt_to_evidentiary_sufficiency",
        "execution_gate_updated_for_pt_certification",
        "hard_entry_gate_unchanged",
        "skg_dtn_pt_aware_non_authoritative",
        "eie_canonical_traversal_state",
        "root_of_trust_anchorage_expanded",
        "phase_18_8b_repository_hardening_complete",
        "canonical_blueprint_series_current",
        "external_production_gap_reported",
        "phase_19_not_started",
    )
    for key in required_true:
        if lock.get(key) is not True:
            failures.append(f"scope_lock_not_true:{key}")
    next_phase = lock.get("next_phase")
    if not isinstance(next_phase, Mapping):
        failures.append("next_phase_not_mapping")
    else:
        if next_phase.get("phase_id") != "18.9":
            failures.append("next_phase_not_18_9")
        if next_phase.get("readiness_marker_only") is not True:
            failures.append("next_phase_readiness_marker_not_true")
        if next_phase.get("implemented_in_this_phase") is not False:
            failures.append("next_phase_implemented_inside_phase")
    return failures


def _reviewer_command_failures(commands_index: Mapping[str, Any] | None, claims_index: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(commands_index, Mapping):
        return ["reviewer_commands_not_mapping"]
    commands = commands_index.get("commands")
    if not isinstance(commands, list):
        return ["reviewer_commands_not_list"]
    claim_ids = _claim_ids(claims_index)
    failures: list[str] = []
    seen: set[str] = set()
    for command in commands:
        if not isinstance(command, Mapping):
            failures.append("reviewer_command_not_mapping")
            continue
        missing = sorted(REQUIRED_COMMAND_FIELDS - set(command))
        failures.extend(f"reviewer_command_missing_field:{command.get('command_id')}:{field}" for field in missing)
        command_id = str(command.get("command_id"))
        seen.add(command_id)
        if command.get("required") is not True:
            failures.append(f"reviewer_command_not_required:{command_id}")
        for claim_id in command.get("related_claim_ids", []):
            if str(claim_id) not in claim_ids:
                failures.append(f"reviewer_command_unknown_claim:{command_id}:{claim_id}")
    for command_id in sorted(required_reviewer_command_ids() - seen):
        failures.append(f"missing_required_command:{command_id}")
    return failures


def _claim_ids(index: Mapping[str, Any] | None) -> set[str]:
    if not isinstance(index, Mapping) or not isinstance(index.get("claims"), list):
        return set()
    return {str(claim.get("claim_id")) for claim in index.get("claims", []) if isinstance(claim, Mapping)}


def _command_ids(index: Mapping[str, Any] | None) -> set[str]:
    if not isinstance(index, Mapping) or not isinstance(index.get("commands"), list):
        return set()
    return {str(command.get("command_id")) for command in index.get("commands", []) if isinstance(command, Mapping)}


def _false_claim_failures(value: Any, path: str) -> list[str]:
    failures: list[str] = []
    false_markers = (
        "validation has occurred",
        "validated by a university",
        "certification has occurred",
        "certified by",
        "production deployment readiness",
        "production-grade readiness",
        "external certification",
        "safety-critical operational approval",
        "formal university validation",
    )
    if isinstance(value, Mapping):
        for key, item in value.items():
            failures.extend(_false_claim_failures(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_false_claim_failures(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        lower = value.lower()
        for marker in false_markers:
            if marker in lower and f"not {marker}" not in lower and f"no {marker}" not in lower:
                failures.append(f"false_validation_or_certification_claim:{path}:{marker}")
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
