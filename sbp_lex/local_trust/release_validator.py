from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any, Mapping

from sbp_lex.local_trust.claims_seed import required_claim_ids, required_command_ids
from sbp_lex.local_trust.git_provenance import current_git_commit
from sbp_lex.local_trust.release_hash_index import artifact_by_path, file_sha256

RELEASE_INTEGRITY_PASS = "RELEASE_INTEGRITY_PASS"
RELEASE_INTEGRITY_FAIL = "RELEASE_INTEGRITY_FAIL"
RELEASE_INTEGRITY_INCOMPLETE = "RELEASE_INTEGRITY_INCOMPLETE"
RELEASE_INTEGRITY_STALE = "RELEASE_INTEGRITY_STALE"
RELEASE_INTEGRITY_DIRTY = "RELEASE_INTEGRITY_DIRTY"

RELEASE_STATUSES = {
    RELEASE_INTEGRITY_PASS,
    RELEASE_INTEGRITY_FAIL,
    RELEASE_INTEGRITY_INCOMPLETE,
    RELEASE_INTEGRITY_STALE,
    RELEASE_INTEGRITY_DIRTY,
}

REQUIRED_MANIFEST_SECTIONS = {
    "release_manifest_type",
    "release_manifest_version",
    "created_at",
    "repository_root",
    "git_commit",
    "git_branch",
    "github_remote",
    "github_sync_status",
    "release_scope",
    "source_phase",
    "completed_local_trust_phases",
    "bound_manifest_digest",
    "bound_execution_envelope_digest",
    "bound_evidence_chain_digest",
    "bound_regression_matrix_digest",
    "bound_constitutional_gates_digest",
    "bound_toolchain_guard_digest",
    "bound_capstone_digest",
    "release_artifacts",
    "verification_commands_reference",
    "claims_to_evidence_seed_reference",
    "boundary_lock_reference",
    "release_payload_digest",
    "release_digest",
    "release_signature",
    "signature_mode",
    "release_status",
    "validation_failures",
}

REQUIRED_LOCAL_TRUST_PHASES = {"18.7D.1", "18.7E.1", "18.7E.2", "18.7E.3", "18.7E.4"}


def validate_release_manifest(
    manifest: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    artifact_hash_index: Mapping[str, Any] | None = None,
    verification_commands: Mapping[str, Any] | None = None,
    claims_to_evidence_seed: Mapping[str, Any] | None = None,
    boundary_lock: Mapping[str, Any] | None = None,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    from sbp_lex.local_trust.manifest import canonicalise_manifest
    from sbp_lex.local_trust.release_manifest import (
        RELEASE_INTEGRITY_SIGNATURE_MODE,
        hash_release_payload,
        release_digest_for,
        release_signature_for,
    )

    failures: list[str] = []
    if not isinstance(manifest, Mapping):
        return {"release_status": RELEASE_INTEGRITY_FAIL, "validation_failures": ["release_manifest_not_mapping"]}

    missing = sorted(REQUIRED_MANIFEST_SECTIONS - set(manifest))
    if missing:
        failures.extend(f"missing_required_section:{section}" for section in missing)
        return {"release_status": RELEASE_INTEGRITY_INCOMPLETE, "validation_failures": failures}

    if manifest.get("release_manifest_type") != "release_integrity_reproducible_validation_bundle":
        failures.append("invalid_release_manifest_type")
    if manifest.get("release_manifest_version") != "18.7F":
        failures.append("invalid_release_manifest_version")
    if manifest.get("source_phase") != "18.7F":
        failures.append("invalid_source_phase")
    if manifest.get("signature_mode") != RELEASE_INTEGRITY_SIGNATURE_MODE:
        failures.append("invalid_signature_mode")
    if manifest.get("release_status") not in RELEASE_STATUSES:
        failures.append("invalid_release_status")

    failures.extend(_digest_binding_failures(manifest))
    failures.extend(_phase_failures(manifest.get("completed_local_trust_phases")))
    failures.extend(_release_artifact_reference_failures(manifest, repository_root))
    failures.extend(_artifact_hash_index_failures(artifact_hash_index, repository_root))
    failures.extend(_verification_command_failures(verification_commands))
    failures.extend(_claims_seed_failures(claims_to_evidence_seed, verification_commands))
    failures.extend(_boundary_lock_failures(boundary_lock))

    try:
        canonicalise_manifest(manifest)
    except (TypeError, ValueError) as exc:
        failures.append(f"canonicalisation_failed:{exc}")

    expected_payload_digest = hash_release_payload(manifest)
    if not hmac.compare_digest(str(manifest.get("release_payload_digest")), expected_payload_digest):
        failures.append("release_payload_digest_mismatch")

    expected_signature = release_signature_for(expected_payload_digest)
    if not hmac.compare_digest(str(manifest.get("release_signature")), expected_signature):
        failures.append("release_signature_mismatch")

    expected_digest = release_digest_for(expected_payload_digest, expected_signature)
    if not hmac.compare_digest(str(manifest.get("release_digest")), expected_digest):
        failures.append("release_digest_mismatch")

    if failures:
        incomplete_markers = (
            "missing_required_section:",
            "missing_required_artifact:",
            "artifact_missing:",
            "missing_required_command:",
            "missing_required_claim:",
            "bundle_reference_missing:",
        )
        status = (
            RELEASE_INTEGRITY_INCOMPLETE
            if any(any(failure.startswith(marker) for marker in incomplete_markers) for failure in failures)
            else RELEASE_INTEGRITY_FAIL
        )
        return {"release_status": status, "validation_failures": sorted(set(failures))}

    if current_validation and repository_root is not None:
        current_commit = current_git_commit(repository_root)
        if current_commit and manifest.get("git_commit") != current_commit:
            return {"release_status": RELEASE_INTEGRITY_STALE, "validation_failures": ["git_commit_stale"]}

    if clean_required and manifest.get("github_sync_status", {}).get("tracked_working_tree_clean") is not True:
        return {"release_status": RELEASE_INTEGRITY_DIRTY, "validation_failures": ["working_tree_dirty"]}

    return {"release_status": RELEASE_INTEGRITY_PASS, "validation_failures": []}


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
    ):
        digest = str(manifest.get(field))
        if len(digest) != 64:
            failures.append(f"bound_digest_invalid:{field}")
    return failures


def _phase_failures(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["completed_local_trust_phases_not_list"]
    seen = {str(item) for item in value}
    return [f"missing_required_phase:{phase_id}" for phase_id in sorted(REQUIRED_LOCAL_TRUST_PHASES - seen)]


def _release_artifact_reference_failures(manifest: Mapping[str, Any], repository_root: Path | None) -> list[str]:
    if repository_root is None:
        return []
    failures: list[str] = []
    references: list[Any] = []
    for key in (
        "release_artifacts",
        "verification_commands_reference",
        "claims_to_evidence_seed_reference",
        "boundary_lock_reference",
        "artifact_hash_index_reference",
    ):
        value = manifest.get(key)
        if isinstance(value, list):
            references.extend(value)
        else:
            references.append(value)
    for reference in references:
        if not isinstance(reference, Mapping):
            failures.append("bundle_reference_not_mapping")
            continue
        path_text = str(reference.get("path"))
        candidate = Path(path_text)
        path = candidate if candidate.is_absolute() else repository_root / candidate
        if not path.exists() or not path.is_file():
            failures.append(f"bundle_reference_missing:{path_text}")
            continue
        if reference.get("exists") is not True:
            failures.append(f"bundle_reference_exists_flag_false:{path_text}")
        if reference.get("size_bytes") != path.stat().st_size:
            failures.append(f"bundle_reference_size_mismatch:{path_text}")
        if reference.get("sha256") != file_sha256(path):
            failures.append(f"bundle_reference_hash_mismatch:{path_text}")
    return failures


def _artifact_hash_index_failures(index: Mapping[str, Any] | None, repository_root: Path | None) -> list[str]:
    if not isinstance(index, Mapping):
        return ["artifact_hash_index_not_mapping"]
    if index.get("artifact_hash_index_type") != "release_integrity_artifact_hash_index":
        return ["invalid_artifact_hash_index_type"]
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list):
        return ["artifact_hash_index_artifacts_not_list"]
    failures: list[str] = []
    summary = index.get("artifact_summary", {})
    required = [artifact for artifact in artifacts if isinstance(artifact, Mapping) and artifact.get("required") is True]
    missing = [artifact for artifact in required if artifact.get("exists") is not True]
    if isinstance(summary, Mapping):
        if summary.get("artifact_count") != len(artifacts):
            failures.append("artifact_count_mismatch")
        if summary.get("required_artifact_count") != len(required):
            failures.append("required_artifact_count_mismatch")
        if summary.get("missing_artifact_count") != len(missing):
            failures.append("missing_artifact_count_mismatch")
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            failures.append("artifact_entry_not_mapping")
            continue
        artifact_id = str(artifact.get("artifact_id"))
        if artifact.get("required") is True and artifact.get("exists") is not True:
            failures.append(f"artifact_missing:{artifact_id}")
        if repository_root is not None and artifact.get("exists") is True:
            path_text = str(artifact.get("path"))
            candidate = Path(path_text)
            path = candidate if candidate.is_absolute() else repository_root / candidate
            if not path.exists() or not path.is_file():
                failures.append(f"artifact_missing_on_disk:{artifact_id}")
            else:
                if artifact.get("size_bytes") != path.stat().st_size:
                    failures.append(f"artifact_size_mismatch:{artifact_id}")
                if artifact.get("sha256") != file_sha256(path):
                    failures.append(f"artifact_hash_mismatch:{artifact_id}")
    paths = artifact_by_path(index)
    for required_path in (
        "outputs/local_trust_root_manifest.json",
        "outputs/local_execution_environment_trust_envelope.json",
        "outputs/local_evidence_chain.json",
        "outputs/local_trust_regression_matrix.json",
        "outputs/local_constitutional_gates.json",
        "outputs/local_toolchain_guard.json",
        "outputs/local_trust_25_year_capstone.json",
    ):
        if required_path not in paths:
            failures.append(f"missing_required_artifact_path:{required_path}")
    return failures


def _verification_command_failures(commands_index: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(commands_index, Mapping):
        return ["verification_commands_not_mapping"]
    commands = commands_index.get("commands")
    if not isinstance(commands, list):
        return ["verification_commands_not_list"]
    seen = {str(command.get("command_id")) for command in commands if isinstance(command, Mapping)}
    failures = [f"missing_required_command:{command_id}" for command_id in sorted(required_command_ids() - seen)]
    for command in commands:
        if not isinstance(command, Mapping):
            failures.append("verification_command_entry_not_mapping")
            continue
        for field in ("command_id", "command", "purpose", "expected_result", "required"):
            if field not in command:
                failures.append(f"verification_command_missing_field:{field}")
    return failures


def _claims_seed_failures(seed: Mapping[str, Any] | None, commands_index: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(seed, Mapping):
        return ["claims_seed_not_mapping"]
    claims = seed.get("claim_seeds")
    if not isinstance(claims, list):
        return ["claim_seeds_not_list"]
    command_ids: set[str] = set()
    if isinstance(commands_index, Mapping) and isinstance(commands_index.get("commands"), list):
        command_ids = {
            str(command.get("command_id"))
            for command in commands_index.get("commands", [])
            if isinstance(command, Mapping)
        }
    seen = {str(claim.get("claim_id")) for claim in claims if isinstance(claim, Mapping)}
    failures = [f"missing_required_claim:{claim_id}" for claim_id in sorted(required_claim_ids() - seen)]
    for claim in claims:
        if not isinstance(claim, Mapping):
            failures.append("claim_seed_entry_not_mapping")
            continue
        for field in ("claim_id", "claim_text", "claim_scope", "evidence_artifacts", "verification_commands", "status", "notes"):
            if field not in claim:
                failures.append(f"claim_seed_missing_field:{field}")
        if claim.get("status") not in {"CLAIM_SEED_READY", "CLAIM_SEED_INCOMPLETE"}:
            failures.append(f"claim_seed_invalid_status:{claim.get('claim_id')}")
        for command_id in claim.get("verification_commands", []):
            if str(command_id) not in command_ids:
                failures.append(f"claim_seed_unknown_command:{claim.get('claim_id')}:{command_id}")
    return failures


def _boundary_lock_failures(lock: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(lock, Mapping):
        return ["boundary_lock_not_mapping"]
    failures: list[str] = []
    required_true = (
        "review_readiness_only",
        "not_production_certification",
        "not_university_validation_result",
        "not_legal_advice",
        "not_patent_validity_confirmation",
        "not_security_certification",
        "notRuntimeActivation",
        "not_phase_19",
        "not_skg_dtn_implementation",
        "not_future_distributed_or_mobile_runtime_implementation",
        "runtime_authority_unchanged",
        "governance_unchanged",
        "procedural_truth_unchanged",
        "execution_gate_unchanged",
        "hard_entry_gate_unchanged",
        "skg_dtn_external_non_authoritative",
        "phase_19_not_started",
    )
    for key in required_true:
        if lock.get(key) is not True:
            failures.append(f"boundary_lock_not_true:{key}")
    next_phase = lock.get("next_phase")
    if not isinstance(next_phase, Mapping):
        failures.append("next_phase_not_mapping")
    else:
        if next_phase.get("phase_id") != "18.7G":
            failures.append("next_phase_not_18_7g")
        if next_phase.get("readiness_marker_only") is not True:
            failures.append("next_phase_readiness_marker_not_true")
        if next_phase.get("implemented_in_this_phase") is not False:
            failures.append("next_phase_implemented_inside_phase")
    return failures
