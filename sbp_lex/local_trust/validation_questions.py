from __future__ import annotations

from typing import Any, Mapping


def validation_questions_index() -> dict[str, Any]:
    questions = [_question_record(spec) for spec in REQUIRED_VALIDATION_QUESTION_SPECS]
    return {
        "validation_questions_type": "university_validation_questions",
        "validation_questions_version": "18.8",
        "questions": questions,
        "question_summary": {
            "validation_question_count": len(questions),
            "required_question_count": len(questions),
        },
    }


def required_validation_question_ids() -> set[str]:
    return {str(spec["question_id"]) for spec in REQUIRED_VALIDATION_QUESTION_SPECS}


def _question_record(spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "question_id": spec["question_id"],
        "question_text": spec["question_text"],
        "related_claim_ids": list(spec["related_claim_ids"]),
        "evidence_artifacts": list(spec["evidence_artifacts"]),
        "verification_commands": list(spec["verification_commands"]),
        "expected_answer": spec["expected_answer"],
        "reviewer_notes": spec["reviewer_notes"],
    }


REQUIRED_VALIDATION_QUESTION_SPECS: tuple[dict[str, Any], ...] = (
    {
        "question_id": "confirm_release_package_binds_repo_state",
        "question_text": "Can the reviewer confirm the release package binds the stated repository state?",
        "related_claim_ids": ["release_integrity_passes"],
        "evidence_artifacts": ["outputs/release_integrity_bundle/RELEASE_MANIFEST.json"],
        "verification_commands": ["release_integrity_validate", "git_status_short_branch"],
        "expected_answer": "Yes, if the release manifest digest and repository status match the dossier.",
        "reviewer_notes": "Record any stale or dirty state separately.",
    },
    {
        "question_id": "confirm_required_local_trust_artifacts_validate",
        "question_text": "Can the reviewer confirm all required local trust artifacts exist and validate?",
        "related_claim_ids": [
            "local_trust_manifest_validates",
            "execution_envelope_validates",
            "evidence_chain_validates",
            "regression_matrix_validates",
            "constitutional_gates_pass",
            "toolchain_guard_passes",
            "local_trust_capstone_passes",
        ],
        "evidence_artifacts": [
            "outputs/local_trust_root_manifest.json",
            "outputs/local_execution_environment_trust_envelope.json",
            "outputs/local_evidence_chain.json",
            "outputs/local_trust_regression_matrix.json",
            "outputs/local_constitutional_gates.json",
            "outputs/local_toolchain_guard.json",
            "outputs/local_trust_25_year_capstone.json",
        ],
        "verification_commands": [
            "manifest_validate",
            "execution_envelope_validate",
            "evidence_chain_validate",
            "regression_matrix_validate",
            "constitutional_gates_validate",
            "toolchain_guard_validate",
            "capstone_validate",
        ],
        "expected_answer": "Yes, if all validators return their expected pass statuses.",
        "reviewer_notes": "A missing or stale artifact should narrow or reject the related claim.",
    },
    {
        "question_id": "confirm_evidence_chain_zero_missing",
        "question_text": "Can the reviewer confirm the evidence chain has zero missing evidence?",
        "related_claim_ids": ["evidence_chain_zero_missing"],
        "evidence_artifacts": ["outputs/local_evidence_chain.json"],
        "verification_commands": ["evidence_chain_validate"],
        "expected_answer": "Yes, if the chain records no missing required evidence.",
        "reviewer_notes": "Check the evidence item summary and missing item list.",
    },
    {
        "question_id": "confirm_evidence_chain_zero_changed",
        "question_text": "Can the reviewer confirm evidence chain compare reports zero changed items?",
        "related_claim_ids": ["evidence_chain_zero_changed"],
        "evidence_artifacts": ["outputs/local_evidence_chain.json"],
        "verification_commands": ["evidence_chain_compare"],
        "expected_answer": "Yes, if compare reports changed_evidence_items=0.",
        "reviewer_notes": "This is current-checkout evidence.",
    },
    {
        "question_id": "confirm_regression_matrix_drift_checks",
        "question_text": "Can the reviewer confirm the regression matrix validates and contains drift-risk checks?",
        "related_claim_ids": ["regression_matrix_validates", "regression_matrix_detects_drift"],
        "evidence_artifacts": ["outputs/local_trust_regression_matrix.json"],
        "verification_commands": ["regression_matrix_validate", "regression_matrix_show"],
        "expected_answer": "Yes, if the matrix validates and lists the required checks.",
        "reviewer_notes": "The matrix is not exhaustive security certification.",
    },
    {
        "question_id": "confirm_constitutional_gates_pass_and_block_unclean",
        "question_text": "Can the reviewer confirm constitutional gates pass and block unclean states?",
        "related_claim_ids": ["constitutional_gates_pass", "constitutional_gates_block_unclean_states"],
        "evidence_artifacts": ["outputs/local_constitutional_gates.json"],
        "verification_commands": ["constitutional_gates_evaluate", "constitutional_gates_validate", "constitutional_gates_show"],
        "expected_answer": "Yes, if gates validate and required gate cases are present.",
        "reviewer_notes": "Constitutional gates are local trust pre-flight guardrails.",
    },
    {
        "question_id": "confirm_toolchain_guard_assumptions",
        "question_text": "Can the reviewer confirm the toolchain guard records Python, pytest, dependency, and command assumptions?",
        "related_claim_ids": ["toolchain_guard_passes", "toolchain_guard_records_assumptions"],
        "evidence_artifacts": ["outputs/local_toolchain_guard.json"],
        "verification_commands": ["toolchain_guard_build", "toolchain_guard_validate", "toolchain_guard_show"],
        "expected_answer": "Yes, if toolchain guard output contains the expected environment and policy records.",
        "reviewer_notes": "Dependency state is local to the recorded environment.",
    },
    {
        "question_id": "confirm_capstone_binds_artifact_set",
        "question_text": "Can the reviewer confirm the capstone binds the local trust artifact set?",
        "related_claim_ids": ["local_trust_capstone_passes"],
        "evidence_artifacts": ["outputs/local_trust_25_year_capstone.json"],
        "verification_commands": ["capstone_build", "capstone_validate", "capstone_show"],
        "expected_answer": "Yes, if capstone validates and bound digests match the dossier.",
        "reviewer_notes": "Capstone is local trust completion evidence.",
    },
    {
        "question_id": "confirm_release_integrity_bundle_validates",
        "question_text": "Can the reviewer confirm the release integrity bundle validates?",
        "related_claim_ids": ["release_integrity_passes", "release_integrity_contains_required_files"],
        "evidence_artifacts": [
            "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
            "outputs/release_integrity_bundle/ARTIFACT_HASH_INDEX.json",
        ],
        "verification_commands": ["release_integrity_build", "release_integrity_validate", "release_integrity_show"],
        "expected_answer": "Yes, if release integrity returns RELEASE_INTEGRITY_PASS.",
        "reviewer_notes": "Release integrity is review readiness evidence only.",
    },
    {
        "question_id": "confirm_adversarial_negative_tests_detect_bad_states",
        "question_text": "Can the reviewer confirm adversarial negative tests detect tampering/missing/boundary-violation cases?",
        "related_claim_ids": ["adversarial_harness_passes", "adversarial_harness_detects_bad_states"],
        "evidence_artifacts": ["outputs/adversarial_local_trust_negative_harness.json"],
        "verification_commands": ["adversarial_harness_run", "adversarial_harness_validate", "adversarial_harness_show"],
        "expected_answer": "Yes, if adversarial harness validates and all required negative cases pass.",
        "reviewer_notes": "Each passing negative case means the bad state was detected or rejected.",
    },
    {
        "question_id": "confirm_runtime_passes_current_scenario",
        "question_text": "Can the reviewer confirm runtime verification passes in the current tested scenario?",
        "related_claim_ids": ["runtime_verification_passes_current_scenario", "dual_adaptive_deterministic_pipelines_preserved"],
        "evidence_artifacts": ["outputs/local_execution_environment_trust_envelope.json"],
        "verification_commands": ["runtime_main"],
        "expected_answer": "Yes, if runtime command returns the expected pass summary.",
        "reviewer_notes": "Current scenario only.",
    },
    {
        "question_id": "confirm_replay_passes_matched",
        "question_text": "Can the reviewer confirm replay verification passes with matched=true and no mismatches?",
        "related_claim_ids": ["replay_verification_passes_matched", "dual_adaptive_deterministic_pipelines_preserved"],
        "evidence_artifacts": ["outputs/local_execution_environment_trust_envelope.json"],
        "verification_commands": ["runtime_replay"],
        "expected_answer": "Yes, if replay reports matched=true and mismatches=[].",
        "reviewer_notes": "Replay is deterministic evidence for the current scenario.",
    },
    {
        "question_id": "confirm_skg_dtn_external_non_authoritative",
        "question_text": "Can the reviewer confirm SKG/DTN remain external and non-authoritative?",
        "related_claim_ids": ["skg_dtn_external_non_authoritative"],
        "evidence_artifacts": ["outputs/university_validation_dossier/SCOPE_AND_EXCLUSIONS_LOCK.json"],
        "verification_commands": ["validation_dossier_validate"],
        "expected_answer": "Yes, if the scope lock preserves SKG/DTN as external and non-authoritative.",
        "reviewer_notes": "No SKG/DTN authority is added by this dossier.",
    },
    {
        "question_id": "confirm_future_surfaces_absent",
        "question_text": "Can the reviewer confirm no active nodes/quorum/mesh/distributed/cloud/APK/V2/V3 implementation exists in this line?",
        "related_claim_ids": ["future_surfaces_absent"],
        "evidence_artifacts": ["outputs/university_validation_dossier/SCOPE_AND_EXCLUSIONS_LOCK.json"],
        "verification_commands": ["validation_dossier_validate"],
        "expected_answer": "Yes, if scope exclusions and static searches preserve this boundary.",
        "reviewer_notes": "These future surfaces are excluded from this line.",
    },
    {
        "question_id": "confirm_phase_19_not_started",
        "question_text": "Can the reviewer confirm Phase 19 has not begun?",
        "related_claim_ids": ["phase_19_not_started"],
        "evidence_artifacts": ["outputs/university_validation_dossier/SCOPE_AND_EXCLUSIONS_LOCK.json"],
        "verification_commands": ["validation_dossier_validate", "validation_dossier_show"],
        "expected_answer": "Yes, if the scope lock records Phase 19 as not started.",
        "reviewer_notes": "18.9 is the next phase marker only.",
    },
    {
        "question_id": "identify_unsupported_or_overbroad_claims",
        "question_text": "Can the reviewer identify any claims that are unsupported, overbroad, ambiguous, or require narrowing?",
        "related_claim_ids": [
            "desktop_v1_local_runtime_prototype",
            "runtime_authority_unchanged",
            "governance_truth_gates_unchanged",
        ],
        "evidence_artifacts": ["outputs/university_validation_dossier/MASTER_CLAIMS_TO_EVIDENCE_INDEX.json"],
        "verification_commands": ["validation_dossier_validate"],
        "expected_answer": "Reviewer may answer yes with specific claim ids and recommended narrowing.",
        "reviewer_notes": "This question invites reviewer critique rather than a fixed pass answer.",
    },
)
