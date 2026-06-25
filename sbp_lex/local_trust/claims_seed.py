from __future__ import annotations

from typing import Any


RELEASE_VERIFICATION_COMMANDS: tuple[dict[str, Any], ...] = (
    {
        "command_id": "compileall",
        "command": "python -m compileall -q .",
        "purpose": "Compile all Python sources for syntax and import readiness.",
        "expected_result": "PASS",
        "required": True,
    },
    {
        "command_id": "pytest",
        "command": "python -m pytest -q",
        "purpose": "Run the repository test suite.",
        "expected_result": "PASS",
        "required": True,
    },
    {
        "command_id": "run_tests_bat",
        "command": "scripts\\run_tests.bat",
        "purpose": "Run the Windows test wrapper.",
        "expected_result": "PASS",
        "required": True,
    },
    {
        "command_id": "manifest_validate",
        "command": "python -m sbp_lex.local_trust.manifest validate",
        "purpose": "Validate the local trust root manifest.",
        "expected_result": "LOCAL_TRUST_VALID",
        "required": True,
    },
    {
        "command_id": "execution_envelope_validate",
        "command": "python -m sbp_lex.local_trust.execution_envelope validate",
        "purpose": "Validate the local execution environment trust envelope.",
        "expected_result": "EXECUTION_ENV_VALID",
        "required": True,
    },
    {
        "command_id": "evidence_chain_validate",
        "command": "python -m sbp_lex.local_trust.evidence_chain validate",
        "purpose": "Validate the local evidence chain.",
        "expected_result": "EVIDENCE_CHAIN_VALID",
        "required": True,
    },
    {
        "command_id": "evidence_chain_compare",
        "command": "python -m sbp_lex.local_trust.evidence_chain compare",
        "purpose": "Compare evidence-chain hashes against current files.",
        "expected_result": "EVIDENCE_CHAIN_VALID changed_evidence_items=0",
        "required": True,
    },
    {
        "command_id": "regression_matrix_validate",
        "command": "python -m sbp_lex.local_trust.regression_matrix validate",
        "purpose": "Validate the local trust regression matrix.",
        "expected_result": "REGRESSION_MATRIX_VALID",
        "required": True,
    },
    {
        "command_id": "regression_matrix_show",
        "command": "python -m sbp_lex.local_trust.regression_matrix show",
        "purpose": "Show the regression matrix summary.",
        "expected_result": "REGRESSION_MATRIX_VALID",
        "required": True,
    },
    {
        "command_id": "constitutional_gates_evaluate",
        "command": "python -m sbp_lex.local_trust.constitutional_gates evaluate",
        "purpose": "Evaluate local trust constitutional gates.",
        "expected_result": "CONSTITUTIONAL_GATES_PASS",
        "required": True,
    },
    {
        "command_id": "constitutional_gates_validate",
        "command": "python -m sbp_lex.local_trust.constitutional_gates validate",
        "purpose": "Validate constitutional gate output.",
        "expected_result": "CONSTITUTIONAL_GATES_PASS",
        "required": True,
    },
    {
        "command_id": "constitutional_gates_show",
        "command": "python -m sbp_lex.local_trust.constitutional_gates show",
        "purpose": "Show constitutional gate summary.",
        "expected_result": "CONSTITUTIONAL_GATES_PASS",
        "required": True,
    },
    {
        "command_id": "toolchain_guard_build",
        "command": "python -m sbp_lex.local_trust.toolchain_guard build",
        "purpose": "Build the local toolchain guard.",
        "expected_result": "TOOLCHAIN_GUARD_PASS",
        "required": True,
    },
    {
        "command_id": "toolchain_guard_validate",
        "command": "python -m sbp_lex.local_trust.toolchain_guard validate",
        "purpose": "Validate the local toolchain guard.",
        "expected_result": "TOOLCHAIN_GUARD_PASS",
        "required": True,
    },
    {
        "command_id": "toolchain_guard_show",
        "command": "python -m sbp_lex.local_trust.toolchain_guard show",
        "purpose": "Show local toolchain guard summary.",
        "expected_result": "TOOLCHAIN_GUARD_PASS",
        "required": True,
    },
    {
        "command_id": "capstone_build",
        "command": "python -m sbp_lex.local_trust.local_trust_capstone build",
        "purpose": "Build the 25-year local trust capstone.",
        "expected_result": "LOCAL_TRUST_CAPSTONE_PASS",
        "required": True,
    },
    {
        "command_id": "capstone_validate",
        "command": "python -m sbp_lex.local_trust.local_trust_capstone validate",
        "purpose": "Validate the 25-year local trust capstone.",
        "expected_result": "LOCAL_TRUST_CAPSTONE_PASS",
        "required": True,
    },
    {
        "command_id": "capstone_show",
        "command": "python -m sbp_lex.local_trust.local_trust_capstone show",
        "purpose": "Show 25-year capstone summary.",
        "expected_result": "LOCAL_TRUST_CAPSTONE_PASS",
        "required": True,
    },
    {
        "command_id": "release_integrity_build",
        "command": "python -m sbp_lex.local_trust.release_integrity build",
        "purpose": "Build the release integrity bundle.",
        "expected_result": "RELEASE_INTEGRITY_PASS",
        "required": True,
    },
    {
        "command_id": "release_integrity_validate",
        "command": "python -m sbp_lex.local_trust.release_integrity validate",
        "purpose": "Validate the release integrity bundle.",
        "expected_result": "RELEASE_INTEGRITY_PASS",
        "required": True,
    },
    {
        "command_id": "release_integrity_show",
        "command": "python -m sbp_lex.local_trust.release_integrity show",
        "purpose": "Show release integrity bundle summary.",
        "expected_result": "RELEASE_INTEGRITY_PASS",
        "required": True,
    },
    {
        "command_id": "runtime_main",
        "command": "python main.py",
        "purpose": "Run canonical runtime verification.",
        "expected_result": "PASS decision=ALLOW execution_result=EXECUTE",
        "required": True,
    },
    {
        "command_id": "runtime_replay",
        "command": "python main.py replay",
        "purpose": "Run deterministic replay verification.",
        "expected_result": "PASS matched=true mismatches=[]",
        "required": True,
    },
    {
        "command_id": "git_diff_check",
        "command": "git diff --check",
        "purpose": "Check whitespace safety.",
        "expected_result": "PASS",
        "required": True,
    },
    {
        "command_id": "git_status_branch",
        "command": "git status --short --branch --untracked-files=no",
        "purpose": "Record tracked branch status.",
        "expected_result": "tracked changes limited to phase scope before commit",
        "required": True,
    },
)


REQUIRED_CLAIM_SEEDS: tuple[dict[str, Any], ...] = (
    {
        "claim_id": "desktop_v1_local_trust_artifacts_validate",
        "claim_text": "Desktop V1 local trust artifacts exist and validate.",
        "claim_scope": "local trust artifact readiness",
        "evidence_artifacts": [
            "outputs/local_trust_root_manifest.json",
            "outputs/local_execution_environment_trust_envelope.json",
            "outputs/local_trust_25_year_capstone.json",
        ],
        "verification_commands": ["manifest_validate", "execution_envelope_validate", "capstone_validate"],
    },
    {
        "claim_id": "evidence_chain_zero_missing",
        "claim_text": "Evidence chain has zero missing evidence.",
        "claim_scope": "local evidence integrity",
        "evidence_artifacts": ["outputs/local_evidence_chain.json"],
        "verification_commands": ["evidence_chain_validate"],
    },
    {
        "claim_id": "evidence_chain_zero_changed",
        "claim_text": "Evidence chain compare reports zero changed evidence.",
        "claim_scope": "local evidence integrity",
        "evidence_artifacts": ["outputs/local_evidence_chain.json"],
        "verification_commands": ["evidence_chain_compare"],
    },
    {
        "claim_id": "regression_matrix_detects_drift",
        "claim_text": "Regression matrix detects local trust drift risks.",
        "claim_scope": "local trust drift detection",
        "evidence_artifacts": ["outputs/local_trust_regression_matrix.json"],
        "verification_commands": ["regression_matrix_validate", "regression_matrix_show"],
    },
    {
        "claim_id": "constitutional_gates_block_unclean_states",
        "claim_text": "Constitutional gates block unclean local trust states.",
        "claim_scope": "local trust pre-flight guardrails",
        "evidence_artifacts": ["outputs/local_constitutional_gates.json"],
        "verification_commands": ["constitutional_gates_evaluate", "constitutional_gates_validate"],
    },
    {
        "claim_id": "toolchain_guard_records_environment",
        "claim_text": "Toolchain guard records Python, pytest, dependency, command, and ignore-policy assumptions.",
        "claim_scope": "toolchain reproducibility",
        "evidence_artifacts": ["outputs/local_toolchain_guard.json"],
        "verification_commands": ["toolchain_guard_build", "toolchain_guard_validate"],
    },
    {
        "claim_id": "capstone_binds_artifact_set",
        "claim_text": "25-year local trust capstone binds the local trust artifact set.",
        "claim_scope": "local trust completion",
        "evidence_artifacts": ["outputs/local_trust_25_year_capstone.json"],
        "verification_commands": ["capstone_build", "capstone_validate"],
    },
    {
        "claim_id": "skg_dtn_external_non_authoritative",
        "claim_text": "SKG/DTN remain external and non-authoritative.",
        "claim_scope": "authority boundary",
        "evidence_artifacts": ["outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json"],
        "verification_commands": ["release_integrity_validate"],
    },
    {
        "claim_id": "future_surfaces_absent",
        "claim_text": "No active nodes/quorum/mesh/distributed/cloud/APK/V2/V3 work exists in this line.",
        "claim_scope": "future-surface exclusion",
        "evidence_artifacts": ["outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json"],
        "verification_commands": ["release_integrity_validate"],
    },
    {
        "claim_id": "phase_19_not_started",
        "claim_text": "Phase 19 remains not started.",
        "claim_scope": "phase boundary",
        "evidence_artifacts": ["outputs/release_integrity_bundle/BOUNDARY_AND_SCOPE_LOCK.json"],
        "verification_commands": ["release_integrity_validate"],
    },
    {
        "claim_id": "runtime_verification_passes",
        "claim_text": "Runtime verification passes.",
        "claim_scope": "runtime proof reference",
        "evidence_artifacts": ["outputs/local_execution_environment_trust_envelope.json"],
        "verification_commands": ["runtime_main"],
    },
    {
        "claim_id": "replay_verification_passes",
        "claim_text": "Replay verification passes.",
        "claim_scope": "replay proof reference",
        "evidence_artifacts": ["outputs/local_execution_environment_trust_envelope.json"],
        "verification_commands": ["runtime_replay"],
    },
)


def verification_commands_index() -> dict[str, Any]:
    return {
        "verification_commands_type": "release_integrity_verification_commands",
        "verification_commands_version": "18.7F",
        "execution_note": "Release integrity records this command sequence only; it does not execute commands.",
        "commands": [
            {**command, "executed_by_release_integrity": False}
            for command in RELEASE_VERIFICATION_COMMANDS
        ],
    }


def claims_to_evidence_seed() -> dict[str, Any]:
    return {
        "claims_seed_type": "release_integrity_claims_to_evidence_seed",
        "claims_seed_version": "18.7F",
        "scope_note": "Seed index for later claims dossier work; it is not external validation or certification.",
        "claim_seeds": [
            {
                **claim,
                "status": "CLAIM_SEED_READY",
                "notes": "Ready for later dossier expansion; no external validation result is claimed.",
            }
            for claim in REQUIRED_CLAIM_SEEDS
        ],
    }


def boundary_and_scope_lock() -> dict[str, Any]:
    return {
        "boundary_lock_type": "release_integrity_boundary_and_scope_lock",
        "boundary_lock_version": "18.7F",
        "review_readiness_only": True,
        "not_production_certification": True,
        "not_university_validation_result": True,
        "not_legal_advice": True,
        "not_patent_validity_confirmation": True,
        "not_security_certification": True,
        "notRuntimeActivation": True,
        "not_phase_19": True,
        "not_skg_dtn_implementation": True,
        "not_future_distributed_or_mobile_runtime_implementation": True,
        "runtime_authority_unchanged": True,
        "governance_unchanged": True,
        "procedural_truth_unchanged": True,
        "execution_gate_unchanged": True,
        "hard_entry_gate_unchanged": True,
        "skg_dtn_external_non_authoritative": True,
        "phase_19_not_started": True,
        "next_phase": {
            "phase_id": "18.7G",
            "phase_name": "Adversarial Local Trust Negative-Test Harness",
            "readiness_marker_only": True,
            "implemented_in_this_phase": False,
        },
    }


def required_command_ids() -> frozenset[str]:
    return frozenset(str(command["command_id"]) for command in RELEASE_VERIFICATION_COMMANDS)


def required_claim_ids() -> frozenset[str]:
    return frozenset(str(claim["claim_id"]) for claim in REQUIRED_CLAIM_SEEDS)


def release_readme_text() -> str:
    return "\n".join(
        [
            "# Release Integrity Bundle",
            "",
            "This directory is the Phase 18.7F reproducible validation bundle.",
            "",
            "It is a review-readiness package, not certification, legal advice, security certification, production release behavior, runtime activation, Phase 19, or external validation.",
            "",
            "## Files",
            "",
            "- `RELEASE_MANIFEST.json`: top-level release integrity manifest and digest.",
            "- `ARTIFACT_HASH_INDEX.json`: validation-relevant artifact hash index.",
            "- `VERIFICATION_COMMANDS.json`: reproducible command sequence index.",
            "- `CLAIMS_TO_EVIDENCE_SEED.json`: seed mapping for later claims-to-evidence work.",
            "- `BOUNDARY_AND_SCOPE_LOCK.json`: scope and exclusion lock.",
            "- `RELEASE_README.md`: this reviewer note.",
            "",
            "## Verification",
            "",
            "Run:",
            "",
            "```bat",
            "python -m sbp_lex.local_trust.release_integrity validate",
            "python -m sbp_lex.local_trust.release_integrity show",
            "```",
            "",
            "18.7G is the next phase marker only. 18.7G is not implemented in this bundle.",
            "",
        ]
    )
