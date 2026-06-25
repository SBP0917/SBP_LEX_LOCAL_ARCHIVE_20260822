from __future__ import annotations

from typing import Any, Mapping


CAPSTONE_VERIFICATION_COMMANDS: tuple[dict[str, Any], ...] = (
    {"command_id": "compileall", "command": "python -m compileall -q .", "required": True},
    {"command_id": "pytest", "command": "python -m pytest -q", "required": True},
    {"command_id": "run_tests_bat", "command": "scripts\\run_tests.bat", "required": True},
    {"command_id": "manifest_validate", "command": "python -m sbp_lex.local_trust.manifest validate", "required": True},
    {"command_id": "execution_envelope_validate", "command": "python -m sbp_lex.local_trust.execution_envelope validate", "required": True},
    {"command_id": "evidence_chain_validate", "command": "python -m sbp_lex.local_trust.evidence_chain validate", "required": True},
    {"command_id": "evidence_chain_compare", "command": "python -m sbp_lex.local_trust.evidence_chain compare", "required": True},
    {"command_id": "regression_matrix_validate", "command": "python -m sbp_lex.local_trust.regression_matrix validate", "required": True},
    {"command_id": "regression_matrix_show", "command": "python -m sbp_lex.local_trust.regression_matrix show", "required": True},
    {"command_id": "constitutional_gates_evaluate", "command": "python -m sbp_lex.local_trust.constitutional_gates evaluate", "required": True},
    {"command_id": "constitutional_gates_validate", "command": "python -m sbp_lex.local_trust.constitutional_gates validate", "required": True},
    {"command_id": "constitutional_gates_show", "command": "python -m sbp_lex.local_trust.constitutional_gates show", "required": True},
    {"command_id": "toolchain_guard_build", "command": "python -m sbp_lex.local_trust.toolchain_guard build", "required": True},
    {"command_id": "toolchain_guard_validate", "command": "python -m sbp_lex.local_trust.toolchain_guard validate", "required": True},
    {"command_id": "toolchain_guard_show", "command": "python -m sbp_lex.local_trust.toolchain_guard show", "required": True},
    {"command_id": "capstone_build", "command": "python -m sbp_lex.local_trust.local_trust_capstone build", "required": True},
    {"command_id": "capstone_validate", "command": "python -m sbp_lex.local_trust.local_trust_capstone validate", "required": True},
    {"command_id": "capstone_show", "command": "python -m sbp_lex.local_trust.local_trust_capstone show", "required": True},
    {"command_id": "runtime_main", "command": "python main.py", "required": True},
    {"command_id": "runtime_replay", "command": "python main.py replay", "required": True},
    {"command_id": "git_diff_check", "command": "git diff --check", "required": True},
    {"command_id": "git_status_short", "command": "git status --short", "required": True},
)


def verification_command_index() -> dict[str, Any]:
    return {
        "index_version": "LOCAL_TRUST_CAPSTONE_VERIFICATION_COMMAND_INDEX_V1",
        "execution_note": "The capstone records required commands only; it does not execute them.",
        "commands": [
            {**command, "executed_by_capstone": False}
            for command in CAPSTONE_VERIFICATION_COMMANDS
        ],
    }


def required_capstone_command_ids() -> frozenset[str]:
    return frozenset(str(command["command_id"]) for command in CAPSTONE_VERIFICATION_COMMANDS)


def completed_phase_index(bindings: Mapping[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "phase_id": "18.7D.1",
            "phase_name": "Evidence Chain Zero-Missing Cleanup",
            "phase_status": "DONE_COMMITTED_PUSHED",
            "commit_hash_if_known": "52b5d046da5af78d0377d007f19276ced554f011",
            "primary_outputs": [
                "reports/PHASE_18_7D_1_ZERO_MISSING_EVIDENCE_CLEANUP_REPORT.md",
                "outputs/local_evidence_chain.json",
            ],
            "primary_digest": bindings.get("evidence_chain", "UNKNOWN_FROM_CURRENT_CONTEXT"),
            "test_count_if_known": 318,
            "verification_summary": "EVIDENCE_CHAIN_VALID with zero missing evidence after cleanup.",
            "boundary_summary": "Local evidence only; no runtime authority change.",
        },
        {
            "phase_id": "18.7E.1",
            "phase_name": "Local Trust Regression Matrix",
            "phase_status": "DONE_COMMITTED_PUSHED",
            "commit_hash_if_known": "d90a255b475e8637a54ecc42c9ce5bef8fbb8d78",
            "primary_outputs": [
                "docs/LOCAL_TRUST_REGRESSION_MATRIX.md",
                "reports/PHASE_18_7E_1_LOCAL_TRUST_REGRESSION_MATRIX_REPORT.md",
                "outputs/local_trust_regression_matrix.json",
            ],
            "primary_digest": bindings.get("regression_matrix", "UNKNOWN_FROM_CURRENT_CONTEXT"),
            "test_count_if_known": 341,
            "verification_summary": "REGRESSION_MATRIX_VALID with 19 passing cases.",
            "boundary_summary": "Constitutional drift detection only; no runtime authority change.",
        },
        {
            "phase_id": "18.7E.2",
            "phase_name": "Constitutional Enforcement Gates",
            "phase_status": "DONE_COMMITTED_PUSHED",
            "commit_hash_if_known": "ccf60acbf51123a9608bc1f399ee48c2e1678c31",
            "primary_outputs": [
                "docs/LOCAL_TRUST_CONSTITUTIONAL_ENFORCEMENT_GATES.md",
                "reports/PHASE_18_7E_2_CONSTITUTIONAL_ENFORCEMENT_GATES_REPORT.md",
                "outputs/local_constitutional_gates.json",
            ],
            "primary_digest": bindings.get("constitutional_gates", "UNKNOWN_FROM_CURRENT_CONTEXT"),
            "test_count_if_known": 372,
            "verification_summary": "CONSTITUTIONAL_GATES_PASS with 24 passing gates.",
            "boundary_summary": "Local pre-flight guardrails only; no execution authority.",
        },
        {
            "phase_id": "18.7E.3",
            "phase_name": "Dependency / Toolchain Guard",
            "phase_status": "DONE_COMMITTED_PUSHED",
            "commit_hash_if_known": "eedb30cc5cd4ea7e6bc9be29d06e1c276e28a6d4",
            "primary_outputs": [
                "docs/LOCAL_TRUST_TOOLCHAIN_GUARD.md",
                "reports/PHASE_18_7E_3_TOOLCHAIN_GUARD_REPORT.md",
                "outputs/local_toolchain_guard.json",
            ],
            "primary_digest": bindings.get("toolchain_guard", "UNKNOWN_FROM_CURRENT_CONTEXT"),
            "test_count_if_known": 399,
            "verification_summary": "TOOLCHAIN_GUARD_PASS with 39 passing checks.",
            "boundary_summary": "Toolchain readiness only; no runtime command execution.",
        },
        {
            "phase_id": "18.7E.4",
            "phase_name": "25-Year Local Trust Capstone",
            "phase_status": "COMPLETE_VERIFIED_UNCOMMITTED",
            "commit_hash_if_known": "UNCOMMITTED_CURRENT_PHASE",
            "primary_outputs": [
                "docs/LOCAL_TRUST_25_YEAR_CAPSTONE.md",
                "reports/PHASE_18_7E_4_25_YEAR_LOCAL_TRUST_CAPSTONE_REPORT.md",
                "outputs/local_trust_25_year_capstone.json",
            ],
            "primary_digest": "RECORDED_IN_TOP_LEVEL_CAPSTONE_DIGEST",
            "test_count_if_known": "RECORDED_AFTER_FINAL_VERIFICATION",
            "verification_summary": "Capstone build/validate/show records local trust completion.",
            "boundary_summary": "Completion lock only; 18.7F marked as next phase without implementation.",
        },
    ]
