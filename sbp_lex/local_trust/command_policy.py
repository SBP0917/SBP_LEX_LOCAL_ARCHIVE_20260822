from __future__ import annotations

from typing import Any


VERIFICATION_COMMAND_POLICY_VERSION = "LOCAL_TRUST_VERIFICATION_COMMAND_POLICY_V1"

REQUIRED_VERIFICATION_COMMANDS: tuple[dict[str, Any], ...] = (
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
    {"command_id": "runtime_main", "command": "python main.py", "required": True},
    {"command_id": "runtime_replay", "command": "python main.py replay", "required": True},
    {"command_id": "git_diff_check", "command": "git diff --check", "required": True},
    {"command_id": "git_status_short", "command": "git status --short", "required": True},
)

PYTEST_COLLECTION_POLICY = {
    "policy_version": "LOCAL_TRUST_PYTEST_COLLECTION_POLICY_V1",
    "required_options": [
        "--ignore=outputs",
        "--ignore-glob=.pytest_tmp_*",
        "--ignore-glob=*sbp_lex_local_trust_pytest_basetemp",
        "--ignore-glob=outputs/local_trust_temp/*",
    ],
    "records_generated_output_exclusion": True,
    "records_stale_temp_exclusion": True,
}

IGNORED_OUTPUT_PATHS: tuple[str, ...] = (
    "outputs",
    "outputs/local_trust_temp",
)

IGNORED_TEMP_PATHS: tuple[str, ...] = (
    ".pytest_cache",
    ".pytest_tmp_*",
    "*sbp_lex_local_trust_pytest_basetemp",
    "__pycache__",
    "*.pyc",
)


def verification_command_policy() -> dict[str, Any]:
    return {
        "policy_version": VERIFICATION_COMMAND_POLICY_VERSION,
        "commands": [
            {**command, "executed_by_toolchain_guard": False}
            for command in REQUIRED_VERIFICATION_COMMANDS
        ],
    }


def required_command_ids() -> frozenset[str]:
    return frozenset(str(command["command_id"]) for command in REQUIRED_VERIFICATION_COMMANDS)
