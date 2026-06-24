from __future__ import annotations

from typing import NamedTuple


LOCAL_TRUST_TOOLCHAIN_POLICY_VERSION = "LOCAL_TRUST_TOOLCHAIN_POLICY_V1"

TOOLCHAIN_CHECK_PASS = "TOOLCHAIN_CHECK_PASS"
TOOLCHAIN_CHECK_FAIL = "TOOLCHAIN_CHECK_FAIL"
TOOLCHAIN_CHECK_SKIPPED = "TOOLCHAIN_CHECK_SKIPPED"
TOOLCHAIN_CHECK_ERROR = "TOOLCHAIN_CHECK_ERROR"

TOOLCHAIN_CHECK_STATUSES = {
    TOOLCHAIN_CHECK_PASS,
    TOOLCHAIN_CHECK_FAIL,
    TOOLCHAIN_CHECK_SKIPPED,
    TOOLCHAIN_CHECK_ERROR,
}


class ToolchainCheckSpec(NamedTuple):
    check_id: str
    check_name: str
    check_category: str
    required: bool
    expected_condition: str


TOOLCHAIN_CHECK_SPECS: tuple[ToolchainCheckSpec, ...] = (
    ToolchainCheckSpec("python_executable_recorded", "Python executable recorded", "python", True, "python_executable_present"),
    ToolchainCheckSpec("python_version_recorded", "Python version recorded", "python", True, "python_version_present"),
    ToolchainCheckSpec("python_executable_exists", "Python executable exists", "python", True, "python_executable_exists"),
    ToolchainCheckSpec("python_version_parseable", "Python version is parseable", "python", True, "python_version_parseable"),
    ToolchainCheckSpec("pytest_version_recorded", "pytest version recorded", "pytest", True, "pytest_version_present"),
    ToolchainCheckSpec("pytest_import_available", "pytest import availability checked", "pytest", True, "pytest_import_available"),
    ToolchainCheckSpec("pip_version_recorded", "pip version recorded if available", "pip", True, "pip_version_recorded_or_unavailable"),
    ToolchainCheckSpec("dependency_files_discovered", "Dependency files discovered", "dependencies", True, "dependency_files_or_none_state_recorded"),
    ToolchainCheckSpec("dependency_file_digests_recorded", "Dependency file digests recorded", "dependencies", True, "dependency_file_digests_recorded"),
    ToolchainCheckSpec("requirements_files_digested", "Requirements files digested if present", "dependencies", True, "requirements_files_checked"),
    ToolchainCheckSpec("pyproject_toml_digested", "pyproject.toml digested if present", "dependencies", True, "pyproject_toml_checked"),
    ToolchainCheckSpec("setup_files_digested", "setup files digested if present", "dependencies", True, "setup_files_checked"),
    ToolchainCheckSpec("verification_command_policy_exists", "Verification command policy exists", "command_policy", True, "command_policy_present"),
    ToolchainCheckSpec("verification_command_compileall", "Verification command policy includes compileall", "command_policy", True, "compileall_recorded"),
    ToolchainCheckSpec("verification_command_pytest", "Verification command policy includes pytest", "command_policy", True, "pytest_recorded"),
    ToolchainCheckSpec("verification_command_run_tests_bat", "Verification command policy includes run_tests.bat", "command_policy", True, "run_tests_bat_recorded"),
    ToolchainCheckSpec("verification_command_manifest_validate", "Verification command policy includes manifest validate", "command_policy", True, "manifest_validate_recorded"),
    ToolchainCheckSpec("verification_command_execution_envelope_validate", "Verification command policy includes execution envelope validate", "command_policy", True, "execution_envelope_validate_recorded"),
    ToolchainCheckSpec("verification_command_evidence_chain_validate_compare", "Verification command policy includes evidence chain validate and compare", "command_policy", True, "evidence_chain_commands_recorded"),
    ToolchainCheckSpec("verification_command_regression_matrix_validate_show", "Verification command policy includes regression matrix validate and show", "command_policy", True, "regression_matrix_commands_recorded"),
    ToolchainCheckSpec("verification_command_constitutional_gates", "Verification command policy includes constitutional gates evaluate/validate/show", "command_policy", True, "constitutional_gate_commands_recorded"),
    ToolchainCheckSpec("verification_command_toolchain_guard", "Verification command policy includes toolchain guard build/validate/show", "command_policy", True, "toolchain_guard_commands_recorded"),
    ToolchainCheckSpec("verification_command_runtime_replay", "Verification command policy includes runtime and replay verification", "command_policy", True, "runtime_replay_commands_recorded"),
    ToolchainCheckSpec("pytest_ignore_outputs_policy", "pytest ignore policy records outputs exclusion", "pytest_policy", True, "outputs_ignored"),
    ToolchainCheckSpec("pytest_ignore_temp_policy", "pytest ignore policy records stale temp and local-trust temp exclusions", "pytest_policy", True, "temp_ignored"),
    ToolchainCheckSpec("temp_cache_exclusion_policy", "Temp/cache exclusion policy exists", "temp_policy", True, "temp_cache_exclusion_recorded"),
    ToolchainCheckSpec("generated_output_folder_policy", "Generated output folder policy exists", "temp_policy", True, "generated_output_policy_recorded"),
    ToolchainCheckSpec("binds_manifest_digest", "Toolchain binds manifest digest", "binding", True, "manifest_digest_bound"),
    ToolchainCheckSpec("binds_execution_envelope_digest", "Toolchain binds execution envelope digest", "binding", True, "execution_envelope_digest_bound"),
    ToolchainCheckSpec("binds_evidence_chain_digest", "Toolchain binds evidence chain digest", "binding", True, "evidence_chain_digest_bound"),
    ToolchainCheckSpec("binds_regression_matrix_digest", "Toolchain binds regression matrix digest", "binding", True, "regression_matrix_digest_bound"),
    ToolchainCheckSpec("binds_constitutional_gates_digest", "Toolchain binds constitutional gates digest", "binding", True, "constitutional_gates_digest_bound"),
    ToolchainCheckSpec("working_tree_policy_recorded", "Working tree policy recorded", "repository", True, "working_tree_policy_recorded"),
    ToolchainCheckSpec("branch_recorded", "Current branch recorded", "repository", True, "branch_recorded"),
    ToolchainCheckSpec("commit_recorded", "Current commit recorded", "repository", True, "commit_recorded"),
    ToolchainCheckSpec("phase_19_boundary_preserved", "Phase 19 not-started boundary preserved", "boundary", True, "phase_19_not_started"),
    ToolchainCheckSpec("future_surface_absent", "Future surface active implementation absent", "boundary", True, "future_surface_absent"),
    ToolchainCheckSpec("future_activation_absent", "Runtime activation active implementation absent", "boundary", True, "active_activation_absent"),
    ToolchainCheckSpec("forbidden_authority_absent", "Forbidden authority leakage absent from toolchain guard", "boundary", True, "forbidden_authority_absent"),
)

REQUIRED_TOOLCHAIN_CHECK_IDS = frozenset(spec.check_id for spec in TOOLCHAIN_CHECK_SPECS if spec.required)
