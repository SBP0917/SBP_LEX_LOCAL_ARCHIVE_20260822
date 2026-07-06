from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_simulation.boundary import run_boundary_check
from sbp_simulation.command_policy import command_allowed
from sbp_simulation.failure_matrix import (
    FAILURE_MATRIX_STATUSES,
    FAILURE_TESTS,
    FAILURE_TEST_STATUSES,
    FORBIDDEN_RUNTIME_STATUSES,
    list_failure_tests,
    run_failure_matrix,
    run_failure_test,
    verify_failure_matrix,
)
from sbp_simulation.scenarios import SCENARIO_LIBRARY, scenario_to_dict, validate_scenario


REQUIRED_FAILURE_TESTS = {
    "UNSAFE_COMMAND_BLOCK",
    "INVALID_RISK_MODE_MAPPING",
    "UNKNOWN_SCENARIO_BLOCK",
    "SCENARIO_RESULT_TAMPER",
    "REPLAY_RESULT_MISMATCH_ARTIFACT",
    "PARITY_MISMATCH_FIXTURE",
    "TOKEN_SIGNATURE_TAMPER_ARTIFACT",
    "HASH_CHAIN_TAMPER_ARTIFACT",
    "REQUIRED_EVIDENCE_MISSING",
    "FORBIDDEN_PUBLICATION_ACTIVATION",
    "PVPL_BUNDLE_TAMPER_COMPATIBILITY",
}


def test_failure_definitions_are_complete() -> None:
    assert set(FAILURE_TESTS) == REQUIRED_FAILURE_TESTS
    for definition in list_failure_tests():
        assert definition["reviewer_description"]
        assert definition["expected_detection_mode"]
        assert definition["expected_status"] in FAILURE_TEST_STATUSES
        assert isinstance(definition["phase19a_required"], bool)


def test_unsafe_commands_are_blocked() -> None:
    blocked = [
        ["git", "clean"],
        ["git", "push"],
        ["delete", "runtime_artifacts"],
        ["rmdir", "runtime_artifacts"],
        ["python", "main.py", "|", "whoami"],
        ["python", "-m", "sbp_pvpl.cli", "--publish", "external"],
    ]
    for command in blocked:
        assert not command_allowed(command)[0]


def test_invalid_mapping_cases_rejected() -> None:
    top_single = scenario_to_dict(SCENARIO_LIBRARY["TOP_PARITY_MISMATCH_BLOCK"])
    top_single["traversal_mode"] = "SINGLE_PIPELINE"
    assert not validate_scenario(top_single)[0]
    low_full = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    low_full["traversal_mode"] = "FULL_DUAL"
    assert not validate_scenario(low_full)[0]
    missing_tier = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    missing_tier.pop("risk_tier")
    assert not validate_scenario(missing_tier)[0]
    missing_mode = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    missing_mode.pop("traversal_mode")
    assert not validate_scenario(missing_mode)[0]


def test_failure_tests_detect_or_block_expected_conditions(tmp_path: Path) -> None:
    expected = {
        "UNSAFE_COMMAND_BLOCK": "FAILURE_TEST_BLOCKED",
        "INVALID_RISK_MODE_MAPPING": "FAILURE_TEST_DETECTED",
        "UNKNOWN_SCENARIO_BLOCK": "FAILURE_TEST_BLOCKED",
        "SCENARIO_RESULT_TAMPER": "FAILURE_TEST_DETECTED",
        "REPLAY_RESULT_MISMATCH_ARTIFACT": "FAILURE_TEST_DETECTED",
        "PARITY_MISMATCH_FIXTURE": "FAILURE_TEST_DETECTED",
        "TOKEN_SIGNATURE_TAMPER_ARTIFACT": "FAILURE_TEST_DETECTED",
        "HASH_CHAIN_TAMPER_ARTIFACT": "FAILURE_TEST_DETECTED",
        "REQUIRED_EVIDENCE_MISSING": "FAILURE_TEST_DETECTED",
        "FORBIDDEN_PUBLICATION_ACTIVATION": "FAILURE_TEST_BLOCKED",
    }
    for test_id, status in expected.items():
        result = run_failure_test(test_id, tmp_path)
        assert result["failure_test_status"] == status
        assert result["failure_test_status"] not in FORBIDDEN_RUNTIME_STATUSES


def test_pvpl_bundle_tamper_detected_or_incomplete(tmp_path: Path) -> None:
    result = run_failure_test("PVPL_BUNDLE_TAMPER_COMPATIBILITY", tmp_path)
    assert result["failure_test_status"] in {"FAILURE_TEST_DETECTED", "FAILURE_TEST_INCOMPLETE"}
    if result["failure_test_status"] == "FAILURE_TEST_DETECTED":
        assert result["pvpl_verify_status"] != "PROOF_OK"


def test_failure_matrix_outputs_and_verification(tmp_path: Path) -> None:
    result = run_failure_matrix(tmp_path)
    assert result["failure_matrix_status"] in FAILURE_MATRIX_STATUSES
    assert result["failure_matrix_status"] in {"FAILURE_MATRIX_OK", "FAILURE_MATRIX_WARNING"}
    verification = verify_failure_matrix(tmp_path)
    assert verification["verification_status"] == "FAILURE_MATRIX_OK", verification
    for test_id in REQUIRED_FAILURE_TESTS:
        test_dir = tmp_path / test_id
        assert (test_dir / "failure_test_definition.json").exists()
        assert (test_dir / "verification_result.json").exists()
        assert (test_dir / "reviewer_failure_summary.md").exists()


def test_all_tampered_files_live_under_sim03(tmp_path: Path) -> None:
    result = run_failure_matrix(tmp_path)
    for item in result["results"]:
        for evidence_path in item.get("evidence_paths", []):
            assert str(tmp_path) in str((Path.cwd() / evidence_path).resolve()) or "sim_03" in evidence_path.replace("\\", "/")


def test_failure_cli_commands(tmp_path: Path) -> None:
    base = [sys.executable, "-m", "sbp_simulation.cli"]
    listed = subprocess.run([*base, "--list-failure-tests"], capture_output=True, text=True, check=True)
    assert "UNSAFE_COMMAND_BLOCK" in listed.stdout
    single = subprocess.run([*base, "--run-failure-test", "PARITY_MISMATCH_FIXTURE", "--out", str(tmp_path)], capture_output=True, text=True, check=True)
    assert json.loads(single.stdout)["failure_test_status"] == "FAILURE_TEST_DETECTED"
    matrix = subprocess.run([*base, "--run-failure-matrix", "--out", str(tmp_path)], capture_output=True, text=True, check=True)
    assert json.loads(matrix.stdout)["failure_matrix_status"] in {"FAILURE_MATRIX_OK", "FAILURE_MATRIX_WARNING"}
    verified = subprocess.run([*base, "--verify-failure-matrix", str(tmp_path)], capture_output=True, text=True, check=True)
    assert json.loads(verified.stdout)["verification_status"] == "FAILURE_MATRIX_OK"


def test_failure_statuses_do_not_use_runtime_status_words() -> None:
    assert not FAILURE_TEST_STATUSES.intersection(FORBIDDEN_RUNTIME_STATUSES)
    assert not FAILURE_MATRIX_STATUSES.intersection(FORBIDDEN_RUNTIME_STATUSES)


def test_pvpl_is_not_imported_by_simulation_failure_module() -> None:
    failure_module = Path("sbp_simulation/failure_matrix.py").read_text(encoding="utf-8")
    assert "import sbp_pvpl" not in failure_module
    assert "from sbp_pvpl" not in failure_module


def test_simulation_boundary_remains_detached_after_sim03() -> None:
    result = run_boundary_check(".")
    assert result["status"] == "SIM_OK", result
