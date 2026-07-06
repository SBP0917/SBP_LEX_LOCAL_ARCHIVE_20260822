from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_simulation.boundary import run_boundary_check
from sbp_simulation.scenarios import (
    SCENARIO_LIBRARY,
    get_scenario,
    run_scenario_library,
    scenario_index,
    scenario_to_dict,
    validate_scenario,
    validate_scenario_library,
)
from sbp_simulation.status import FORBIDDEN_SIMULATION_STATUSES


REQUIRED_SCENARIO_IDS = {
    "LOW_ALLOW_ROUTINE_STATUS_CHECK",
    "LOW_DENY_MISSING_REQUIRED_TOKEN",
    "LOW_REPLAY_MATCH",
    "MEDIUM_ALLOW_SPLIT_VALIDATOR_CONFIG_REVIEW",
    "MEDIUM_ESCALATE_CORROBORATION_SHORTFALL",
    "MEDIUM_DENY_LICENSE_SCOPE_MISMATCH",
    "MEDIUM_REPLAY_MATCH",
    "TOP_ALLOW_FULL_DUAL_FULLY_VALIDATED",
    "TOP_DENY_GOVERNANCE_AUTHORITY_FAIL",
    "TOP_ESCALATE_AUTHORITY_CONFLICT",
    "TOP_HALT_TOKEN_SIGNATURE_TAMPER",
    "TOP_PARITY_MISMATCH_BLOCK",
    "TOP_REPLAY_MATCH",
}


def test_all_required_scenarios_exist() -> None:
    assert set(SCENARIO_LIBRARY) == REQUIRED_SCENARIO_IDS


def test_scenario_schema_rejects_missing_and_invalid_fields() -> None:
    valid, failures = validate_scenario({"simulation_id": "BROKEN"})
    assert not valid
    assert "missing_field:phase19a_required" in failures
    payload = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    payload["risk_tier"] = "UNKNOWN"
    assert "invalid_risk_tier" in validate_scenario(payload)[1]
    payload = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    payload["traversal_mode"] = "UNKNOWN"
    assert "invalid_traversal_mode" in validate_scenario(payload)[1]
    payload = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    payload["expected_outcome_category"] = "ALLOW"
    assert "invalid_expected_outcome_category" in validate_scenario(payload)[1]


def test_adaptive_traversal_mapping_rejects_invalid_pairs() -> None:
    for scenario in SCENARIO_LIBRARY.values():
        valid, failures = validate_scenario(scenario_to_dict(scenario))
        assert valid, failures
    low_full_dual = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    low_full_dual["traversal_mode"] = "FULL_DUAL"
    assert "invalid_adaptive_traversal_mapping" in validate_scenario(low_full_dual)[1]
    top_single = scenario_to_dict(SCENARIO_LIBRARY["TOP_PARITY_MISMATCH_BLOCK"])
    top_single["traversal_mode"] = "SINGLE_PIPELINE"
    assert "invalid_adaptive_traversal_mapping" in validate_scenario(top_single)[1]


def test_scenario_index_counts_are_correct() -> None:
    index = scenario_index()
    assert index["total_scenarios"] == 13
    assert index["scenarios_by_risk_tier"] == {"LOW": 3, "MEDIUM": 4, "TOP": 6}
    assert index["scenarios_by_traversal_mode"] == {"SINGLE_PIPELINE": 3, "SPLIT_VALIDATOR": 4, "FULL_DUAL": 6}
    assert index["scenarios_by_expected_outcome"] == {
        "EXPECT_ALLOW": 3,
        "EXPECT_DENY": 3,
        "EXPECT_ESCALATE": 2,
        "EXPECT_HALT": 1,
        "EXPECT_PARITY_FAIL": 1,
        "EXPECT_REPLAY_MATCH": 3,
    }
    assert index["runtime_backed_count"] == 0
    assert index["phase19a_required_count"] == 13
    assert index["invalid_count"] == 0


def test_every_scenario_has_reviewer_notes_forbidden_claims_pvpl_and_oda_expectations() -> None:
    for scenario in SCENARIO_LIBRARY.values():
        payload = scenario_to_dict(scenario)
        assert payload["reviewer_notes"]
        assert isinstance(payload["forbidden_claims"], list)
        assert payload["required_pvpl_expectations"]
        assert payload["required_oda_explanation_expectations"]


def test_validate_scenario_library_passes() -> None:
    result = validate_scenario_library()
    assert result["scenario_library_status"] == "SIM_OK"
    assert all(item["valid"] for item in result["results"])


def test_run_scenario_library_writes_evidence_without_runtime_proof(tmp_path: Path) -> None:
    result = run_scenario_library(tmp_path)
    assert result["simulation_status"] == "SIM_OK"
    for scenario_id in REQUIRED_SCENARIO_IDS:
        scenario_dir = tmp_path / scenario_id
        for name in ("scenario_fixture.json", "scenario_validation.json", "scenario_result.json", "reviewer_scenario_summary.md"):
            assert (scenario_dir / name).exists()
        scenario_result = json.loads((scenario_dir / "scenario_result.json").read_text(encoding="utf-8"))
        assert scenario_result["scenario_status"] == "SCENARIO_READY_FOR_PHASE_19A"
        assert scenario_result["runtime_execution_status"] == "NOT_EXECUTED_PHASE19A_REQUIRED"
        assert scenario_result["runtime_backed"] is False
        assert scenario_result["phase19a_required"] is True
        assert scenario_result["scenario_status"] not in FORBIDDEN_SIMULATION_STATUSES
        assert scenario_result["runtime_execution_status"] not in FORBIDDEN_SIMULATION_STATUSES
        assert scenario_result["forbidden_claims_absent"] is True


def test_cli_scenario_commands(tmp_path: Path) -> None:
    base_command = [sys.executable, "-m", "sbp_simulation.cli"]
    listed = subprocess.run([*base_command, "--list-scenarios"], capture_output=True, text=True, check=True)
    assert "LOW_ALLOW_ROUTINE_STATUS_CHECK" in listed.stdout
    shown_low = subprocess.run([*base_command, "--show-scenario", "LOW_ALLOW_ROUTINE_STATUS_CHECK"], capture_output=True, text=True, check=True)
    assert json.loads(shown_low.stdout)["simulation_id"] == "LOW_ALLOW_ROUTINE_STATUS_CHECK"
    shown_top = subprocess.run([*base_command, "--show-scenario", "TOP_PARITY_MISMATCH_BLOCK"], capture_output=True, text=True, check=True)
    assert json.loads(shown_top.stdout)["simulation_id"] == "TOP_PARITY_MISMATCH_BLOCK"
    unknown = subprocess.run([*base_command, "--show-scenario", "UNKNOWN_SCENARIO"], capture_output=True, text=True, check=False)
    assert unknown.returncode == 1
    assert json.loads(unknown.stdout)["simulation_status"] == "SIM_BLOCKED"
    validated = subprocess.run([*base_command, "--validate-scenario-library"], capture_output=True, text=True, check=True)
    assert json.loads(validated.stdout)["scenario_library_status"] == "SIM_OK"
    run = subprocess.run([*base_command, "--run-scenario-library", "--out", str(tmp_path)], capture_output=True, text=True, check=True)
    assert json.loads(run.stdout)["simulation_status"] == "SIM_OK"


def test_scenario_lookup() -> None:
    assert get_scenario("LOW_ALLOW_ROUTINE_STATUS_CHECK") is not None
    assert get_scenario("UNKNOWN_SCENARIO") is None


def test_simulation_boundary_remains_detached() -> None:
    result = run_boundary_check(".")
    assert result["status"] == "SIM_OK", result
