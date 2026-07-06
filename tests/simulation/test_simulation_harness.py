from __future__ import annotations

import json
from pathlib import Path

from sbp_simulation.boundary import run_boundary_check
from sbp_simulation.command_policy import command_allowed
from sbp_simulation.fixtures import (
    SEED_FIXTURES,
    fixture_to_dict,
    validate_fixture,
)
from sbp_simulation.parser import parse_json_stdout
from sbp_simulation.runner import run_fixture, verify_outputs
from sbp_simulation.status import FORBIDDEN_SIMULATION_STATUSES


def test_seed_fixtures_validate() -> None:
    for fixture in SEED_FIXTURES.values():
        valid, failures = validate_fixture(fixture_to_dict(fixture))
        assert valid, failures


def test_missing_required_fields_rejected() -> None:
    valid, failures = validate_fixture({"simulation_id": "BROKEN"})
    assert not valid
    assert "missing_field:expected_outcome_category" in failures
    assert "missing_command" in failures


def test_invalid_expected_outcome_rejected() -> None:
    payload = fixture_to_dict(SEED_FIXTURES["MAIN_RUNTIME_SMOKE"])
    payload["expected_outcome_category"] = "ALLOW"
    valid, failures = validate_fixture(payload)
    assert not valid
    assert "invalid_expected_outcome_category" in failures


def test_command_policy_allows_seed_commands_and_blocks_unsafe_commands() -> None:
    assert command_allowed(["python", "main.py"])[0]
    assert command_allowed(["python", "main.py", "replay"])[0]
    assert not command_allowed(["git", "push"])[0]
    assert not command_allowed(["python", "-m", "unknown.module"])[0]
    assert not command_allowed(["python", "main.py", "|", "curl", "https://example.test"])[0]
    assert not command_allowed(["python", "-m", "sbp_pvpl.cli", "--publish", "ledger"])[0]


def test_unknown_simulation_id_is_blocked(tmp_path: Path) -> None:
    result = run_fixture("UNKNOWN_SIM", tmp_path)
    assert result["simulation_status"] == "SIM_BLOCKED"
    assert result["artifacts_written"] == []


def test_parser_warning_does_not_fake_success() -> None:
    observations, parser_status = parse_json_stdout("not-json")
    assert observations == {}
    assert parser_status == "WARNING"


def test_runner_writes_controlled_evidence_files(tmp_path: Path) -> None:
    result = run_fixture("MAIN_RUNTIME_SMOKE", tmp_path)
    assert result["simulation_status"] in {"SIM_OK", "SIM_WARNING", "SIM_FAILED"}
    assert result["simulation_status"] not in FORBIDDEN_SIMULATION_STATUSES
    sim_dir = tmp_path / "MAIN_RUNTIME_SMOKE"
    for name in ("fixture.json", "command_capture.json", "simulation_result.json", "reviewer_summary.md"):
        assert (sim_dir / name).exists()
    stored = json.loads((sim_dir / "simulation_result.json").read_text(encoding="utf-8"))
    assert stored["runtime_authority_created_by_simulation"] is False
    assert stored["publication_active"] is False
    assert "runtime_observations" in stored
    assert "decision" not in stored or stored["simulation_status"] not in {"ALLOW", "DENY", "ESCALATE", "EXECUTE", "HALT"}


def test_verify_outputs_detects_written_results(tmp_path: Path) -> None:
    run_fixture("MAIN_RUNTIME_SMOKE", tmp_path)
    verification = verify_outputs(tmp_path)
    assert verification["verification_status"] == "SIM_OK"
    assert verification["result_count"] == 1


def test_boundary_keeps_simulation_detached_from_runtime() -> None:
    result = run_boundary_check(".")
    assert result["status"] == "SIM_OK", result
    assert result["finding_count"] == 0
