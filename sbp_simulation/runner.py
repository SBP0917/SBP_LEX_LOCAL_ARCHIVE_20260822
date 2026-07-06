from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbp_simulation.command_policy import command_allowed
from sbp_simulation.fixtures import (
    SimulationFixture,
    fixture_to_dict,
    get_fixture,
    validate_fixture,
)
from sbp_simulation.parser import compare_observations, parse_json_stdout
from sbp_simulation.status import (
    FORBIDDEN_SIMULATION_STATUSES,
    OBSERVATION_STATUSES,
    SCENARIO_RUNTIME_EXECUTION_STATUSES,
    SCENARIO_STATUSES,
    SimulationStatus,
)


BOUNDARY_STATEMENT = (
    "SIM-01 is local/private controlled validation only. It does not activate "
    "production traversal, create execution authority, mutate governance, or "
    "modify SBP-LEX runtime authority files."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _command_for_subprocess(command: list[str]) -> list[str]:
    if command and command[0].lower() == "python":
        return [sys.executable, *command[1:]]
    return command


def _simulation_dir(out_root: Path, simulation_id: str) -> Path:
    return out_root / simulation_id


def _forbidden_claims_absent(stdout: str, stderr: str, forbidden_claims: list[str]) -> bool:
    observed_text = f"{stdout}\n{stderr}".lower()
    return not any(claim.lower() in observed_text for claim in forbidden_claims)


def _summary_markdown(result: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# SIM-01 Reviewer Summary: {result['simulation_id']}",
            "",
            f"- Simulation status: {result['simulation_status']}",
            f"- Command: `{' '.join(result['command'])}`",
            f"- Exit code: {result['command_exit_code']}",
            f"- Observation status: {result['observation_match_status']}",
            f"- Parser status: {result['parser_status']}",
            f"- Runtime authority created by simulation: {result['runtime_authority_created_by_simulation']}",
            f"- Publication active: {result['publication_active']}",
            "",
            "## Observations",
            "",
            "```json",
            json.dumps(result["runtime_observations"], indent=2, sort_keys=True),
            "```",
            "",
            "## Evidence Files",
            "",
            *[f"- `{path}`" for path in result["artifacts_written"]],
            "",
            "## Boundary",
            "",
            BOUNDARY_STATEMENT,
            "",
            "## Reviewer Next Command",
            "",
            "`python -m sbp_simulation.cli --verify runtime_artifacts/sim_01/`",
            "",
            "PVPL can consume the JSON evidence paths listed above in later local/private proof bundle phases.",
            "",
        ]
    )


def run_fixture(
    simulation_id: str,
    out_root: str | Path = "runtime_artifacts/sim_01/",
    runtime_root: str | Path = ".",
) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    out_root_path = Path(out_root)
    if not out_root_path.is_absolute():
        out_root_path = root / out_root_path
    started_at = _utc_now()
    fixture = get_fixture(simulation_id)
    if fixture is None:
        return {
            "simulation_id": simulation_id,
            "simulation_status": SimulationStatus.SIM_BLOCKED.value,
            "error": "unknown_simulation_id",
            "started_at": started_at,
            "completed_at": _utc_now(),
            "artifacts_written": [],
            "boundary_statement": BOUNDARY_STATEMENT,
        }
    return run_fixture_payload(fixture, out_root_path, root)


def run_fixture_payload(
    fixture: SimulationFixture,
    out_root: str | Path = "runtime_artifacts/sim_01/",
    runtime_root: str | Path = ".",
) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    out_root_path = Path(out_root)
    if not out_root_path.is_absolute():
        out_root_path = root / out_root_path
    payload = fixture_to_dict(fixture)
    valid, validation_failures = validate_fixture(payload)
    sim_dir = _simulation_dir(out_root_path, fixture.simulation_id)
    sim_dir.mkdir(parents=True, exist_ok=True)
    fixture_path = sim_dir / "fixture.json"
    command_capture_path = sim_dir / "command_capture.json"
    result_path = sim_dir / "simulation_result.json"
    summary_path = sim_dir / "reviewer_summary.md"
    command = fixture.runtime_command or fixture.replay_command or []
    allowed, allow_reason = command_allowed(command)
    artifacts = [
        _display_path(fixture_path, root),
        _display_path(command_capture_path, root),
        _display_path(result_path, root),
        _display_path(summary_path, root),
    ]

    _write_json(fixture_path, payload)
    if not valid or not allowed:
        status = SimulationStatus.SIM_INVALID_FIXTURE if not valid else SimulationStatus.SIM_BLOCKED
        capture = {
            "command": command,
            "command_allowed": allowed,
            "allow_reason": allow_reason,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "started_at": _utc_now(),
            "completed_at": _utc_now(),
        }
        _write_json(command_capture_path, capture)
        result = {
            "simulation_id": fixture.simulation_id,
            "simulation_status": status.value,
            "fixture_valid": valid,
            "fixture_validation_failures": validation_failures,
            "command": command,
            "command_allowed": allowed,
            "command_policy_reason": allow_reason,
            "command_exit_code": None,
            "parser_status": "NOT_RUN",
            "runtime_observations": {},
            "expected_observations": fixture.expected_observations,
            "observation_match_status": "OBSERVATION_NOT_CHECKED",
            "artifacts_written": artifacts,
            "pvpl_ready_paths": artifacts,
            "oda_summary": "Simulation was blocked before runtime command execution.",
            "boundary_statement": BOUNDARY_STATEMENT,
            "forbidden_claims_absent": True,
            "runtime_authority_created_by_simulation": False,
            "publication_active": False,
        }
        _write_json(result_path, result)
        summary_path.write_text(_summary_markdown(result), encoding="utf-8")
        return result

    started_at = _utc_now()
    completed = subprocess.run(
        _command_for_subprocess(command),
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    completed_at = _utc_now()
    observations, parser_status = parse_json_stdout(completed.stdout)
    observation_status = compare_observations(observations, fixture.expected_observations)
    if observation_status not in OBSERVATION_STATUSES:
        observation_status = "OBSERVATION_NOT_CHECKED"

    if completed.returncode != 0:
        status = SimulationStatus.SIM_FAILED
    elif parser_status != "OK" or observation_status in {"OBSERVATION_PARTIAL", "OBSERVATION_MISSING"}:
        status = SimulationStatus.SIM_WARNING
    else:
        status = SimulationStatus.SIM_OK

    capture = {
        "command": command,
        "subprocess_command": _command_for_subprocess(command),
        "cwd": str(root),
        "command_allowed": allowed,
        "allow_reason": allow_reason,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "started_at": started_at,
        "completed_at": completed_at,
    }
    _write_json(command_capture_path, capture)
    result = {
        "simulation_id": fixture.simulation_id,
        "simulation_status": status.value,
        "fixture_valid": valid,
        "fixture_validation_failures": validation_failures,
        "command": command,
        "command_allowed": allowed,
        "command_policy_reason": allow_reason,
        "command_exit_code": completed.returncode,
        "parser_status": parser_status,
        "runtime_observations": observations,
        "expected_observations": fixture.expected_observations,
        "observation_match_status": observation_status,
        "artifacts_written": artifacts,
        "pvpl_ready_paths": artifacts,
        "oda_summary": (
            "Local controlled command evidence captured. Review command_capture.json "
            "for stdout/stderr and simulation_result.json for structured observations."
        ),
        "boundary_statement": BOUNDARY_STATEMENT,
        "forbidden_claims_absent": _forbidden_claims_absent(
            completed.stdout, completed.stderr, fixture.forbidden_claims
        ),
        "runtime_authority_created_by_simulation": False,
        "publication_active": False,
    }
    if result["simulation_status"] in FORBIDDEN_SIMULATION_STATUSES:
        result["simulation_status"] = SimulationStatus.SIM_FAILED.value
    _write_json(result_path, result)
    summary_path.write_text(_summary_markdown(result), encoding="utf-8")
    return result


def verify_outputs(out_root: str | Path = "runtime_artifacts/sim_01/", runtime_root: str | Path = ".") -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    base = Path(out_root)
    if not base.is_absolute():
        base = root / base
    findings: list[dict[str, str]] = []
    result_files = sorted(base.glob("*/simulation_result.json"))
    scenario_result_files = sorted(base.glob("*/scenario_result.json"))
    for result_file in result_files:
        try:
            payload = json.loads(result_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            findings.append({"path": _display_path(result_file, root), "finding": "invalid_json"})
            continue
        status = payload.get("simulation_status")
        if status in FORBIDDEN_SIMULATION_STATUSES:
            findings.append({"path": _display_path(result_file, root), "finding": "forbidden_status"})
        if status not in {item.value for item in SimulationStatus}:
            findings.append({"path": _display_path(result_file, root), "finding": "unknown_simulation_status"})
        for artifact in payload.get("artifacts_written", []):
            if not (root / artifact).exists():
                findings.append({"path": artifact, "finding": "missing_artifact"})
    for result_file in scenario_result_files:
        try:
            payload = json.loads(result_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            findings.append({"path": _display_path(result_file, root), "finding": "invalid_json"})
            continue
        status = payload.get("scenario_status")
        runtime_status = payload.get("runtime_execution_status")
        if status in FORBIDDEN_SIMULATION_STATUSES or runtime_status in FORBIDDEN_SIMULATION_STATUSES:
            findings.append({"path": _display_path(result_file, root), "finding": "forbidden_status"})
        if status not in SCENARIO_STATUSES:
            findings.append({"path": _display_path(result_file, root), "finding": "unknown_scenario_status"})
        if runtime_status not in SCENARIO_RUNTIME_EXECUTION_STATUSES:
            findings.append({"path": _display_path(result_file, root), "finding": "unknown_runtime_execution_status"})
        for artifact in payload.get("pvpl_ready_paths", []):
            if not (root / artifact).exists():
                findings.append({"path": artifact, "finding": "missing_artifact"})
    if not result_files and not scenario_result_files:
        findings.append({"path": _display_path(base, root), "finding": "no_simulation_results"})
    status = SimulationStatus.SIM_OK if not findings else SimulationStatus.SIM_INCOMPLETE
    return {
        "verification_status": status.value,
        "result_count": len(result_files) + len(scenario_result_files),
        "simulation_result_count": len(result_files),
        "scenario_result_count": len(scenario_result_files),
        "finding_count": len(findings),
        "findings": findings,
    }
