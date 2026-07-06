from __future__ import annotations

import argparse
import json
from typing import Any

from sbp_simulation.boundary import run_boundary_check
from sbp_simulation.failure_matrix import (
    list_failure_tests,
    run_failure_matrix,
    run_failure_test,
    verify_failure_matrix,
)
from sbp_simulation.fixtures import list_fixtures
from sbp_simulation.runner import run_fixture, verify_outputs
from sbp_simulation.scenarios import (
    get_scenario,
    run_scenario_library,
    scenario_index,
    scenario_to_dict,
    validate_scenario_library,
)
from sbp_simulation.status import SimulationStatus


SMOKE_SUITE = ("MAIN_RUNTIME_SMOKE", "MAIN_REPLAY_SMOKE")


def _print(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX controlled simulation harness")
    parser.add_argument("--list", action="store_true", help="List available simulation fixtures")
    parser.add_argument("--run", help="Run a single simulation fixture")
    parser.add_argument("--run-suite", help="Run a named simulation suite")
    parser.add_argument("--verify", help="Verify simulation output directory")
    parser.add_argument("--list-scenarios", action="store_true", help="List controlled SIM-02 scenarios")
    parser.add_argument("--show-scenario", help="Show one controlled SIM-02 scenario")
    parser.add_argument("--validate-scenario-library", action="store_true", help="Validate controlled SIM-02 scenarios")
    parser.add_argument("--run-scenario-library", action="store_true", help="Write SIM-02 scenario evidence")
    parser.add_argument("--list-failure-tests", action="store_true", help="List controlled SIM-03 failure tests")
    parser.add_argument("--run-failure-test", help="Run one controlled SIM-03 failure test")
    parser.add_argument("--run-failure-matrix", action="store_true", help="Run the controlled SIM-03 failure matrix")
    parser.add_argument("--verify-failure-matrix", help="Verify SIM-03 failure matrix outputs")
    parser.add_argument("--out", default="runtime_artifacts/sim_01/", help="Simulation output root")
    parser.add_argument("--runtime-root", default=".", help="Repository runtime root")
    args = parser.parse_args()

    if args.list:
        _print({"fixtures": list_fixtures()})
        return 0
    if args.list_scenarios:
        _print(scenario_index())
        return 0
    if args.show_scenario:
        scenario = get_scenario(args.show_scenario)
        if scenario is None:
            _print({"scenario_id": args.show_scenario, "simulation_status": SimulationStatus.SIM_BLOCKED.value, "error": "unknown_scenario"})
            return 1
        _print(scenario_to_dict(scenario))
        return 0
    if args.validate_scenario_library:
        result = validate_scenario_library()
        _print(result)
        return 0 if result.get("scenario_library_status") == SimulationStatus.SIM_OK.value else 1
    if args.run_scenario_library:
        result = run_scenario_library(args.out, args.runtime_root)
        _print(result)
        return 0 if result.get("simulation_status") == SimulationStatus.SIM_OK.value else 1
    if args.list_failure_tests:
        _print({"failure_tests": list_failure_tests()})
        return 0
    if args.run_failure_test:
        result = run_failure_test(args.run_failure_test, args.out, args.runtime_root)
        _print(result)
        return 0 if result.get("failure_test_status") in {"FAILURE_TEST_DETECTED", "FAILURE_TEST_BLOCKED", "FAILURE_TEST_INCOMPLETE"} else 1
    if args.run_failure_matrix:
        result = run_failure_matrix(args.out, args.runtime_root)
        _print(result)
        return 0 if result.get("failure_matrix_status") in {"FAILURE_MATRIX_OK", "FAILURE_MATRIX_WARNING"} else 1
    if args.verify_failure_matrix:
        result = verify_failure_matrix(args.verify_failure_matrix, args.runtime_root)
        _print(result)
        return 0 if result.get("verification_status") == "FAILURE_MATRIX_OK" else 1
    if args.run:
        result = run_fixture(args.run, args.out, args.runtime_root)
        _print(result)
        return 0 if result.get("simulation_status") in {SimulationStatus.SIM_OK.value, SimulationStatus.SIM_WARNING.value} else 1
    if args.run_suite:
        if args.run_suite != "smoke":
            _print({"suite": args.run_suite, "simulation_status": SimulationStatus.SIM_BLOCKED.value, "error": "unknown_suite"})
            return 1
        results = [run_fixture(sim_id, args.out, args.runtime_root) for sim_id in SMOKE_SUITE]
        boundary = run_boundary_check(args.runtime_root)
        suite_status = SimulationStatus.SIM_OK.value
        if any(item.get("simulation_status") in {SimulationStatus.SIM_FAILED.value, SimulationStatus.SIM_BLOCKED.value, SimulationStatus.SIM_INVALID_FIXTURE.value} for item in results):
            suite_status = SimulationStatus.SIM_FAILED.value
        elif any(item.get("simulation_status") == SimulationStatus.SIM_WARNING.value for item in results):
            suite_status = SimulationStatus.SIM_WARNING.value
        if boundary.get("status") != SimulationStatus.SIM_OK.value:
            suite_status = SimulationStatus.SIM_BLOCKED.value
        _print({"suite": "smoke", "simulation_status": suite_status, "results": results, "boundary": boundary})
        return 0 if suite_status in {SimulationStatus.SIM_OK.value, SimulationStatus.SIM_WARNING.value} else 1
    if args.verify:
        result = verify_outputs(args.verify, args.runtime_root)
        _print(result)
        return 0 if result.get("verification_status") == SimulationStatus.SIM_OK.value else 1
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
