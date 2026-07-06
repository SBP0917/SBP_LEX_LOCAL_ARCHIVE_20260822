# SIM-01 Controlled Simulation Harness Report

Draft status: repository-contained implementation report.

## Purpose

SIM-01 adds a controlled local simulation harness for SBP-LEX reviewer evidence capture. The harness records what existing allowlisted runtime commands return. It does not create runtime authority, change traversal behavior, publish evidence, mutate audit chains, or attach to SBP-LEX runtime startup.

## Scope Implemented

- Added `sbp_simulation/` as a runtime-detached simulation harness.
- Added deterministic seed fixtures for `MAIN_RUNTIME_SMOKE` and `MAIN_REPLAY_SMOKE`.
- Added an allowlist-only command policy.
- Added runtime/replay command capture into `runtime_artifacts/sim_01/<simulation_id>/`.
- Added structured `simulation_result.json` outputs with PVPL-compatible artifact paths.
- Added reviewer `reviewer_summary.md` outputs with ODA-readable explanation fields.
- Added SIM-01 CLI commands for listing, running, suite execution, and output verification.
- Added focused tests under `tests/simulation/`.

## Boundary Statement

SIM-01 is local/private controlled validation only. It does not activate production traversal, create execution authority, mutate governance, or modify SBP-LEX runtime authority files.

## Allowed Commands

- `python main.py`
- `python main.py replay`
- `python -m sbp_pvpl.cli --runtime-root . --summary`
- `python -m sbp_oda.cli --health --runtime-root .`
- `python -m sbp_oda.cli --diagnostics --runtime-root .`

## Simulation Status Values

- `SIM_OK`
- `SIM_WARNING`
- `SIM_FAILED`
- `SIM_BLOCKED`
- `SIM_INCOMPLETE`
- `SIM_INVALID_FIXTURE`

Runtime decision words such as `ALLOW`, `DENY`, `ESCALATE`, `EXECUTE`, and `HALT` are not used as simulation statuses.

## Evidence Outputs

Each run writes:

- `fixture.json`
- `command_capture.json`
- `simulation_result.json`
- `reviewer_summary.md`

Generated evidence belongs under `runtime_artifacts/sim_01/`.

## Validation Results

- `python -m compileall -q .`: PASS
- `python -m pytest -q tests/simulation --basetemp runtime_artifacts/pytest_tmp_sim01`: PASS, 9 passed
- `python -m pytest -q tests/pvpl --basetemp runtime_artifacts/pytest_tmp_sim01_pvpl`: PASS, 23 passed
- `python -m pytest -q tests/oda --basetemp runtime_artifacts/pytest_tmp_sim01_oda`: PASS, 34 passed
- `python -m pytest -q tests/test_pqc_01_provider_contract.py --basetemp runtime_artifacts/pytest_tmp_sim01_pqc`: PASS, 10 passed
- `python -m pytest -q --basetemp runtime_artifacts/pytest_tmp_sim01_full`: PASS, 681 passed
- `python -m sbp_simulation.cli --list`: PASS
- `python -m sbp_simulation.cli --run MAIN_RUNTIME_SMOKE --out runtime_artifacts/sim_01/`: PASS, `SIM_OK`
- `python -m sbp_simulation.cli --run MAIN_REPLAY_SMOKE --out runtime_artifacts/sim_01/`: PASS, `SIM_OK`
- `python -m sbp_simulation.cli --run-suite smoke --out runtime_artifacts/sim_01/`: PASS, `SIM_OK`
- `python -m sbp_simulation.cli --verify runtime_artifacts/sim_01/`: PASS, `SIM_OK`
- `python -m sbp_oda.cli --diagnostics --runtime-root .`: PASS, `HARNESS_WARNING` due to existing dirty tree; `runtime_authority` remained `NONE`
- `python -m sbp_pvpl.cli --build-bundle --runtime-root . --out runtime_artifacts/pvpl_02/proof_bundle_after_sim01.json`: PASS, `PROOF_OK`
- `python -m sbp_pvpl.cli --verify-bundle --runtime-root . --bundle runtime_artifacts/pvpl_02/proof_bundle_after_sim01.json`: PASS, `PROOF_OK`
- `python main.py`: PASS, exit code 0
- `python main.py replay`: PASS, exit code 0

The first full pytest attempt timed out at 300 seconds while still progressing without visible failures. It was rerun with a 600 second timeout and passed.

## Remaining Limitations

- SIM-01 only captures existing controlled runtime and replay smoke behavior.
- SIM-01 does not activate Phase 19A traversal.
- SIM-01 does not publish externally or connect to blockchain, cloud, ledger, or network publication systems.
- SIM-01 does not certify production readiness.
- Later phases may add expanded fixture coverage, richer scenario taxonomy, and deeper PVPL bundle integration.
