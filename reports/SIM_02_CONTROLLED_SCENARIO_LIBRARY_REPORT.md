# SIM-02 Controlled Scenario Library Report

Draft status: repository-contained implementation report.

## Purpose

SIM-02 adds a controlled LOW / MEDIUM / TOP scenario library on top of the SIM-01 harness. It defines reviewer-ready scenario fixtures for future controlled traversal activation without claiming that Phase 19A runtime traversal has already occurred.

## Implemented

- Added SIM-02 scenario schema and validation.
- Added adaptive traversal mapping enforcement:
  - LOW -> SINGLE_PIPELINE
  - MEDIUM -> SPLIT_VALIDATOR
  - TOP -> FULL_DUAL
- Added 13 controlled scenario definitions.
- Added scenario index counts by risk tier, traversal mode, expected outcome, runtime-backed state, and Phase 19A dependency.
- Added CLI commands:
  - `python -m sbp_simulation.cli --list-scenarios`
  - `python -m sbp_simulation.cli --show-scenario LOW_ALLOW_ROUTINE_STATUS_CHECK`
  - `python -m sbp_simulation.cli --show-scenario TOP_PARITY_MISMATCH_BLOCK`
  - `python -m sbp_simulation.cli --validate-scenario-library`
  - `python -m sbp_simulation.cli --run-scenario-library --out runtime_artifacts/sim_02/`
- Extended `python -m sbp_simulation.cli --verify` to validate SIM-02 scenario evidence outputs.
- Added focused scenario tests under `tests/simulation/`.

## Not Implemented

- No Phase 19A traversal activation.
- No full dual runtime traversal proof.
- No production or live execution claim.
- No external actuation.
- No public publication.
- No runtime authority pathway.
- No ODA/PVPL code modification.
- No validation dossier modification.

## Scenario List

| Scenario | Risk | Traversal | Expected Outcome |
| --- | --- | --- | --- |
| LOW_ALLOW_ROUTINE_STATUS_CHECK | LOW | SINGLE_PIPELINE | EXPECT_ALLOW |
| LOW_DENY_MISSING_REQUIRED_TOKEN | LOW | SINGLE_PIPELINE | EXPECT_DENY |
| LOW_REPLAY_MATCH | LOW | SINGLE_PIPELINE | EXPECT_REPLAY_MATCH |
| MEDIUM_ALLOW_SPLIT_VALIDATOR_CONFIG_REVIEW | MEDIUM | SPLIT_VALIDATOR | EXPECT_ALLOW |
| MEDIUM_ESCALATE_CORROBORATION_SHORTFALL | MEDIUM | SPLIT_VALIDATOR | EXPECT_ESCALATE |
| MEDIUM_DENY_LICENSE_SCOPE_MISMATCH | MEDIUM | SPLIT_VALIDATOR | EXPECT_DENY |
| MEDIUM_REPLAY_MATCH | MEDIUM | SPLIT_VALIDATOR | EXPECT_REPLAY_MATCH |
| TOP_ALLOW_FULL_DUAL_FULLY_VALIDATED | TOP | FULL_DUAL | EXPECT_ALLOW |
| TOP_DENY_GOVERNANCE_AUTHORITY_FAIL | TOP | FULL_DUAL | EXPECT_DENY |
| TOP_ESCALATE_AUTHORITY_CONFLICT | TOP | FULL_DUAL | EXPECT_ESCALATE |
| TOP_HALT_TOKEN_SIGNATURE_TAMPER | TOP | FULL_DUAL | EXPECT_HALT |
| TOP_PARITY_MISMATCH_BLOCK | TOP | FULL_DUAL | EXPECT_PARITY_FAIL |
| TOP_REPLAY_MATCH | TOP | FULL_DUAL | EXPECT_REPLAY_MATCH |

## Coverage

| Risk Tier | Count |
| --- | ---: |
| LOW | 3 |
| MEDIUM | 4 |
| TOP | 6 |

| Traversal Mode | Count |
| --- | ---: |
| SINGLE_PIPELINE | 3 |
| SPLIT_VALIDATOR | 4 |
| FULL_DUAL | 6 |

| Expected Outcome | Count |
| --- | ---: |
| EXPECT_ALLOW | 3 |
| EXPECT_DENY | 3 |
| EXPECT_ESCALATE | 2 |
| EXPECT_HALT | 1 |
| EXPECT_PARITY_FAIL | 1 |
| EXPECT_REPLAY_MATCH | 3 |

## Phase 19A And Runtime Backing

- `phase19a_required_count`: 13
- `runtime_backed_count`: 0

All SIM-02 scenarios are definition-ready only. They are marked `SCENARIO_READY_FOR_PHASE_19A` with `runtime_execution_status` of `NOT_EXECUTED_PHASE19A_REQUIRED` when evidence is generated.

## Evidence Outputs

For each scenario, SIM-02 writes:

- `scenario_fixture.json`
- `scenario_validation.json`
- `scenario_result.json`
- `reviewer_scenario_summary.md`

Output root:

- `runtime_artifacts/sim_02/`

## No-Plastic Safeguards

- Scenario validation rejects invalid risk tiers, traversal modes, expected outcomes, missing Phase 19A flags, and invalid adaptive traversal mappings.
- SIM-02 does not mark Phase 19A-required scenarios as runtime-backed.
- SIM-02 does not use `ALLOW`, `DENY`, `ESCALATE`, `EXECUTE`, or `HALT` as simulation or scenario statuses.
- Runtime decision words appear only as expected outcome categories or captured runtime observations from SIM-01 smoke commands.
- Scenario evidence states the boundary between definition readiness and runtime proof.

## Boundary Proof

SIM-02 remains local/private controlled validation only. It is not production activation, external actuation, runtime authority, a university validation result, or public publication.

## Validation Results

- `python -m compileall -q .`: PASS
- `python -m pytest -q tests/simulation --basetemp runtime_artifacts/pytest_tmp_sim02`: PASS, 19 passed
- `python -m pytest -q tests/pvpl --basetemp runtime_artifacts/pytest_tmp_sim02_pvpl`: PASS, 23 passed
- `python -m pytest -q tests/oda --basetemp runtime_artifacts/pytest_tmp_sim02_oda`: PASS, 34 passed
- `python -m pytest -q tests/test_pqc_01_provider_contract.py --basetemp runtime_artifacts/pytest_tmp_sim02_pqc`: PASS, 10 passed
- `python -m pytest -q --basetemp runtime_artifacts/pytest_tmp_sim02_full`: PASS, 691 passed
- `python -m sbp_simulation.cli --list`: PASS
- `python -m sbp_simulation.cli --list-scenarios`: PASS, 13 scenarios
- `python -m sbp_simulation.cli --show-scenario LOW_ALLOW_ROUTINE_STATUS_CHECK`: PASS
- `python -m sbp_simulation.cli --show-scenario TOP_PARITY_MISMATCH_BLOCK`: PASS
- `python -m sbp_simulation.cli --validate-scenario-library`: PASS, `SIM_OK`
- `python -m sbp_simulation.cli --run-scenario-library --out runtime_artifacts/sim_02/`: PASS, `SIM_OK`
- `python -m sbp_simulation.cli --verify runtime_artifacts/sim_02/`: PASS, `SIM_OK`, 13 scenario results
- `python -m sbp_simulation.cli --run-suite smoke --out runtime_artifacts/sim_01_regression/`: PASS, `SIM_OK`
- `python -m sbp_oda.cli --diagnostics --runtime-root .`: PASS, `HARNESS_WARNING` due to existing dirty tree; `runtime_authority` remained `NONE`
- `python -m sbp_pvpl.cli --build-bundle --runtime-root . --out runtime_artifacts/pvpl_02/proof_bundle_after_sim02.json`: PASS, `PROOF_OK`
- `python -m sbp_pvpl.cli --verify-bundle --runtime-root . --bundle runtime_artifacts/pvpl_02/proof_bundle_after_sim02.json`: PASS, `PROOF_OK`
- `python main.py`: PASS, exit code 0
- `python main.py replay`: PASS, exit code 0

One PVPL verification attempt was run in parallel with runtime smoke commands and reported digest mismatches for `runtime_artifacts` and `audit_integrity_store`. The bundle was rebuilt after runtime smoke completion and then verified sequentially with `PROOF_OK`.

## Confirmations

- No runtime authority files changed for SIM-02.
- No ODA code changed for SIM-02.
- No PVPL code changed for SIM-02.
- No validation dossier files changed for SIM-02.
- Nothing staged, committed, or pushed by SIM-02.
