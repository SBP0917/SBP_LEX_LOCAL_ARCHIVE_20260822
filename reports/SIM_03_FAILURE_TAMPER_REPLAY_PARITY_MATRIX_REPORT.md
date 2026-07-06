# SIM-03 Failure / Tamper / Replay / Parity Matrix Report

Draft status: repository-contained implementation report.

## Purpose

SIM-03 adds a controlled failure matrix for the SBP-LEX simulation evidence layer. It proves artifact-level and fixture-level detection paths for unsafe commands, invalid scenario mappings, unknown scenarios, tampered copied artifacts, replay mismatch artifacts, parity mismatch fixtures, token evidence tamper, hash-chain tamper, missing evidence, forbidden publication activation flags, and PVPL tampered-bundle compatibility.

## Implemented

- Added deterministic canonical JSON and digest helpers.
- Added 11 failure test definitions.
- Added controlled evidence writing under `runtime_artifacts/sim_03/`.
- Added failure matrix index, result, and reviewer summary outputs.
- Added PVPL compatibility check through CLI subprocess only, without importing PVPL.
- Added CLI commands:
  - `python -m sbp_simulation.cli --list-failure-tests`
  - `python -m sbp_simulation.cli --run-failure-test UNSAFE_COMMAND_BLOCK --out runtime_artifacts/sim_03/`
  - `python -m sbp_simulation.cli --run-failure-test PARITY_MISMATCH_FIXTURE --out runtime_artifacts/sim_03/`
  - `python -m sbp_simulation.cli --run-failure-test PVPL_BUNDLE_TAMPER_COMPATIBILITY --out runtime_artifacts/sim_03/`
  - `python -m sbp_simulation.cli --run-failure-matrix --out runtime_artifacts/sim_03/`
  - `python -m sbp_simulation.cli --verify-failure-matrix runtime_artifacts/sim_03/`
- Added SIM-03 tests under `tests/simulation/`.

## Not Implemented

- No Phase 19A runtime activation.
- No runtime token/hash-chain tamper proof.
- No full-dual runtime parity proof.
- No production readiness claim.
- No runtime authority pathway.
- No ODA/PVPL/PQC code modification.
- No validation dossier modification.

## Failure Test List

| Failure Test | Detection Mode | Proof Level |
| --- | --- | --- |
| UNSAFE_COMMAND_BLOCK | safe command policy block | artifact/policy |
| INVALID_RISK_MODE_MAPPING | schema validation rejection | artifact/schema |
| UNKNOWN_SCENARIO_BLOCK | unknown lookup block | artifact/schema |
| SCENARIO_RESULT_TAMPER | canonical digest mismatch | artifact |
| REPLAY_RESULT_MISMATCH_ARTIFACT | replay mismatch fields detected | artifact |
| PARITY_MISMATCH_FIXTURE | branch digest mismatch | fixture |
| TOKEN_SIGNATURE_TAMPER_ARTIFACT | token digest/signature mismatch | artifact |
| HASH_CHAIN_TAMPER_ARTIFACT | chain link mismatch | artifact |
| REQUIRED_EVIDENCE_MISSING | missing required file reference | artifact |
| FORBIDDEN_PUBLICATION_ACTIVATION | forbidden activation flags blocked | boundary |
| PVPL_BUNDLE_TAMPER_COMPATIBILITY | PVPL verify does not return PROOF_OK | compatibility |

## Artifact-Level Versus Runtime-Level

SIM-03 detection is artifact-level or fixture-level unless explicitly stated otherwise. Replay mismatch, parity mismatch, token tamper, and hash-chain tamper include `PHASE19A_RUNTIME_REQUIRED` notes because runtime-level proof requires controlled traversal activation in a later phase.

## Evidence Outputs

For each failure test:

- `failure_test_definition.json`
- `original_artifact_copy.json` when applicable
- `tampered_artifact.json` when applicable
- `verification_result.json`
- `reviewer_failure_summary.md`

Matrix-level outputs:

- `runtime_artifacts/sim_03/failure_matrix_index.json`
- `runtime_artifacts/sim_03/failure_matrix_result.json`
- `runtime_artifacts/sim_03/reviewer_failure_matrix_summary.md`

## No-Plastic Safeguards

- Original SIM-02 and PVPL source artifacts are copied before mutation.
- Tampered artifacts are written only under `runtime_artifacts/sim_03/`.
- Failure statuses do not use `ALLOW`, `DENY`, `ESCALATE`, `EXECUTE`, or `HALT`.
- PVPL compatibility uses the PVPL CLI only; `sbp_simulation` does not import `sbp_pvpl`.
- Runtime-level proof is not claimed where only artifact-level evidence exists.

## Boundary Proof

SIM-03 remains local/private artifact-level failure validation only. It is not production activation, external actuation, runtime authority, public publication, or Phase 19A runtime proof.

## Validation Results

- `python -m compileall -q .`: PASS
- `python -m pytest -q tests/simulation --basetemp runtime_artifacts/pytest_tmp_sim03`: PASS, 30 passed
- `python -m pytest -q tests/pvpl --basetemp runtime_artifacts/pytest_tmp_sim03_pvpl`: PASS, 23 passed
- `python -m pytest -q tests/oda --basetemp runtime_artifacts/pytest_tmp_sim03_oda`: PASS, 34 passed
- `python -m pytest -q tests/test_pqc_01_provider_contract.py --basetemp runtime_artifacts/pytest_tmp_sim03_pqc`: PASS, 10 passed
- `python -m pytest -q --basetemp runtime_artifacts/pytest_tmp_sim03_full`: PASS, 702 passed
- `python -m sbp_simulation.cli --list`: PASS
- `python -m sbp_simulation.cli --list-scenarios`: PASS
- `python -m sbp_simulation.cli --validate-scenario-library`: PASS, `SIM_OK`
- `python -m sbp_simulation.cli --run-scenario-library --out runtime_artifacts/sim_02_regression/`: PASS, `SIM_OK`
- `python -m sbp_simulation.cli --list-failure-tests`: PASS
- `python -m sbp_simulation.cli --run-failure-test UNSAFE_COMMAND_BLOCK --out runtime_artifacts/sim_03/`: PASS, `FAILURE_TEST_BLOCKED`
- `python -m sbp_simulation.cli --run-failure-test PARITY_MISMATCH_FIXTURE --out runtime_artifacts/sim_03/`: PASS, `FAILURE_TEST_DETECTED`
- `python -m sbp_simulation.cli --run-failure-test PVPL_BUNDLE_TAMPER_COMPATIBILITY --out runtime_artifacts/sim_03/`: PASS, `FAILURE_TEST_DETECTED`
- `python -m sbp_simulation.cli --run-failure-matrix --out runtime_artifacts/sim_03/`: PASS, `FAILURE_MATRIX_OK`
- `python -m sbp_simulation.cli --verify-failure-matrix runtime_artifacts/sim_03/`: PASS, `FAILURE_MATRIX_OK`
- `python -m sbp_simulation.cli --run-suite smoke --out runtime_artifacts/sim_01_regression_after_sim03/`: PASS, `SIM_OK`
- `python -m sbp_oda.cli --diagnostics --runtime-root .`: PASS, `HARNESS_WARNING` due to existing dirty tree; `runtime_authority` remained `NONE`
- `python -m sbp_pvpl.cli --build-bundle --runtime-root . --out runtime_artifacts/pvpl_02/proof_bundle_after_sim03.json`: PASS, `PROOF_OK`
- `python -m sbp_pvpl.cli --verify-bundle --runtime-root . --bundle runtime_artifacts/pvpl_02/proof_bundle_after_sim03.json`: PASS, `PROOF_OK`
- `python main.py`: PASS, exit code 0
- `python main.py replay`: PASS, exit code 0

One `--verify-failure-matrix` attempt ran in parallel before the matrix result file had been written and returned `failure_matrix_result_missing`. It was rerun sequentially after the matrix completed and passed with `FAILURE_MATRIX_OK`.

## Confirmations

- No runtime authority files changed for SIM-03.
- No ODA code changed for SIM-03.
- No PVPL code changed for SIM-03.
- No PQC code changed for SIM-03.
- No validation dossier files changed for SIM-03.
- Nothing staged, committed, or pushed by SIM-03.
