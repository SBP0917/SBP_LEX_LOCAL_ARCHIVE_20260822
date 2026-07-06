# BASELINE-01 Evidence Spine Baseline Report

## Baseline Name

Evidence Spine Baseline - Pre-Blueprint / Pre-Phase19A

## Included Phase List

- NP-03A wording / manifest corrections
- ODA-02 evidence-grade onsite deployment assistant
- PVPL-02 evidence-grade local proof verification layer
- SIM-01 controlled simulation harness
- SIM-02 controlled scenario library
- SIM-03 failure / tamper / replay / parity matrix
- PQC provider contract and documentation alignment

## Files Included By Category

### ODA-02

- `sbp_oda/`
- `tests/oda/`
- `reports/ODA_02_EVIDENCE_GRADE_ONSITE_DEPLOYMENT_ASSISTANT_REPORT.md`
- `reports/ODA_V1_SKELETON_IMPLEMENTATION_REPORT.md`

### PVPL-02

- `sbp_pvpl/`
- `tests/pvpl/`
- `reports/PVPL_02_EVIDENCE_GRADE_LOCAL_PROOF_LAYER_REPORT.md`
- `reports/PVPL_V1_SKELETON_IMPLEMENTATION_REPORT.md`

### SIM-01 / SIM-02 / SIM-03

- `sbp_simulation/`
- `tests/simulation/`
- `reports/SIM_01_CONTROLLED_SIMULATION_HARNESS_REPORT.md`
- `reports/SIM_02_CONTROLLED_SCENARIO_LIBRARY_REPORT.md`
- `reports/SIM_03_FAILURE_TAMPER_REPLAY_PARITY_MATRIX_REPORT.md`

### PQC Provider Contract And Documentation

- `sbp_lex/security/pqc.py`
- `sbp_lex/security/pqc_policy.py`
- `sbp_lex/security/pqc_provider.py`
- `sbp_lex/config/security_config.py`
- `sbp_lex/api/schema_validation.py`
- `tests/test_pqc_01_provider_contract.py`
- `reports/PQC_01_REAL_PROVIDER_CONTRACT_REPORT.md`
- `requirements.txt`
- `README.md`
- `START_HERE.md`
- `DEPLOYMENT_SECURITY.md`
- `docs/UNIVERSITY_VALIDATION_DOSSIER.md`
- `outputs/university_validation_dossier/UNIVERSITY_HANDOFF_README.md`
- `outputs/university_validation_dossier/REVIEWER_VERIFICATION_COMMANDS.json`
- `outputs/university_validation_dossier/DOSSIER_MANIFEST.json`
- `reports/EIE_PT_SKG_DTN_CONTROL_PLANE_HANDOVER_READINESS_REPORT.md`

### Baseline Report

- `reports/BASELINE_01_EVIDENCE_SPINE_PRE_PHASE19A_REPORT.md`

## Files Excluded By Category

### Generated Runtime Artifacts

- `runtime_artifacts/pytest_tmp*`
- `runtime_artifacts/sim_01/`
- `runtime_artifacts/sim_02/`
- `runtime_artifacts/sim_03/`
- `runtime_artifacts/sim_01_baseline_regression/`
- `runtime_artifacts/sim_02_baseline_regression/`
- `runtime_artifacts/sim_03_baseline_regression/`
- `runtime_artifacts/pvpl_02/`
- `runtime_artifacts/oda_02/`

### Temp / Cache

- `.pytest_cache/`
- `__pycache__/`
- `*.pyc`

### Human Review / Not Baseline Scope

- `baselines/`
- `reports/PHASE_IMPLEMENTATION_RECONCILIATION_AUDIT.md`

## Runtime Authority Change Review

No unexpected runtime authority changes were included. The only `sbp_lex/` changes selected for this baseline are the previously validated PQC provider contract, PQC policy/provider modules, security configuration, and schema validation changes named in the BASELINE-01 scope.

`main.py` was not modified or staged.

## ODA Status

- ODA diagnostics: `HARNESS_WARNING` because the tree was intentionally dirty before staging.
- ODA runtime authority: `NONE`
- ODA boundary check: `HARNESS_OK`

## PVPL Status

- PVPL baseline bundle build: `PROOF_OK`
- PVPL baseline bundle verify: `PROOF_OK`

## Simulation Status

- SIM-01 smoke regression: `SIM_OK`
- SIM-02 scenario library validation: `SIM_OK`
- SIM-02 scenario evidence generation: `SIM_OK`
- SIM-03 failure matrix: `FAILURE_MATRIX_OK`
- SIM-03 failure matrix verification: `FAILURE_MATRIX_OK`

## PQC Provider Status

- PQC provider contract tests: 10 passed
- Provider status reported by ODA dependency diagnostics: `PQC_PROVIDER_AVAILABLE`
- `cryptography` provider version observed: `49.0.0`

## Test Results

### Pre-Stage Validation

- `python -m compileall -q .`: PASS
- `python -m pytest -q tests/simulation --basetemp runtime_artifacts/pytest_tmp_baseline01_sim`: PASS, 30 passed
- `python -m pytest -q tests/pvpl --basetemp runtime_artifacts/pytest_tmp_baseline01_pvpl`: PASS, 23 passed
- `python -m pytest -q tests/oda --basetemp runtime_artifacts/pytest_tmp_baseline01_oda`: PASS, 34 passed
- `python -m pytest -q tests/test_pqc_01_provider_contract.py --basetemp runtime_artifacts/pytest_tmp_baseline01_pqc`: PASS, 10 passed
- `python -m pytest -q --basetemp runtime_artifacts/pytest_tmp_baseline01_full`: PASS, 702 passed

## Runtime Smoke Results

- `python main.py`: PASS, exit code 0, controlled runtime output returned `convergence_matched: true`

## Replay Results

- `python main.py replay`: PASS, exit code 0, replay output returned `matched: true`

## Boundary Confirmations

- No blueprint alignment was started.
- Phase 19A was not started.
- Simulation remains runtime-detached.
- ODA remains runtime-detached with `runtime_authority: NONE`.
- PVPL remains local/private proof tooling.
- No production/live/external actuation was added.
- No generated runtime evidence is intended for commit.

## Generated Artifacts Policy

`.gitignore` already excludes generated runtime artifacts, pytest cache, Python bytecode, and temporary trust outputs. `git ls-files runtime_artifacts` returned no tracked runtime artifacts. Generated validation outputs were preserved locally but excluded from baseline staging.

## Known Next Phases

- BLUEPRINT-ALIGN-01
- Phase 19A
- Phase 19B
- TEST-01
- HANDOVER-01
