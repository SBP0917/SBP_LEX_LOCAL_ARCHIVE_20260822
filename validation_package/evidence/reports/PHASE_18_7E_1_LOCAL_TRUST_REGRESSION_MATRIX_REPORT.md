# Phase 18.7E.1 Local Trust Regression Matrix Report

## Files Changed

```text
sbp_lex/local_trust/__init__.py
sbp_lex/local_trust/regression_cases.py
sbp_lex/local_trust/regression_matrix.py
sbp_lex/local_trust/regression_runner.py
sbp_lex/local_trust/regression_validator.py
tests/test_phase_18_7e_1_local_trust_regression_matrix.py
docs/LOCAL_TRUST_REGRESSION_MATRIX.md
reports/PHASE_18_7E_1_LOCAL_TRUST_REGRESSION_MATRIX_REPORT.md
outputs/local_trust_regression_matrix.json
```

## Implementation Summary

Phase 18.7E.1 adds a deterministic local trust regression matrix that binds the Phase 18.7B manifest digest, Phase 18.7C execution envelope digest, and Phase 18.7D evidence chain digest.

The matrix checks copied or temporary artifacts only. It does not mutate the committed manifest, execution envelope, evidence chain, reports, or runtime artifacts.

## Matrix Fields

```text
matrix_type
matrix_version
created_at
repository_root
git_commit
git_branch
git_status_short
working_tree_clean
bound_manifest_digest
bound_execution_envelope_digest
bound_evidence_chain_digest
regression_cases
regression_summary
matrix_payload_digest
matrix_digest
matrix_signature
signature_mode
matrix_status
validation_failures
```

## CLI Behavior

```bat
python -m sbp_lex.local_trust.regression_matrix build
python -m sbp_lex.local_trust.regression_matrix run
python -m sbp_lex.local_trust.regression_matrix validate
python -m sbp_lex.local_trust.regression_matrix show
```

`build` writes a valid skipped-case skeleton. `run` performs deterministic copied-artifact checks. `validate` validates canonical digests and case structure. `show` prints a concise matrix summary.

The CLI does not call runtime, replay, pytest, batch tests, Governance, Procedural Truth, Execution Gate, Hard Entry Gate, SKG, or DTN.

## Tests Added

```text
tests/test_phase_18_7e_1_local_trust_regression_matrix.py
```

Coverage includes matrix build, run, digest validation, tamper detection, stale and dirty status checks, missing required sections, required case coverage, CLI build/run/validate/show, and static boundary checks against runtime/replay/test execution inside the regression package.

## Expected Matrix Output

```text
outputs/local_trust_regression_matrix.json
```

Expected status after `run`:

```text
REGRESSION_MATRIX_VALID
```

Expected case summary:

```text
total_cases=19
passed_cases=19
failed_cases=0
skipped_cases=0
error_cases=0
```

## Safety Boundaries Preserved

No runtime activation was introduced.

No SBP-LEX runtime authority was changed.

Governance behavior was unchanged.

Procedural Truth behavior was unchanged.

Execution Gate behavior was unchanged.

Hard Entry Gate behavior was unchanged.

SKG and DTN remain external and non-authoritative.

No nodes, quorum, mesh, distributed runtime, cloud, APK, V2, or V3 work was introduced.

Phase 19 remains not started.

## Final Verification

```text
python -m compileall -q .                                  PASS
python -m pytest -q                                        PASS, 341 passed
scripts\run_tests.bat                                      PASS, 341 passed
python -m sbp_lex.local_trust.manifest validate            LOCAL_TRUST_VALID
python -m sbp_lex.local_trust.execution_envelope validate  EXECUTION_ENV_VALID
python -m sbp_lex.local_trust.evidence_chain validate      EVIDENCE_CHAIN_VALID
python -m sbp_lex.local_trust.evidence_chain compare       EVIDENCE_CHAIN_VALID, changed_evidence_items=0
python -m sbp_lex.local_trust.regression_matrix build      REGRESSION_MATRIX_VALID
python -m sbp_lex.local_trust.regression_matrix run        REGRESSION_MATRIX_VALID
python -m sbp_lex.local_trust.regression_matrix validate   REGRESSION_MATRIX_VALID
python -m sbp_lex.local_trust.regression_matrix show       REGRESSION_MATRIX_VALID
python main.py                                             PASS
python main.py replay                                      PASS, matched=true, mismatches=[]
git diff --check                                           PASS
```

`python -m pytest -q` and `scripts\run_tests.bat` used:

```text
PYTEST_ADDOPTS=--ignore=outputs --ignore-glob=.pytest_tmp_* --ignore-glob=*sbp_lex_local_trust_pytest_basetemp --ignore-glob=outputs/local_trust_temp/*
```

This avoids collecting stale generated output and temporary local-trust folders.

The bundled Codex Python runtime was used:

```text
C:\Users\LeighMC\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
```

## Final Matrix Result

```text
matrix_status=REGRESSION_MATRIX_VALID
matrix_digest=99c4559c82d0064d14c949ecafbcd64f79e16d8135c1b9046bb0ad85ef9a6976
total_cases=19
passed_cases=19
failed_cases=0
skipped_cases=0
error_cases=0
bound_manifest_digest=de939d9e8776f1fbd6399f5b920c19ebe6cffbf84e0eb899fe506338564742a8
bound_execution_envelope_digest=1cff5e9e7656da0e27645c14c96a43fc886598266139ed46dbb1be874e4c7d6c
bound_evidence_chain_digest=e7cb82f7bb26fb489b09b6f739e58ebda70bad4916c0603bafeed8a706bab979
```
