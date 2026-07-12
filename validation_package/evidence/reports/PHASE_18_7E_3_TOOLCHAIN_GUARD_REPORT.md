# Phase 18.7E.3 Toolchain Guard Report

## Files Changed

```text
sbp_lex/local_trust/__init__.py
sbp_lex/local_trust/command_policy.py
sbp_lex/local_trust/toolchain_guard.py
sbp_lex/local_trust/toolchain_inventory.py
sbp_lex/local_trust/toolchain_policy.py
sbp_lex/local_trust/toolchain_validator.py
tests/test_phase_18_7e_3_toolchain_guard.py
docs/LOCAL_TRUST_TOOLCHAIN_GUARD.md
reports/PHASE_18_7E_3_TOOLCHAIN_GUARD_REPORT.md
outputs/local_toolchain_guard.json
outputs/local_constitutional_gates.json (refreshed by required constitutional_gates evaluate)
```

## Implementation Summary

Phase 18.7E.3 adds a deterministic local dependency and toolchain guard. It captures Python, pytest, pip, dependency file digests, installed package metadata, verification command policy, pytest ignore policy, temp/cache exclusion policy, and bindings to the manifest, execution envelope, evidence chain, regression matrix, and constitutional gates.

The toolchain guard records verification environment readiness only. It does not run runtime, replay, pytest, batch tests, Governance, Execution Gate, Hard Entry Gate, SKG, or DTN.

## Toolchain Policy Summary

Policy version:

```text
LOCAL_TRUST_TOOLCHAIN_POLICY_V1
```

The policy requires Python evidence, pytest evidence, dependency file digest evidence, command policy evidence, generated-output collection policy, temp/cache exclusion policy, local trust artifact bindings, forbidden-authority boundary checks, future-surface absence checks, and Phase 19 boundary preservation.

## Toolchain Guard Fields

```text
toolchain_guard_type
toolchain_guard_version
created_at
repository_root
git_commit
git_branch
python_executable
python_version
python_prefix
python_base_prefix
platform
pytest_version
pip_version_if_available
dependency_files
dependency_file_digests
installed_package_snapshot
verification_command_policy
pytest_collection_policy
ignored_output_paths
ignored_temp_paths
bound_manifest_digest
bound_execution_envelope_digest
bound_evidence_chain_digest
bound_regression_matrix_digest
bound_constitutional_gates_digest
toolchain_checks
toolchain_summary
toolchain_payload_digest
toolchain_digest
toolchain_signature
signature_mode
toolchain_status
validation_failures
```

## Check Categories

```text
python
pytest
pip
dependencies
command_policy
pytest_policy
temp_policy
binding
repository
boundary
```

## Runtime And Dependency Evidence

Python executable:

```text
C:\Users\LeighMC\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
```

Python version:

```text
3.12.13 (main, Mar  3 2026, 15:01:35) [MSC v.1944 64 bit (AMD64)]
```

pytest version:

```text
9.1.1
```

Dependency files detected:

```text
requirements.txt
```

Dependency file digest:

```text
requirements.txt=12e4ba4731303c0dcc1abdc162dc954cf2a48f4926d468a0259bc8072a12ba0c
```

## Bound Digests

```text
bound_manifest_digest=de939d9e8776f1fbd6399f5b920c19ebe6cffbf84e0eb899fe506338564742a8
bound_execution_envelope_digest=1cff5e9e7656da0e27645c14c96a43fc886598266139ed46dbb1be874e4c7d6c
bound_evidence_chain_digest=e7cb82f7bb26fb489b09b6f739e58ebda70bad4916c0603bafeed8a706bab979
bound_regression_matrix_digest=99c4559c82d0064d14c949ecafbcd64f79e16d8135c1b9046bb0ad85ef9a6976
bound_constitutional_gates_digest=5ef81bbc776f7e89c8d7b11965ca460b2649bda43bee4fa4498a0e9e7e259e5e
```

## Final Toolchain Guard Result

```text
status=TOOLCHAIN_GUARD_PASS
digest=911121c8aaa724490edd64d92a8658ce1779baa4ea6b1b33e9c2cc2eb4934852
checks=39
passed=39
failed=0
skipped=0
errors=0
```

## CLI Behavior

```bat
python -m sbp_lex.local_trust.toolchain_guard build
python -m sbp_lex.local_trust.toolchain_guard validate
python -m sbp_lex.local_trust.toolchain_guard show
```

`build` writes `outputs/local_toolchain_guard.json`. `validate` validates schema, digest, bindings, required checks, and boundary rules. `show` prints a concise toolchain status summary.

## Tests Added

```text
tests/test_phase_18_7e_3_toolchain_guard.py
```

Focused tests cover artifact bindings, digest validation, tamper detection, Python and pytest evidence, dependency file digests, verification command policy, pytest ignore policy, temp/cache policy, forbidden authority rejection, boundary checks, CLI build/validate/show, import safety, command-execution absence, prohibited active-term absence, and runtime authority file non-modification.

## Verification Results

```text
python -m compileall -q .: PASS
python -m pytest -q: PASS, 399 passed
scripts\run_tests.bat: PASS, 399 passed
python -m sbp_lex.local_trust.manifest validate: LOCAL_TRUST_VALID
python -m sbp_lex.local_trust.execution_envelope validate: EXECUTION_ENV_VALID
python -m sbp_lex.local_trust.evidence_chain validate: EVIDENCE_CHAIN_VALID
python -m sbp_lex.local_trust.evidence_chain compare: EVIDENCE_CHAIN_VALID, changed_evidence_items=0
python -m sbp_lex.local_trust.regression_matrix validate: REGRESSION_MATRIX_VALID
python -m sbp_lex.local_trust.constitutional_gates evaluate: CONSTITUTIONAL_GATES_PASS
python -m sbp_lex.local_trust.constitutional_gates validate: CONSTITUTIONAL_GATES_PASS
python -m sbp_lex.local_trust.toolchain_guard build: TOOLCHAIN_GUARD_PASS
python -m sbp_lex.local_trust.toolchain_guard validate: TOOLCHAIN_GUARD_PASS
python -m sbp_lex.local_trust.toolchain_guard show: TOOLCHAIN_GUARD_PASS
python main.py: PASS, decision=ALLOW, execution_result=EXECUTE
python main.py replay: PASS, matched=true, mismatches=[]
git diff --check: PASS
static prohibited executable concept search: PASS
```

`compileall` emitted known non-fatal list warnings for ignored stale local temp/cache folders. Pytest and batch verification were run with `PYTEST_ADDOPTS=--ignore=outputs --ignore-glob=.pytest_tmp_* --ignore-glob=*sbp_lex_local_trust_pytest_basetemp --ignore-glob=outputs/local_trust_temp/*` and scratch cache/base-temp paths outside the repository output payloads.

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
