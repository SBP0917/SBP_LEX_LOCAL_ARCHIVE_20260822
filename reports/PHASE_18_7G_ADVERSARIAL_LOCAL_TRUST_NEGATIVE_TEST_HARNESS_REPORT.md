# Phase 18.7G Adversarial Local Trust Negative-Test Harness Report

## Files Changed

```text
sbp_lex/local_trust/__init__.py
sbp_lex/local_trust/adversarial_cases.py
sbp_lex/local_trust/adversarial_negative_harness.py
sbp_lex/local_trust/adversarial_runner.py
sbp_lex/local_trust/adversarial_validator.py
tests/test_phase_18_7g_adversarial_local_trust_negative_harness.py
docs/ADVERSARIAL_LOCAL_TRUST_NEGATIVE_TEST_HARNESS.md
reports/PHASE_18_7G_ADVERSARIAL_LOCAL_TRUST_NEGATIVE_TEST_HARNESS_REPORT.md
outputs/adversarial_local_trust_negative_harness.json
```

## Implementation Summary

Phase 18.7G adds a deterministic adversarial negative-test harness for local trust and release integrity artifacts. The harness runs required negative cases against temporary copied artifacts and in-memory mutations, records whether the expected detector rejected the bad state, and writes a hash-bound output artifact.

The harness does not call runtime, replay, pytest, the batch test runner, Governance, Execution Gate, Hard Entry Gate, SKG, or DTN.

## Adversarial Output Path

```text
outputs/adversarial_local_trust_negative_harness.json
```

## Adversarial Summary

```text
adversarial_status=ADVERSARIAL_NEGATIVE_HARNESS_PASS
adversarial_digest=d2f92f2e45b158b3435da5ece9e2dfb799d196d621db7eb64299a63c4e8754cf
case_count=39
passed_case_count=39
failed_case_count=0
skipped_case_count=0
artifact_mutation_cases=18
release_integrity_mutation_cases=8
boundary_violation_cases=4
forbidden_authority_leakage_cases=2
phase_19_boundary_cases=2
```

## Bound Digests

```text
bound_manifest_digest=de939d9e8776f1fbd6399f5b920c19ebe6cffbf84e0eb899fe506338564742a8
bound_execution_envelope_digest=1cff5e9e7656da0e27645c14c96a43fc886598266139ed46dbb1be874e4c7d6c
bound_evidence_chain_digest=e7cb82f7bb26fb489b09b6f739e58ebda70bad4916c0603bafeed8a706bab979
bound_regression_matrix_digest=99c4559c82d0064d14c949ecafbcd64f79e16d8135c1b9046bb0ad85ef9a6976
bound_constitutional_gates_digest=88a6a8fe1bd15c172150f1ec348324255398536f056a83a4715daddb9562c31f
bound_toolchain_guard_digest=71fa1b4b2004376767d0511167e18aac049507f5b95e9f9b05842db0752745aa
bound_capstone_digest=a244e1f359948176208c948939f433b3f9879ed8d42371f11f1270d0dca527cc
bound_release_integrity_digest=9ed12bd8857c46eb7b2a210da29fe030d4c6c2b16d81d50380c5839a407794e1
```

## Verification Summary

```text
python -m compileall -q .: PASS
python -m pytest -q: PASS, 533 passed
scripts\run_tests.bat: PASS, 533 passed
manifest validate: LOCAL_TRUST_VALID
execution envelope validate: EXECUTION_ENV_VALID
evidence chain validate: EVIDENCE_CHAIN_VALID
evidence chain compare: EVIDENCE_CHAIN_VALID, changed_evidence_items=0
regression matrix validate/show: REGRESSION_MATRIX_VALID
constitutional gates evaluate/validate/show: CONSTITUTIONAL_GATES_PASS
toolchain guard build/validate/show: TOOLCHAIN_GUARD_PASS
local trust capstone build/validate/show: LOCAL_TRUST_CAPSTONE_PASS
release integrity build/validate/show: RELEASE_INTEGRITY_PASS
adversarial harness run/validate/show: ADVERSARIAL_NEGATIVE_HARNESS_PASS
runtime result: PASS, decision=ALLOW, execution_result=EXECUTE
replay result: PASS, matched=true, mismatches=[]
static prohibited executable-term scan: PASS
git diff --check: PASS
```

The bundled Codex Python runtime was used:

```text
C:\Users\LeighMC\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
```

Generated-output pytest ignores were used:

```text
--ignore=outputs --ignore-glob=.pytest_tmp_* --ignore-glob=*sbp_lex_local_trust_pytest_basetemp --ignore-glob=outputs/local_trust_temp/*
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

18.8 is marked as next phase only.

18.8 was not implemented.
