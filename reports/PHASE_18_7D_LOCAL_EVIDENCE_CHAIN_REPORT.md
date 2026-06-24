# Phase 18.7D Local Evidence Chain Report

## Scope

Phase 18.7D adds local-only evidence chain and report integrity attestation tooling. It hashes known phase reports, trusted output artifacts, local trust manifests, execution envelopes, and documentation so local evidence drift is detectable after verification.

This phase does not alter SBP-LEX runtime authority or execution behavior.

## Files Added

- `sbp_lex/local_trust/evidence_chain.py`
- `sbp_lex/local_trust/evidence_chain_validator.py`
- `sbp_lex/local_trust/evidence_registry.py`
- `sbp_lex/local_trust/report_attestation.py`
- `tests/test_phase_18_7d_local_evidence_chain.py`
- `docs/LOCAL_EVIDENCE_CHAIN_REPORT_INTEGRITY_ATTESTATION.md`
- `reports/PHASE_18_7D_LOCAL_EVIDENCE_CHAIN_REPORT.md`

## Files Updated

- `sbp_lex/local_trust/__init__.py`

## Implementation Summary

- Added deterministic evidence item hashing for phase reports, trusted outputs, manifests, envelopes, and documentation.
- Added missing evidence recording rather than silent omission.
- Added manifest binding to `outputs/local_trust_root_manifest.json`.
- Added execution envelope binding to `outputs/local_execution_environment_trust_envelope.json`.
- Added chain digest and placeholder signature binding using the existing local trust canonical JSON rules.
- Added compare mode to detect modified, missing, replaced, or newly appeared evidence files.
- Added validator statuses:
  - `EVIDENCE_CHAIN_VALID`
  - `EVIDENCE_CHAIN_INVALID`
  - `EVIDENCE_CHAIN_INCOMPLETE`
  - `EVIDENCE_CHAIN_STALE`
  - `EVIDENCE_CHAIN_DIRTY`

## Evidence Chain Fields

The evidence chain records chain identity, version, created timestamp, repository root, Git commit, Git branch, working-tree state, bound manifest path/digest/status, bound execution envelope path/digest/status, evidence scope, evidence items, missing evidence items, excluded volatile paths, payload digest, chain digest, signature placeholder, signature mode, evidence chain status, and validation failures.

## Evidence Item Categories

Supported categories include phase report, implementation report, manifest, execution envelope, commit report, replay evidence, runtime evidence, trusted output, quarantine evidence, and documentation. The initial registry covers the required Phase 18 through Phase 18.7C reports, trusted outputs, local trust manifest, execution envelope, and local trust documentation.

## Manifest Binding Result

The chain binds to `outputs/local_trust_root_manifest.json`.

Final bound manifest digest:

```text
de939d9e8776f1fbd6399f5b920c19ebe6cffbf84e0eb899fe506338564742a8
```

## Execution Envelope Binding Result

The chain binds to `outputs/local_execution_environment_trust_envelope.json`.

Final bound execution envelope digest:

```text
1cff5e9e7656da0e27645c14c96a43fc886598266139ed46dbb1be874e4c7d6c
```

## CLI Behavior

The CLI is:

```powershell
python -m sbp_lex.local_trust.evidence_chain build
python -m sbp_lex.local_trust.evidence_chain validate
python -m sbp_lex.local_trust.evidence_chain show
python -m sbp_lex.local_trust.evidence_chain compare
```

Default output path:

```text
outputs/local_evidence_chain.json
```

The CLI validates evidence files only. It does not call runtime traversal, replay, pytest, the batch test runner, Hard Entry Gate, Governance, Execution Gate, SKG, or DTN.

## Tests Added

Added focused coverage for chain build, repository provenance, manifest binding, execution envelope binding, evidence hashing, deterministic missing evidence, excluded path behavior, digest validation, tamper detection, changed evidence comparison, missing/invalid binding handling, forbidden authority leakage, stale/dirty status handling, CLI build/validate/show/compare, import safety, non-execution of runtime/replay/pytest, and prohibited topology/runtime term absence.

## Verification Results

- `python -m compileall -q .` passed with exit code 0.
  - Non-fatal notices were emitted for old local pytest temporary directories.
- `python -m pytest -q` passed: 318 passed.
  - `PYTEST_ADDOPTS=--ignore=outputs --basetemp=.pytest_tmp_full_18_7d_final` was used so generated evidence outputs and stale temp folders were not collected.
- `scripts\run_tests.bat` passed: 318 passed.
  - The bundled Codex Python runtime directory was prepended to `PATH`.
  - `PYTEST_ADDOPTS=--ignore=outputs --basetemp=.pytest_tmp_bat_18_7d_final` was used.
- `python -m sbp_lex.local_trust.manifest validate` passed.
  - Manifest status: `LOCAL_TRUST_VALID`.
- `python -m sbp_lex.local_trust.execution_envelope validate` passed.
  - Execution envelope status: `EXECUTION_ENV_VALID`.
- `python -m sbp_lex.local_trust.evidence_chain build` passed.
  - Evidence chain status: `EVIDENCE_CHAIN_VALID`.
  - Evidence chain path: `outputs/local_evidence_chain.json`.
- `python -m sbp_lex.local_trust.evidence_chain validate` passed.
  - Evidence chain status: `EVIDENCE_CHAIN_VALID`.
- `python -m sbp_lex.local_trust.evidence_chain show` passed.
  - Commit: `6ac6314d9590c34f5a3a9e8f304bb51f8a4428c2`.
  - Branch: `main`.
  - Evidence items: 15.
  - Missing evidence items: 1.
- `python -m sbp_lex.local_trust.evidence_chain compare` passed.
  - Evidence chain status: `EVIDENCE_CHAIN_VALID`.
  - Changed evidence items: 0.
- `python main.py` passed.
  - Runtime decision remained the existing deterministic runtime output.
  - Audit hash: `f76139687e3db432edfda4c9eb34d27dea6ad28cef3e59d8cbf419f58b95ea9d`.
  - Pipeline mode: `MODE_2_SPLIT_VALIDATOR`.
  - Convergence matched: `true`.
- `python main.py replay` passed.
  - Replay count: 2.
  - Matched: `true`.
  - Mismatches: none.
- `git diff --check` passed.
- `git status --short` showed Phase 18.7D working-tree additions and modifications:
  - `.gitignore`
  - `docs/LOCAL_EVIDENCE_CHAIN_REPORT_INTEGRITY_ATTESTATION.md`
  - `outputs/local_evidence_chain.json`
  - `reports/PHASE_18_7D_LOCAL_EVIDENCE_CHAIN_REPORT.md`
  - `sbp_lex/local_trust/__init__.py`
  - `sbp_lex/local_trust/command_capture.py`
  - `sbp_lex/local_trust/evidence_chain.py`
  - `sbp_lex/local_trust/evidence_chain_validator.py`
  - `sbp_lex/local_trust/evidence_registry.py`
  - `sbp_lex/local_trust/report_attestation.py`
  - `tests/test_phase_18_7d_local_evidence_chain.py`

Final evidence chain digest:

```text
459d9f36b74436510635769dd06e8cf80cce0608be5c5c30095d7fa8a68d6b9d
```

Evidence scope:

```text
expected_item_count=15
present_item_count=14
missing_item_count=1
```

Deterministic missing evidence item:

```text
outputs/SBP_OPERATOR_ASSISTANT_V1_COMMIT_AND_TEST_REPORT.md
```

Bundled Codex Python runtime used:

```text
C:\Users\LeighMC\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
```

Static boundary search of executable local trust implementation found no active prohibited runtime concepts. The only matching prohibited-output phrase was `external_governance_result` in the 18.7B validator's forbidden-field rejection list, where it is intentionally treated as invalid authority leakage.

## Safety Boundaries Preserved

- No runtime activation introduced.
- No SBP-LEX runtime authority changed.
- No Governance authority changed.
- No Procedural Truth authority changed.
- No Execution Gate behavior changed.
- No Hard Entry Gate behavior changed.
- No SKG/DTN authority added.
- SKG/DTN remain external and non-authoritative.
- Local Evidence Chain is not an execution authority.
- No nodes, quorum, mesh, distributed runtime, cloud service, APK, V2, or V3 work introduced.
- Phase 19 remains not started.
