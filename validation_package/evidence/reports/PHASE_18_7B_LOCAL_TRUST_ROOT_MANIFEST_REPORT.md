# Phase 18.7B Local Trust Root Manifest Report

## Scope

Phase 18.7B adds local-only repository provenance tooling. It creates a deterministic Local Trust Root Manifest and validator so the repository can record what local baseline, Python runtime, Git commit, working-tree state, critical files, reports, and intended verification commands were used.

This phase does not alter SBP-LEX runtime authority or execution behavior.

## Files Added

- `sbp_lex/local_trust/__init__.py`
- `sbp_lex/local_trust/critical_paths.py`
- `sbp_lex/local_trust/file_digest.py`
- `sbp_lex/local_trust/git_provenance.py`
- `sbp_lex/local_trust/python_provenance.py`
- `sbp_lex/local_trust/manifest.py`
- `sbp_lex/local_trust/manifest_validator.py`
- `tests/test_phase_18_7b_local_trust_manifest.py`
- `docs/LOCAL_TRUST_ROOT_MANIFEST.md`
- `reports/PHASE_18_7B_LOCAL_TRUST_ROOT_MANIFEST_REPORT.md`

## Implementation Summary

- Added deterministic file hashing for critical files, reports, and known outputs.
- Added Git provenance capture for branch, commit, status, and clean/dirty state.
- Added Python provenance capture for executable path, version, and executable digest when available.
- Added command provenance for intended verification commands without executing them.
- Added deterministic JSON canonicalisation and digest/ML-DSA-65 signature binding.
- Added validator statuses:
  - `LOCAL_TRUST_VALID`
  - `LOCAL_TRUST_INVALID`
  - `LOCAL_TRUST_INCOMPLETE`
  - `LOCAL_TRUST_STALE`
  - `LOCAL_TRUST_DIRTY`
- Added authority-leakage detection for forbidden runtime-authority fields and values.

## Manifest Fields

The manifest records manifest identity, created timestamp, repository root, digest scope, Git provenance, Python provenance, command provenance, critical file hashes, trusted report hashes, trusted output hashes, integrity-store status, quarantine-evidence status, test baseline, runtime baseline, replay baseline, phase baseline, local trust status, validation failures, payload digest, manifest digest, ML-DSA signature envelope, and signature mode. Verification is pinned to an explicitly configured trusted public key.

## CLI Behavior

The CLI is:

```powershell
python -m sbp_lex.local_trust.manifest build
python -m sbp_lex.local_trust.manifest validate
python -m sbp_lex.local_trust.manifest show
```

Default output path:

```text
outputs/local_trust_root_manifest.json
```

The CLI does not call runtime traversal, replay, pytest, Hard Entry Gate, or any runtime state mutation.

## Tests Added

Added focused coverage for:

- successful manifest build
- repository root provenance
- Git commit and branch fields
- working tree status
- Python executable and version
- critical file hashing
- deterministic missing critical file records
- trusted report hashing
- deterministic missing output records
- manifest digest validation
- tamper detection
- dirty state with `clean_required=True`
- stale commit detection
- malformed manifest invalid status
- missing required sections incomplete status
- forbidden authority output detection
- CLI build
- CLI validate
- CLI show
- load/write round trip
- no runtime activation execution
- no runtime traversal call inside local trust package
- no replay call inside local trust package
- no pytest execution inside local trust package
- no prohibited topology terms in implementation

## Verification Results

- `python -m compileall -q .` passed with exit code 0.
  - Non-fatal notices were emitted for unreadable local pytest temporary/cache directories.
- `python -m pytest -q` passed: 268 passed, 1 pytest cache warning.
- `scripts\run_tests.bat` passed: 268 passed, 1 pytest cache warning.
- `python -m sbp_lex.local_trust.manifest build` passed.
  - Manifest status: `LOCAL_TRUST_VALID`.
  - Manifest path: `outputs/local_trust_root_manifest.json`.
- `python -m sbp_lex.local_trust.manifest validate` passed.
  - Manifest status: `LOCAL_TRUST_VALID`.
- `python -m sbp_lex.local_trust.manifest show` passed.
  - Commit: `b54103b907b26729cf09d4f2f8dab743cf9a691a`.
  - Branch: `main`.
  - Working tree clean: `False`, because Phase 18.7B files are uncommitted during this implementation pass.
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
- `git status --short` showed untracked Phase 18.7B additions:
  - `docs/LOCAL_TRUST_ROOT_MANIFEST.md`
  - `outputs/local_trust_root_manifest.json`
  - `reports/PHASE_18_7B_LOCAL_TRUST_ROOT_MANIFEST_REPORT.md`
  - `sbp_lex/local_trust/`
  - `tests/test_phase_18_7b_local_trust_manifest.py`

Bundled Codex Python runtime used:

```text
C:\Users\LeighMC\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe
```

Static boundary search of executable local trust implementation found no active prohibited runtime concepts. The only matching prohibited-output phrase was `external_governance_result` in the validator's forbidden-field rejection list, where it is intentionally treated as invalid authority leakage.

## Safety Boundaries Preserved

- No runtime activation introduced.
- No SBP-LEX runtime authority changed.
- No Governance authority changed.
- No Procedural Truth authority changed.
- No Execution Gate behavior changed.
- No Hard Entry Gate behavior changed.
- No SKG/DTN authority added.
- SKG/DTN remain external and non-authoritative.
- Local Trust Manifest is not an execution authority.
- No nodes, quorum, mesh, distributed runtime, cloud service, APK, V2, or V3 work introduced.
