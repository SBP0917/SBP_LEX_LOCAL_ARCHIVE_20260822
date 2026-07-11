# H8 Measured Startup, Runtime Identity and Drift Detection Report

## Mission identity

- Mission: H8A-H8F, Desktop V1 measured startup, runtime drift detection, approved runtime identity, critical configuration measurement, dependency measurement, and policy/schema measurement.
- Starting commit: `1c5d98cb9f881cb7b093a8a99b1a20fabd8dd238`.
- Ending commit: the single local commit containing this report (`git rev-parse HEAD` after commit is authoritative because a commit cannot embed its own hash).
- Scope: Desktop V1 only. The canonical architecture, deterministic replay topology, single-node/no-node rule, and detached ODA/cognitive boundaries are unchanged.

## Measurement architecture

`sbp_lex.runtime.measured_startup` deterministically inventories the approved runtime state using sorted relative paths, SHA-256 file measurements, canonical structured digests, strict JSON parsing, bounded file/cardinality limits, path-containment checks, and symlink rejection.

The approved baseline measures:

| Category | Coverage | Approved digest |
|---|---|---|
| Software | `main.py` and 178 critical `sbp_lex` Python modules | `dd2ba5e785c3b76ff9dec82e93a0640eb4752e825c7b25a41e6ed5316e99faf8` |
| Configuration | 9 runtime/API/security configuration inputs | `3050a28c1236357f6d2c8ebb17d7f177d5528a26de181de0928e66635b32d6a6` |
| Policy | 8 policy, rules, threshold, and execution-gate files | `93da9c8a77e2921a169e30fe107dc162b65673a9384630f6701218c15a149cf4` |
| Schema | 22 Desktop V1, external-substrate, and fixture schemas/validators | `2722e53c6a413efc5bdae94ade622fccc4b9b84fefe4a03132f53226596ee32b` |
| Trust store | 7 local-trust evidence outputs | `674922c02dc56c3b2d43bf5237ac58ea8692439268f4ae1486eb2909d661f471` |
| Protected documentation | 5 already-protected architecture/security documents | `56d811c9906134cbb1c7006becd2ad9420d91ad5e60ae44194e6fbb5f81e710a` |
| Startup environment | Explicit API, transport, security, admission, and execution variables | `aa59d644e72828d818e77b990bb17c8efdf7f825d3e2a1f2b4deaa76e7ea73a4` |
| Dependencies | Declared and installed versions for `cryptography` and `pytest` | `2e13f1b088cf891af9f71b4e2412d0656564115d18961a11e2d8c9e666d573aa` |
| Executable | CPython executable bytes, implementation, version, and architecture | `56a041a547219740405cb93acab71f2cb5a3536a80f6627cd256a8e8c614bcaf` |

The approved aggregate measurement digest is `df028f7e61fae199743986a08e5ac586aea6aaa9c65991250080e53a7870e000`. The executable is CPython 3.12.13 AMD64 with SHA-256 `3c6a206b7d93cca823934a83732220dcffd413fd1036d9fb82eebb64599cf7f3`.

Ignored runtime/test directories are not eligible schema roots. Detached ODA schemas are also outside the runtime identity, preserving the canonical boundary. Unexpected files added within an approved measurement root remain critical drift.

## Runtime identity design

The deterministic identity is domain-separated from the baseline identifier and the configuration, environment, dependency, policy, schema, software, trust-store, documentation, and executable digests. It contains no raw secret. Sensitive environment values are represented only by a domain-separated digest, presence state, and length.

The approved identity is:

`4d98a432fb391f0fbf6525e04f06eb752a4098d399c8a80d56c455922ddde3cf`

Startup time is deliberately excluded from the deterministic identity. A signed startup attestation separately binds that identity, approved baseline identifier, baseline-store digest, UTC startup timestamp, and monotonic local sequence. The local anchor binds baseline generation and lineage for replacement/rollback detection.

## Drift classes and startup validation

- `approved`: every required category and aggregate measurement matches the approved baseline.
- `warning`: represented by the model but never used to waive a required measurement mismatch.
- `critical`: known security-relevant mismatch, identity mismatch, baseline mismatch, rollback, or changed measured state.
- `unknown`: malformed/corrupt/missing state, partial measurement failure, invalid cardinality, unreadable input, or an unclassifiable integrity failure.

Critical and unknown drift fail closed. The API server validates after selecting its security mode but before transport validation, persistent security-state creation, server construction, socket creation, or listener binding. Canonical traversal and replay validate before engine execution and remeasure on every operation. Failure produces a stable `measured_startup_failed:<class>:<reason>` diagnostic plus bounded in-memory audit evidence and a signed local failure record containing digests rather than secrets.

## Baseline model

Baseline states are `PENDING`, `APPROVED`, and `RETIRED`. Stores require strict schema, a single approved record, unique identifiers, monotonic sequence/generation, measurement integrity, deterministic identity agreement, and an integrity signature. A proposal cannot become approved without an explicit approval reference and exact retirement identifier.

This mission exercised the real transition rather than silently replacing the baseline:

| Sequence | Identifier | Final state | Purpose |
|---|---|---|---|
| 1 | `DESKTOP_V1_H8_APPROVED_2026_07_11_01` | `RETIRED` | Provisional H8 state before the required local-trust builders refreshed protected outputs |
| 2 | `DESKTOP_V1_H8_APPROVED_2026_07_11_02` | `APPROVED` | Final reconciled code, configuration, dependency, policy, schema, documentation, environment, executable, and protected trust-output state |

The store is at generation 3. The final approval reference is `H8_MISSION_EXPLICIT_LOCAL_TRUST_REFRESH_1C5D98C`; the new record names the retired identifier as its prior baseline. Changed measurements are never auto-accepted.

## Adversarial tests

Thirty H8 tests cover approved startup; configuration, policy, schema, trust-store, software, dependency, environment, and executable mutation; deleted and unexpected files; category/hash and runtime-identity mismatch; requested-baseline mismatch; invalid, missing, corrupt, and duplicate baselines; pending-state rejection; explicit update approval; partial measurement failure; replay; rollback; anchor/store corruption; secret non-disclosure; attestation binding; runtime drift after startup; listener fail-closed ordering; and canonical traversal/replay fail-closed behavior.

Focused reconciliation results were 65/65 for H8 plus runtime/persistence integration and 39/39 for H8 plus ODA boundary verification. The full repository suite and batch entry point each passed 1,069/1,069.

## Verification commands and results

| Command or command group | Result |
|---|---|
| `python -m compileall -q .` | PASS |
| `python -m pytest -q --basetemp=runtime_artifacts\\pytest_tmp_main` | PASS, 1,069 tests in 256.35 seconds |
| `scripts\\run_tests.bat` with bundled Python and workspace-local `TEMP`/`TMP` | PASS, 1,069 tests in 291.66 seconds |
| Manifest build/validate/show | `LOCAL_TRUST_VALID` |
| Execution envelope build/validate/show | `EXECUTION_ENV_VALID` |
| Evidence chain build/validate/compare/show | `EVIDENCE_CHAIN_VALID`, `changed_evidence_items=0`, 15 items, 0 missing |
| Regression matrix build/run/validate/show | `REGRESSION_MATRIX_VALID`, 19/19 |
| Constitutional gates evaluate/validate/show | `CONSTITUTIONAL_GATES_PASS`, 24/24 |
| Toolchain guard build/validate/show | `TOOLCHAIN_GUARD_PASS`, 39/39 |
| Capstone build/validate/show | `LOCAL_TRUST_CAPSTONE_PASS` |
| Validation dossier build/validate/show | `VALIDATION_DOSSIER_READY`, 32 claims and 50 evidence artifacts |
| Release integrity build/validate/show | `RELEASE_INTEGRITY_PASS`, 38/38 required artifacts |
| Adversarial negative harness run/validate/show | `ADVERSARIAL_NEGATIVE_HARNESS_PASS`, 39/39 |
| Measured baseline propose/approve/validate/show | `MEASURED_STARTUP_APPROVED`, `MEASURED_BASELINE_VALID` |
| `python main.py` | PASS, `ALLOW` / `EXECUTE`, convergence matched |
| `python main.py replay` | PASS, two runs matched, no mismatches |
| `git diff --check` | PASS in final pre-commit verification |

The first direct batch invocation could not discover Python; the next invocation discovered Python but the sandbox denied pytest's user-profile temp root. The successful recorded invocation changed no repository script: it prepended the bundled Python directory and directed `TEMP`/`TMP` to `runtime_artifacts/batch_temp` for that process.

## Security properties

- Required state is measured before listener binding and before canonical execution.
- Missing, unreadable, corrupt, rolled-back, replaced, or mismatched required state cannot silently continue.
- Runtime identity is deterministic, baseline-bound, and secret-free.
- Startup timestamp evidence is bound without making replay identity nondeterministic.
- File collection is sorted, contained, cardinality-bounded, and symlink rejecting.
- Baseline changes require a pending record, explicit approval, and retirement lineage.
- Runtime and replay retain the existing canonical deterministic results.
- No listener, node, distributed topology, public deployment, or cognitive capability was added.

## Remaining limitations

- This is application-level measured startup, not TPM measured boot, Secure Boot, an external transparency log, or hardware-backed remote attestation.
- The local integrity signer and baseline live within the Desktop V1 trust boundary. Host compromise that can replace both application code and its trust material requires operating-system controls and trusted software delivery to contain.
- Dependency measurement binds declared requirements and installed versions, not every byte of every transitive package. Critical local Python module bytes and the Python executable are measured.
- Environment coverage is an explicit security/runtime allowlist. A newly introduced environment-controlled behavior must be added to the measurement policy in the same approved change.
- Drift is checked before startup/listener binding and before each traversal/replay; there is no filesystem watcher between operations and no in-memory process-injection detector.

## Desktop V1 and no-node confirmation

Desktop V1 architecture remains unchanged: the same canonical runtime, pipelines, gates, local persistence, listener implementation, and deterministic replay are used. H8 adds only a fail-closed measurement prerequisite and status evidence. The ODA boundary checker passes, the constitutional and toolchain gates pass, no cognitive path is changed, and no node or distributed topology exists or was introduced.

No GitHub operation or push was performed by this mission.
