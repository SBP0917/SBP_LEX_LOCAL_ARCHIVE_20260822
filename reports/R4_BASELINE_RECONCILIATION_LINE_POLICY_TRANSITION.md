# R4 Baseline Reconciliation and Line-Policy Transition

## Purpose

This transition corrects the checkout-representation defect proven during the
bounded Windows R4 reconciliation. It does not change runtime architecture,
authority, provenance enforcement, branch validation, measured-startup logic,
or tests.

## Proven defect

The retired R4 baseline measured raw bytes from a clean but historically mixed
working tree. The tracked Git blobs were LF, while a Windows clone governed only
by `core.autocrlf=true` rendered most text as CRLF. Seventeen apparent content
mismatches and 68 CRLF-only mismatches were therefore checkout representation
failures, not semantic repository regressions.

## Repository-owned checkout policy

Policy source commit:
`a3fc47c922501f42e00bcdc8ec11943936502db1`.

The root `.gitattributes` now defines:

- LF checkout bytes for repository text;
- CRLF checkout bytes for Windows `.bat` and `.cmd` launchers;
- CRLF preservation for the Local Trust, adversarial, release-integrity, and
  university-dossier generators that emit CRLF, including their copied IVVP
  evidence; generators that emit LF remain explicitly under the default LF
  policy;
- explicit binary treatment for binary assets and packages.

A genuinely independent `--no-local` clone on branch `main`, with inherited
`core.autocrlf=true`, produced:

- 799 LF text files before the generated-evidence exception was exercised;
- two CRLF Windows batch files;
- one explicit binary file;
- zero mixed text files;
- exact worktree-to-Git-blob matches for all 315 measured paths.

The generated-evidence exception was added before final evidence commit after
verification proved that normalizing generated CRLF bytes would invalidate
embedded package hashes. It changes no semantic content and makes the generator
output representation explicit and reproducible.

## Controlled measured-baseline transition

- Final successor: `DESKTOP_V1_R4_RECONCILED_FINAL_2026_07_16_19`
- Sequence: 19
- Status: `APPROVED`
- Created UTC: `2026-07-16T07:11:57+00:00`
- Approval reference:
  `R4_RECONCILED_FINAL_LOCAL_TRUST_85AE1AF_2026_07_16`
- Prior baseline: `DESKTOP_V1_R4_RECONCILED_APPROVED_2026_07_16_18`
- Historical baselines: sequences 17 and 18 are retained and marked `RETIRED`
  by the normal baseline transition mechanism
- Measurement digest:
  `56d08812faded67aa0a73f391ed0b8c7df0f059d320ff201835df60e23e625b3`
- Runtime identity:
  `23c34e088901d64b86decb98114fd71932c02d60816cf3890e84dc4daf53ec58`

Sequence 18 was measured in the independent fresh `main` clone at policy source
commit `a3fc47c922501f42e00bcdc8ec11943936502db1`. It provided the controlled bridge
needed to refresh the seven measured Local Trust outputs. Sequence 19 then
measured the refreshed outputs at transition source commit
`85ae1af085170f48f438fda547a303c5721110ee`. The final evidence commit
necessarily follows that source commit because a commit cannot embed its own
final identity.

## Runtime and dependencies

- Executable:
  `C:\Users\LeighMC\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`
- Executable SHA-256:
  `3c6a206b7d93cca823934a83732220dcffd413fd1036d9fb82eebb64599cf7f3`
- Runtime: CPython 3.12.13, AMD64
- `cryptography`: declared `>=49.0.0`, measured `49.0.0`
- `pytest`: declared `>=8.0.0`, measured `9.1.1`
- `PYTEST_ADDOPTS`: removed
- `PYTHONPATH`: removed

The executable is the exact R4-approved runtime. Its location remains a shared
Codex cache path and must not be represented as an independently provisioned or
permanent distribution path.

## Creation commands

```text
python -m sbp_lex.runtime.measured_startup propose \
  --identifier DESKTOP_V1_R4_RECONCILED_FINAL_2026_07_16_19

python -m sbp_lex.runtime.measured_startup approve \
  --identifier DESKTOP_V1_R4_RECONCILED_FINAL_2026_07_16_19 \
  --retire DESKTOP_V1_R4_RECONCILED_APPROVED_2026_07_16_18 \
  --approval-reference R4_RECONCILED_FINAL_LOCAL_TRUST_85AE1AF_2026_07_16
```

## Pre-commit verification

The existing baseline manager returned:

```text
MEASURED_BASELINE_PENDING
MEASURED_BASELINE_APPROVED
MEASURED_BASELINE_VALID
MEASURED_STARTUP_APPROVED
```

No test, runtime module, provenance rule, or branch-validation rule was added,
changed, removed, weakened, or converted to a skip by this transition.

Full Windows verification remains gated on validation from a second fresh
`main` clone containing the committed successor store.
