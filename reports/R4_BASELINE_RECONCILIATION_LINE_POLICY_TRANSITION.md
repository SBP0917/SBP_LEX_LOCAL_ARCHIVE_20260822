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
- explicit binary treatment for binary assets and packages.

A genuinely independent `--no-local` clone on branch `main`, with inherited
`core.autocrlf=true`, produced:

- 799 LF text files;
- two CRLF Windows batch files;
- one explicit binary file;
- zero mixed text files;
- exact worktree-to-Git-blob matches for all 315 measured paths.

## Controlled measured-baseline transition

- Successor: `DESKTOP_V1_R4_RECONCILED_APPROVED_2026_07_16_18`
- Sequence: 18
- Status: `APPROVED`
- Created UTC: `2026-07-16T07:02:44+00:00`
- Approval reference:
  `R4_BASELINE_RECONCILIATION_LINE_POLICY_A3FC47C_2026_07_16`
- Prior baseline: `DESKTOP_V1_R4_APPROVED_2026_07_13_17`
- Prior baseline disposition: retained as historical evidence and marked
  `RETIRED` by the normal baseline transition mechanism
- Measurement digest:
  `a410600adc3a941aa5465c6d99c99a7fe99de4681eda1ed5e4e7213940246ba3`
- Runtime identity:
  `b22d4056a28821f54e642cc731ff86b1561d7aa7eae05f4e3f14ba15630e1903`

The baseline was measured in the independent fresh `main` clone at policy
source commit `a3fc47c922501f42e00bcdc8ec11943936502db1`. The baseline-store transition
commit necessarily follows that source commit because a commit cannot embed its
own final identity.

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
  --identifier DESKTOP_V1_R4_RECONCILED_APPROVED_2026_07_16_18

python -m sbp_lex.runtime.measured_startup approve \
  --identifier DESKTOP_V1_R4_RECONCILED_APPROVED_2026_07_16_18 \
  --retire DESKTOP_V1_R4_APPROVED_2026_07_13_17 \
  --approval-reference R4_BASELINE_RECONCILIATION_LINE_POLICY_A3FC47C_2026_07_16
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
