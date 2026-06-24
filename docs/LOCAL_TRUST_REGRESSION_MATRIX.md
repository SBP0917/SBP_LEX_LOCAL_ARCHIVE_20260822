# Local Trust Regression Matrix

## Purpose

Phase 18.7E.1 adds a deterministic 25-year local trust regression matrix for SBP-LEX DUAL V6. The matrix checks that the local trust manifest, execution environment trust envelope, and evidence chain continue to detect implementation drift, evidence drift, stale provenance, and authority-boundary leakage without changing runtime behavior.

The matrix is local evidence tooling only. It is not Governance, Procedural Truth, SKG, DTN, an execution gate, or a runtime authority.

## Local Trust Problem

Local-only repositories can still drift. A local baseline can be undermined by a stale commit reference, wrong Python executable, dirty working tree, changed evidence artifact, overwritten report, mutated manifest, or generated cache/test artifact being mistaken for canonical evidence.

The regression matrix gives the repository a repeatable baseline for proving those risks remain detectable over time.

## Matrix Structure

The output file is:

```text
outputs/local_trust_regression_matrix.json
```

The matrix records:

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

JSON is canonicalised with stable key ordering before digesting. Status and validation fields are excluded from the payload digest so validation can be deterministic while still reporting current status.

## Regression Cases

Each case records:

```text
case_id
case_name
risk_category
target_artifact
mutation_type
expected_detection
actual_detection
status
reason
```

The matrix covers digest tampering, missing evidence, modified evidence, stale commit references, dirty working tree handling, missing bound artifacts, forbidden authority leakage, generated-output collection guards, temp/cache evidence exclusions, wrong Python provenance, future activation wording checks, Phase 19 non-start confirmation, and future-surface absence checks for nodes, quorum, mesh, distributed runtime, cloud, APK, V2, and V3.

All destructive or mutating checks are performed against copied objects or temporary files. The committed baseline artifacts are not edited by the regression runner.

## Status Meanings

```text
REGRESSION_MATRIX_VALID
REGRESSION_MATRIX_INVALID
REGRESSION_MATRIX_INCOMPLETE
REGRESSION_MATRIX_STALE
REGRESSION_MATRIX_DIRTY
REGRESSION_MATRIX_FAILED
```

Case statuses are:

```text
REGRESSION_CASE_PASS
REGRESSION_CASE_FAIL
REGRESSION_CASE_SKIPPED
REGRESSION_CASE_ERROR
```

`build` creates a structurally valid matrix with cases marked skipped. `run` executes deterministic copied-artifact checks and records pass/fail results.

## CLI

```bat
python -m sbp_lex.local_trust.regression_matrix build
python -m sbp_lex.local_trust.regression_matrix run
python -m sbp_lex.local_trust.regression_matrix validate
python -m sbp_lex.local_trust.regression_matrix show
```

The CLI does not call `python main.py`, replay, pytest, `scripts\run_tests.bat`, Governance, Procedural Truth, Execution Gate, Hard Entry Gate, SKG, or DTN.

## Relationship To 18.7B, 18.7C, 18.7D, And 18.7D.1

Phase 18.7B created the Local Trust Root Manifest. Phase 18.7C added the execution environment trust envelope. Phase 18.7D added report integrity attestation through the evidence chain. Phase 18.7D.1 cleaned the evidence baseline to zero missing evidence items.

Phase 18.7E.1 binds to those digests and verifies that detection behavior itself remains stable.

## Future 18.7E Work

This phase is a baseline regression matrix only. It does not begin Phase 19 and does not introduce runtime activation. Future local trust phases may extend the matrix, but this matrix remains evidence-only unless a later phase explicitly defines a new local evidence scope.

## Boundary

The regression matrix never emits runtime authority decisions such as ALLOW, DENY, ESCALATE, EXECUTE, or HALT. It reports only local regression and trust statuses.

No SBP-LEX runtime authority is changed. Governance, Procedural Truth, Execution Gate, Hard Entry Gate, SKG, and DTN remain unchanged. SKG and DTN remain external and non-authoritative.
