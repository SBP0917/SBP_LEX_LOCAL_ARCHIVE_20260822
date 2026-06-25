# Adversarial Local Trust Negative-Test Harness

## Purpose

Phase 18.7G adds a deterministic adversarial negative-test harness for the local trust and release integrity evidence line.

The release integrity package created in 18.7F proves that the clean review bundle can be assembled and validated. The adversarial harness proves the opposite side of the trust story: corrupted, missing, stale, dirty, overclaiming, or boundary-violating artifacts are detected or rejected.

This package is local evidence tooling only. It is not SBP-LEX runtime authority, Governance, Procedural Truth, Execution Gate, Hard Entry Gate, SKG, or DTN.

## Why Negative Testing Follows Release Integrity

A validation bundle is incomplete if it only demonstrates the happy path. Reviewers need evidence that the package fails correctly when attacked or weakened.

18.7G tests copied artifacts, not the committed baseline artifacts. The real repository outputs remain unchanged while the harness mutates temporary copies and records whether the expected detector rejected the bad state.

## Relationship To Prior Local Trust Phases

18.7D.1 removed deterministic missing-evidence ambiguity from the evidence chain.

18.7E.1 introduced regression cases for local trust drift.

18.7E.2 introduced constitutional gates for local trust pre-flight guardrails.

18.7E.3 introduced dependency and toolchain guard evidence.

18.7E.4 introduced the 25-year local trust capstone.

18.7F introduced the release integrity bundle for reproducible review readiness.

18.7G consumes those artifacts and proves negative failure modes are detected.

## Case Structure

Each adversarial case records:

```text
case_id
case_name
case_category
target_artifact
attack_type
mutation_method
expected_detection
actual_detection
expected_result
actual_result
status
reason
```

`ADVERSARIAL_CASE_PASS` means the bad state was correctly detected or rejected.

`ADVERSARIAL_CASE_FAIL` means the bad state was not detected as expected.

`ADVERSARIAL_CASE_SKIPPED` means the case was intentionally not run.

`ADVERSARIAL_CASE_ERROR` means the harness itself hit an unexpected error.

## Attack Simulation Model

The harness uses temporary copied artifacts and in-memory mutations. It does not destructively mutate committed baseline outputs.

Attack categories include:

```text
missing artifact
digest tamper
required evidence item removal
changed evidence hash
failed regression case
failed constitutional gate
toolchain drift
dependency digest mutation
release manifest tamper
release artifact mismatch
verification command removal
claims-to-evidence overclaim
boundary false-claim
dirty working tree simulation
stale commit simulation
```

## Boundary Violation Categories

The harness includes negative cases for false claims about:

```text
external validation
certification
Phase 19
runtime activation
runtime authority leakage
nodes/quorum/mesh/distributed/cloud/APK/V2/V3 implementation
```

These are negative-test inputs only. They are not active implementation concepts.

## What Pass Means

`ADVERSARIAL_NEGATIVE_HARNESS_PASS` means all required adversarial cases passed, the harness digest validates, the case summary is internally consistent, and the expected failure-mode coverage is present.

It does not mean external validation, certification, university review, legal review, patent validity, security certification, runtime activation, or production readiness occurred.

## What Fail Means

`ADVERSARIAL_NEGATIVE_HARNESS_FAIL` means at least one adversarial case, digest, summary, boundary confirmation, or schema check failed.

`ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE` means required schema or case coverage is missing.

`ADVERSARIAL_NEGATIVE_HARNESS_STALE` means current validation found the harness commit reference no longer matches the current repository commit.

`ADVERSARIAL_NEGATIVE_HARNESS_DIRTY` means clean-required validation found the recorded local state dirty.

## Phase 19 Boundary

Phase 19 remains not started. 18.7G is not a runtime activation phase and does not grant execution permission.

## Strict Runtime Boundary

The adversarial harness must not call:

```text
python main.py
python main.py replay
pytest
scripts\run_tests.bat
Hard Entry Gate
Governance
Execution Gate
SKG
DTN
```

Those commands remain external verification commands. The harness records local trust negative-test evidence only.

## Transition To 18.8

After 18.7G is completed, verified, committed, and pushed, the next phase is:

```text
18.8 — Master Claims-to-Evidence Index / University Validation Dossier
```

18.8 is not implemented by this phase.

