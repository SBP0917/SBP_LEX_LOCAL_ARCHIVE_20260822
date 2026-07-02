# University Validation Dossier

## Purpose

Phase 18.8 creates a reviewer-facing university validation dossier for the SBP-LEX Desktop V1 local trust evidence line.

The dossier translates local trust, release integrity, and adversarial negative-test artifacts into bounded review questions. It is intended to help reviewers see what is being claimed, which artifacts support each claim, which commands can be run, and which areas are explicitly outside the review scope.

This dossier is local evidence tooling only. It is not external certification, university validation result, legal advice, patent validity confirmation, security certification, government approval, cloud deployment, or Phase 19. It now includes repository evidence for the EIE / SKG / DTN / Root of Trust / Procedural Truth / Execution Gate rebuild, but the dossier itself is not runtime authority.

## Why Claims-To-Evidence Mapping Is Required

By the end of 18.7G, the repository contains local trust manifests, execution environment evidence, an evidence chain, regression checks, constitutional gates, toolchain guard evidence, a capstone, a release integrity bundle, and adversarial negative-test evidence.

Those artifacts are strong but dense. A reviewer should not need to infer:

```text
what claims are being made
which artifacts support each claim
which commands verify each claim
which scope boundaries are excluded
which future phases have not been implemented
which claims need narrowing
```

The master claims-to-evidence index makes that mapping explicit and deterministic.

## Relationship To Prior Phases

18.7D.1 removed deterministic missing-evidence ambiguity from the local evidence chain.

18.7E.1 introduced the local trust regression matrix for drift detection.

18.7E.2 introduced constitutional enforcement gates and local trust pre-flight guardrails.

18.7E.3 introduced the dependency and toolchain guard.

18.7E.4 introduced the 25-year local trust capstone.

18.7F introduced the release integrity package.

18.7G introduced the adversarial local trust negative-test harness.

18.8 consumes those artifacts and creates a university handoff dossier. This handover update also binds the EIE / PT / SKG / DTN rebuild addenda, focused rebuild tests, and control-plane handover readiness report into the dossier evidence set. It does not replace or weaken any of the underlying validators.

## EIE / PT / SKG / DTN Handover Update

The dossier now includes bounded claims and reviewer questions for:

```text
EIE as canonical traversal state
SKG truth-foundation enrichment
DTN contextual and operational enrichment
Root of Trust Anchorage binding
Procedural Truth Evidentiary Sufficiency certification
Execution Gate PT certification enforcement
Audit/replay metadata preservation
```

The added evidence artifacts include:

```text
docs/blueprint_addenda/
reports/EIE_PT_SKG_DTN_CONTROL_PLANE_HANDOVER_READINESS_REPORT.md
tests/test_eie_pt_sufficiency_rebuild.py
```

## Dossier Structure

The generated dossier is written to:

```text
outputs/university_validation_dossier/
```

Required files:

```text
DOSSIER_MANIFEST.json
MASTER_CLAIMS_TO_EVIDENCE_INDEX.json
VALIDATION_QUESTIONS.json
EVIDENCE_ARTIFACT_INDEX.json
SCOPE_AND_EXCLUSIONS_LOCK.json
REVIEWER_VERIFICATION_COMMANDS.json
UNIVERSITY_HANDOFF_README.md
```

`DOSSIER_MANIFEST.json` binds the repository commit, branch, GitHub remote, sync status, source phase, local trust artifact digests, release integrity digest, adversarial harness digest, dossier references, dossier payload digest, dossier digest, signature placeholder, status, and validation failures.

Expected status:

```text
VALIDATION_DOSSIER_READY
```

Other statuses are:

```text
VALIDATION_DOSSIER_FAIL
VALIDATION_DOSSIER_INCOMPLETE
VALIDATION_DOSSIER_STALE
VALIDATION_DOSSIER_DIRTY
```

## Claim Structure

Each claim in `MASTER_CLAIMS_TO_EVIDENCE_INDEX.json` records:

```text
claim_id
claim_text
claim_category
claim_scope
claim_status
supporting_evidence_artifacts
supporting_verification_commands
expected_validation_answer
reviewer_validation_question
exclusions
notes
```

Claim status values:

```text
CLAIM_READY_FOR_REVIEW
CLAIM_INCOMPLETE
CLAIM_OUT_OF_SCOPE
```

The claims are bounded. They do not state that a university has already validated the project, that certification exists, or that production readiness has been proven.

## Validation Question Structure

Each entry in `VALIDATION_QUESTIONS.json` records:

```text
question_id
question_text
related_claim_ids
evidence_artifacts
verification_commands
expected_answer
reviewer_notes
```

The questions ask reviewers to confirm whether specific evidence supports specific claims. One question explicitly invites reviewers to identify unsupported, overbroad, ambiguous, or narrowing-required claims.

## Evidence Artifact Index

`EVIDENCE_ARTIFACT_INDEX.json` records the evidence set used by the dossier. Each artifact entry includes:

```text
artifact_id
artifact_group
path
exists
size_bytes
sha256
required
related_claim_ids
reason
```

The index includes local trust artifacts, release integrity artifacts, adversarial negative-test output, EIE/PT rebuild addenda, the handover readiness report, focused rebuild tests, and the dossier's own reviewer-facing files.

The artifact index excludes caches, temporary folders, `.git`, secrets, credentials, and scratch paths.

## Scope And Exclusions Lock

`SCOPE_AND_EXCLUSIONS_LOCK.json` states that the review scope is limited to:

```text
SBP-LEX Desktop V1 current repository state
EIE as canonical traversal state
Procedural Truth Evidentiary Sufficiency certification
SKG truth-foundation enrichment
DTN contextual and operational enrichment
Root of Trust Anchorage binding
local trust evidence
release integrity bundle
adversarial local trust negative-test harness
runtime and replay evidence for the current tested scenario
bounded validation questions only
```

It also states that the dossier is not:

```text
production certification
university validation result
legal advice
patent validity confirmation
security certification
government approval
runtime activation
Phase 19
external SKG/DTN runtime deployment
production certification
production security assurance
live distributed deployment
multi-node implementation
active nodes/quorum/mesh/distributed runtime
SKG/DTN implementation
cloud implementation
APK implementation
V2 or V3 implementation
```

The lock preserves:

```text
SBP-LEX runtime authority unchanged
Governance unchanged
Procedural Truth unchanged
Execution Gate unchanged
Hard Entry Gate unchanged
SKG/DTN external and non-authoritative
Phase 19 not started
```

## Reviewer Command Index

`REVIEWER_VERIFICATION_COMMANDS.json` records the verification commands reviewers may run. The dossier CLI does not execute these commands.

The command index includes compile, pytest, batch test, local trust validation, release integrity validation, adversarial harness validation, dossier validation, runtime, replay, and Git hygiene commands.

The CLI modes are:

```text
python -m sbp_lex.local_trust.validation_dossier build
python -m sbp_lex.local_trust.validation_dossier validate
python -m sbp_lex.local_trust.validation_dossier show
```

## What Reviewers Are Asked To Validate

Reviewers are asked to assess whether each bounded claim is supported by the listed artifacts and verification commands.

They may answer that a claim is:

```text
supported
unsupported
overbroad
ambiguous
requires narrowing
```

Reviewers are also asked to report missing evidence, hash mismatches, stale evidence, command failures, or unclear scope boundaries.

## What Reviewers Are Not Asked To Validate

Reviewers are not being asked to certify production readiness, provide legal advice, confirm patent validity, perform security certification, grant external execution permission, activate runtime behavior, or validate any future nodes/quorum/mesh/distributed/cloud/APK/V2/V3 surface.

The dossier does not ask reviewers to treat SKG or DTN as local runtime authority.

## Phase Boundary

Phase 19 remains not started.

18.9 is listed as the next phase only:

```text
18.9 - External Review Lock / Validation Handoff Pack
```

18.9 is not implemented by Phase 18.8.

## Strict Runtime Boundary

The dossier is not runtime authority. It must not call:

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

Those commands are recorded for reviewers only. They remain external verification actions, not dossier build actions.

## Phase 18.8B Handover Update

The dossier now references the Phase 18.8B repository-contained hardening pass:

- `reports/PHASE_18_8B_REPOSITORY_HARDENING_INSPECTION_MAP.md`
- `reports/PHASE_18_8B_EXTERNAL_PRODUCTION_READINESS_GAP_REPORT.md`
- `reports/PHASE_18_8B_MAXIMUM_REPOSITORY_HARDENING_BASELINE_REPORT.md`
- `docs/canonical_blueprint_series/00_CANONICAL_BLUEPRINT_SERIES_INDEX.md`
- `docs/canonical_blueprint_series/BLUEPRINT_SOURCE_AND_SUPERSESSION_MAP.md`
- `tests/test_phase_18_8b_repository_hardening.py`

SBP-LEX Dual V6 is presented as a local deterministic control-plane prototype suitable for university technical review, validation discussion, architectural assessment, stress testing, and further hardening feedback.

The dossier does not claim production deployment readiness, formal university validation, external certification, or safety-critical operational approval.
