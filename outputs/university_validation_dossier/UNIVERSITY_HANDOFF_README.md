# University Validation Dossier

This package is a reviewer-facing dossier for bounded assessment of the SBP-LEX Desktop V1 local trust evidence line.

## What This Package Is

- A claims-to-evidence index for the current repository state.
- A validation question set for reviewers.
- An evidence artifact hash index.
- A scope and exclusions lock.
- A reviewer verification command index.

## What This Package Is Not

- Not production certification.
- Not a university validation result.
- Not legal advice.
- Not patent validity confirmation.
- Not security certification.
- Not government approval.
- Not runtime activation.
- Not Phase 19.
- Not SKG or DTN implementation.
- Not nodes, quorum, mesh, distributed runtime, cloud, APK, V2, or V3 implementation.

## Current Repository Commit

`96a9745ab40317f91d22b62b92e5110bdc0d94d2`

## Review Scope

Reviewers are asked to assess whether the bounded claims in `MASTER_CLAIMS_TO_EVIDENCE_INDEX.json` are supported by the listed artifacts and verification commands.

## Excluded Scope

The dossier excludes certification, external validation conclusions, runtime activation, Phase 19, legal conclusions, patent validity, security certification, and future distributed or mobile implementation work.

## How To Verify

1. Inspect `DOSSIER_MANIFEST.json` for bound digests and dossier status.
2. Inspect `EVIDENCE_ARTIFACT_INDEX.json` for file hashes.
3. Inspect `REVIEWER_VERIFICATION_COMMANDS.json` for commands to run.
4. Inspect `MASTER_CLAIMS_TO_EVIDENCE_INDEX.json` for claim support.
5. Inspect `VALIDATION_QUESTIONS.json` for requested reviewer answers.
6. Inspect `SCOPE_AND_EXCLUSIONS_LOCK.json` for excluded claims and boundaries.

## Requested Reviewer Answer

Reviewers are asked to answer whether each bounded claim is supported, unsupported, overbroad, ambiguous, or requires narrowing.

## Reporting Unsupported Claims

Report the claim id, unsupported text, missing or weak evidence, and suggested narrowing.

## Reporting Defects

Report the artifact path, observed defect, verification command if applicable, and reproduction notes.

## Phase Boundary

Phase 19 remains not started. 18.9 is listed as the next phase only and is not implemented here.
