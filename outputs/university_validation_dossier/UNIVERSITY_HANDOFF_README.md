# University Validation Dossier

This package is a reviewer-facing dossier for bounded assessment of the SBP-LEX Desktop V1 local trust evidence line.

## What This Package Is

- A claims-to-evidence index for the current repository state.
- A validation question set for reviewers.
- An evidence artifact hash index.
- A scope and exclusions lock.
- A reviewer verification command index.
- EIE / SKG / DTN / Root of Trust / Procedural Truth rebuild alignment evidence.

## What This Package Is Not

- Not production certification.
- Not a university validation result.
- Not legal advice.
- Not patent validity confirmation.
- Not security certification.
- Not government approval.
- Not runtime activation.
- Not Phase 19.
- Not external SKG or DTN runtime deployment.
- Not production deployment readiness.
- Not external certification.
- Not safety-critical operational approval.
- Not nodes, quorum, mesh, distributed runtime, cloud, APK, V2, or V3 implementation.

## Current Repository Commit

`67ee3176ad068558567b54dd029ee3d4df70a7ff`

## Review Scope

Reviewers are asked to assess whether the bounded claims in `MASTER_CLAIMS_TO_EVIDENCE_INDEX.json` are supported by the listed artifacts and verification commands, including the EIE canonical traversal state, SKG/DTN enrichment, Root of Trust anchorage, Procedural Truth certification, Execution Gate enforcement, Phase 18.8B hardening, and the 13-document blueprint series.

## Excluded Scope

SBP-LEX Dual V6 is presented as a local deterministic control-plane prototype suitable for university technical review, validation discussion, architectural assessment, stress testing, and further hardening feedback.

The dossier excludes production deployment readiness, formal university validation, external certification, safety-critical operational approval, external validation conclusions, external SKG/DTN deployment, runtime activation beyond this local control-plane traversal, Phase 19, legal conclusions, patent validity, security certification, and future distributed or mobile implementation work.

## How To Verify

1. Inspect `DOSSIER_MANIFEST.json` for bound digests and dossier status.
2. Inspect `EVIDENCE_ARTIFACT_INDEX.json` for file hashes.
3. Inspect `REVIEWER_VERIFICATION_COMMANDS.json` for commands to run.
4. Inspect `MASTER_CLAIMS_TO_EVIDENCE_INDEX.json` for claim support.
5. Inspect `VALIDATION_QUESTIONS.json` for requested reviewer answers.
6. Inspect `SCOPE_AND_EXCLUSIONS_LOCK.json` for excluded claims and boundaries.

## PQC Provider Handoff

The current repository uses a real PQC provider contract for enforcement-evidence
signatures. The bounded policy is:

```text
Policy: NIST_FIPS_203_204_205
Primary signature algorithm: ML-DSA
Backup signature policy: SLH-DSA
KEM basis: ML-KEM
Provider used in current runtime: cryptography.mldsa
Tested cryptography version: 49.0.0
```

Provider availability is required. If the provider is unavailable, PQC
operations fail closed. Verification cannot be faked by setting `verified=true`,
and placeholder/HMAC PQC signatures are no longer accepted as valid provider
signatures.

Old placeholder/HMAC runtime integrity records are rejected under the real
provider contract and can be quarantined by the existing integrity-store
quarantine behavior. Local-trust deterministic `PLACEHOLDER` labels are not the
active PQC provider path and must not be described as production cryptography.

This is not production certification and does not claim certified PQC
compliance beyond the implemented provider contract.

## Requested Reviewer Answer

Reviewers are asked to answer whether each bounded claim is supported, unsupported, overbroad, ambiguous, or requires narrowing.

## Reporting Unsupported Claims

Report the claim id, unsupported text, missing or weak evidence, and suggested narrowing.

## Reporting Defects

Report the artifact path, observed defect, verification command if applicable, and reproduction notes.

## Phase Boundary

Phase 19 remains not started. 18.9 is listed as the next phase only and is not implemented here.
