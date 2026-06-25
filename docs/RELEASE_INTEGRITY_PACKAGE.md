# Release Integrity Package

## Purpose

Phase 18.7F creates a reproducible validation bundle for external review readiness:

```text
outputs/release_integrity_bundle/
```

The bundle records what repository state, local trust artifacts, reports, tests, verification commands, claims seeds, and boundaries are being presented for review.

It is not runtime authority.

## Why Release Integrity Follows Local Trust

The 18.7 local trust phases establish a local evidence baseline. A reviewer still needs a controlled package that says which artifacts are in scope, how to re-hash them, which commands reproduce the validation checks, and which claims are supported by which evidence. The release integrity bundle provides that handoff structure without claiming certification or external validation.

## Relationship To Prior Phases

18.7D.1 cleaned the evidence chain to a zero-missing evidence state.

18.7E.1 added the local trust regression matrix.

18.7E.2 added constitutional gates for local trust pre-flight guardrails.

18.7E.3 added dependency and toolchain guard evidence.

18.7E.4 added the 25-year local trust capstone completion lock.

18.7F binds those artifacts into a review-ready release integrity directory.

## Bundle Structure

The bundle contains:

```text
RELEASE_MANIFEST.json
ARTIFACT_HASH_INDEX.json
VERIFICATION_COMMANDS.json
CLAIMS_TO_EVIDENCE_SEED.json
BOUNDARY_AND_SCOPE_LOCK.json
RELEASE_README.md
```

No zip archive is created. The deterministic directory plus JSON indexes are the release package.

## Artifact Hash Index

`ARTIFACT_HASH_INDEX.json` indexes validation-relevant artifacts, including local trust outputs, phase reports, local trust documentation, local trust tests, runtime/replay proof references, command policy references, and bundle files.

Each entry records:

```text
artifact_id
artifact_group
path
exists
size_bytes
sha256
required
reason
```

The bundle excludes `.git`, pycache, pytest cache/temp folders, local trust temp outputs, Codex scratch folders, secrets, credentials, and private tokens.

## Verification Command Index

`VERIFICATION_COMMANDS.json` records the reproducible command sequence for release review. The release integrity CLI does not run those commands. It only records and validates the command index.

## Claims-To-Evidence Seed

`CLAIMS_TO_EVIDENCE_SEED.json` is a seed index for later claims dossier work. It maps high-level local trust claims to evidence artifacts and verification commands.

This is not the final 18.8 claims dossier, and it does not claim external validation has occurred.

## Boundary And Scope Lock

`BOUNDARY_AND_SCOPE_LOCK.json` confirms that the package is:

```text
review readiness only
not production certification
not university validation result
not legal advice
not patent validity confirmation
not security certification
not runtime activation
not Phase 19
not SKG/DTN implementation
not nodes/quorum/mesh/distributed/cloud/APK/V2/V3 implementation
```

It also preserves that SBP-LEX runtime authority, Governance, Procedural Truth, Execution Gate, Hard Entry Gate, and SKG/DTN boundaries are unchanged.

## What This Package Proves

The package proves that a deterministic local release integrity bundle exists, that its release manifest digest validates, that required artifacts are hash-indexed, that local trust digests are bound, and that reproducible verification commands and claim seeds are available for review.

## What This Package Does Not Prove

The package does not prove formal certification, university validation, legal conclusions, patent validity, security certification, production readiness, external governance, or runtime activation.

## Transition

The next phase after 18.7F is:

```text
18.7G - Adversarial Local Trust Negative-Test Harness
```

18.7G is only marked as next-phase readiness in this package. It is not implemented here.

Later claims dossier work belongs to 18.8. Phase 19 remains not started.
