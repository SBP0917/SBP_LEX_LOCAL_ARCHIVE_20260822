# Griffith University Evaluation Package Regeneration

## Purpose

This workflow regenerates and records the SBP-LEX Desktop V1 evidence needed
for a bounded, controlled university evaluation. It fails closed. It does not
claim Griffith University validation, endorsement, certification, production
approval, legal conclusions, or runtime authority.

The owner-side assurance status is:

```text
OWNER_SIDE_HANDOVER_ASSURANCE_PASSED
```

The final external assembly status is:

```text
GRIFFITH_EVALUATION_PACKAGE_ASSEMBLED_AND_TRIPLE_VERIFIED
```

Those statuses are available only after the repository, trust identity,
measured baseline, evidence, Git lineage, R1-R4 package, three assurance runs,
archive hashes, detached verification, repository-bound verification, and
three no-source-leakage archive checks all pass.

External validation remains `PENDING`. The archive is not an initial-contact
attachment. Send only the controlled proposal at first contact unless
Griffith requests the Level C technical material and a named assessor,
approved scope, confidentiality/IP controls, and explicit owner approval are
recorded.

## Assurance Direction

Generated evidence follows one direction:

```text
source authority commit
  -> PHQ
  -> Local Trust
  -> Release Integrity
  -> Adversarial Harness
  -> University Dossier
  -> R1 Recovery
  -> R2 Supply Chain
  -> R3 Custody
  -> R4 Independent Verification Package
  -> evidence-only recording commit
```

R1 consumes Local Trust and Release evidence. Local Trust does not hash R1
outputs back into itself. R2 and R4 bind R1. This removes a cryptographically
impossible mutual-hash cycle while preserving the recovery and handover
assurance links.

## Git Provenance Rule

Evidence records the clean source authority commit on which it was generated.
Git then records the evidence in a descendant commit.

The descendant is accepted only when:

- the recorded source commit is an ancestor of the current commit;
- the chain is linear and contains no merge;
- the chain contains no more than 32 commits;
- every commit is non-empty;
- every changed path is an explicitly approved generated-evidence path;
- no source, configuration, test, baseline-authority, or lookalike path
  changed.

This is not a waiver for stale evidence. It is the bounded recording rule
required to avoid claiming that evidence contained the hash of the commit
that did not exist until after that evidence was written.

## Required Environment

Use the canonical Windows checkout on `main`, with:

- canonical origin `github.com/SBP0917/SBP_LEX_DUAL_V6`;
- upstream `origin/main`;
- clean `HEAD` equal to `origin/main`;
- production ML-DSA signing seed provisioned out of band;
- trusted ML-DSA public key provisioned out of band;
- separately verified signer fingerprint;
- the final controlled Griffith proposal PDF, stored outside the repository;
- the separately reviewed SHA-256 of that exact proposal PDF;
- the canonical baseline store at
  `sbp_lex/runtime/approved_runtime_baselines.json`;
- no override for the baseline path, measured-startup state root, or Local
  Trust evidence root before starting.

Never include the signing seed, private key, credentials, tokens, or
environment dump in the handover package.

The external archive must not include a source snapshot, Git bundle, Git
history, repository checkout, executable source, or repository credentials.
Repository-bound reproduction, if later approved, occurs in a separately
controlled verification session without transferring repository custody.

On Windows, the controlled entry point is:

```powershell
.\scripts\finalize_university_handover.bat
```

It pauses only at the three material trust boundaries: source push, explicit
baseline approval/push, and evidence push. All other steps are automated and
fail closed.

## Successor Baseline

The hardening changes alter measured source. A successor baseline therefore
requires explicit owner approval.

Preview:

```powershell
python -m sbp_lex.assurance.handover_regeneration baseline-preview
```

Approval requires:

- a new baseline identifier;
- the prior approved baseline identifier;
- an approval reference;
- the exact confirmation string printed by the controlled wrapper.

No baseline is auto-approved.

After approval, commit and push only:

```text
sbp_lex/runtime/approved_runtime_baselines.json
```

The resulting clean, synced commit is the source authority commit.

## Evidence Generation

The staging directory must be absolute, empty, outside the repository, and
free of links or junctions.

```powershell
python -m sbp_lex.assurance.handover_regeneration generate `
  --stage-root "C:\absolute\outside\repository\handover-stage" `
  --expected-fingerprint "64_lowercase_hex"
```

Generation:

- creates one PHQ artifact and reuses that exact artifact downstream;
- regenerates Local Trust, Release, adversarial, and dossier evidence;
- initializes measured-startup evidence;
- regenerates R1, R2, and R3;
- builds R4 and records runtime/replay evidence;
- regenerates top-level R1-R3 against the final startup state;
- validates every layer;
- rejects legacy V1 signatures and deterministic placeholders;
- writes a hash inventory for the staging set.

The canonical repository remains unchanged during generation.

## Evidence Recording

Record the verified stage in one evidence-only commit:

```powershell
python -m sbp_lex.assurance.handover_regeneration record `
  --stage-root "C:\absolute\outside\repository\handover-stage"
```

The recorder:

- backs up replaced evidence into the staging directory;
- installs only approved generated-evidence paths;
- rejects any source or unexpected path change;
- stages only approved evidence paths;
- commits once;
- proves the new commit is a bounded evidence-only descendant;
- requires a clean repository after the commit.

Push that evidence commit to `origin/main` before final verification.

## Final Verification

```powershell
python -m sbp_lex.assurance.handover_regeneration verify `
  --stage-root "C:\absolute\outside\repository\handover-stage" `
  --expected-fingerprint "64_lowercase_hex"
```

The verifier requires the final evidence commit to be clean and equal to
`origin/main`. It then runs:

- one complete Double Triple handover gate;
- two additional complete evidence gates;
- three total production-evidence validations.

The source gate inside the first run includes the complete test suite and
three fresh startup-to-terminal linkage runs.

## Final Archive

```powershell
python -m sbp_lex.assurance.handover_regeneration archive `
  --stage-root "C:\absolute\outside\repository\handover-stage" `
  --output "C:\absolute\GRIFFITH_UNIVERSITY_EVALUATION_PACKAGE.zip" `
  --proposal "C:\absolute\SBP_LEX_GRIFFITH_RESEARCH_PARTNERSHIP_PROPOSAL_CONTROLLED.pdf" `
  --expected-proposal-sha256 "64_lowercase_hex" `
  --expected-fingerprint "64_lowercase_hex"
```

The archive contains:

- the controlled Griffith proposal;
- the bounded R4 technical evidence package;
- path-redacted final verification logs, each bound to its private raw-log
  SHA-256;
- an owner-side assurance record;
- a controlled-review notice and evaluation README;
- SHA-256 checksums.

The archive is extracted and verified three times. Each run checks:

- ZIP CRC and safe paths;
- outer file checksums;
- exact equality of the released R4 evidence and the recorded repository
  evidence;
- detached R4 verification;
- controlled package topology;
- absence of repository, Git bundle, source, executable-script, credential,
  private-key, and private-path leakage;
- absence of legacy V1 and placeholder evidence markers.

The repository-bound R4 check already runs inside each owner-side evidence
gate before archive construction. It is not weakened or removed; repository
material is simply excluded from the external archive.

The trusted public verification identity remains out of band.
