# University Transmission Control Protocol

Status: draft control protocol for no-money IP containment.

This protocol is for controlled university first contact and later confidential
validation. It is not legal advice, does not guarantee legal or patent
protection, and does not claim university validation has occurred.

## Purpose

SBP-LEX Dual V6 may be shown to a university reviewer only through staged,
controlled disclosure. The owner does not have funded legal drafting or patent
attorney review, so repository transmission must limit what is disclosed and
must preserve an evidence trail.

## Disclosure Stages

### Stage 1: First Contact

Allowed material:

- short redacted cover summary
- redacted scope and exclusions summary
- redacted validation questions
- optional owner-approved screenshots or demo stills

Not allowed:

- source code
- full traversal mechanics
- blueprint content
- technical commands
- hash indexes
- attack reports
- deployment notes
- raw repository archive
- final pilot package

### Stage 2: Confidentiality / NDA Acceptance

Before any technical disclosure, the recipient must accept written
confidentiality limits or an NDA route. The owner must approve the recipient,
institution/team, transmission purpose, and document list.

### Stage 3: Named Reviewer Only

Technical material may be shared only with named reviewers approved by the
owner. Do not forward to students, research assistants, teaching teams,
classrooms, labs, public repositories, or additional staff without written owner
approval.

### Stage 4: Demo Only

Source-sensitive or architecture-sensitive material should be shown by guided
demo, screenshot, or screen share where possible. Do not leave raw source,
internal command packs, full logs, or unredacted reports with the recipient at
this stage.

## Required Notice Terms

Every non-first-contact transmission must include:

- confidential reviewer material
- named reviewer only
- no student access
- no publication
- no redistribution
- no licence granted
- no ownership transfer
- no copying except review copy authorised by owner
- no modification
- no derivative works
- no teaching or training use
- no public repository upload
- no screenshots, excerpts, summaries, or diagrams in publications without
  written owner approval
- return/delete on owner request

## Package Boundary Rules

First-contact package:

- redacted, non-enabling summaries only
- no commands
- no source
- no full dossier
- no architecture rebuild detail

NDA-only package:

- selected dossier files
- selected claims/evidence summaries
- selected validation reports
- all watermarked and hash-manifested

Named-reviewer-only package:

- command guides
- hash manifests
- detailed technical reports
- attack/hardening reports
- selected architecture summaries

Do-not-send material:

- `baselines/`
- `runtime_artifacts/`
- raw repository source tree
- full bulk `reports/`
- deployment security notes
- unredacted attack reports to non-security reviewers
- unredacted blueprint/canon-candidate materials
- missing originals as authority
- any package without recipient watermark and SHA-256 manifest

## Required Evidence Trail

Before transmission, record:

- package ID
- package purpose
- recipient name
- recipient institution/team
- recipient role
- owner approval date
- git commit hash
- package file list
- per-file SHA-256 hash
- package-level SHA-256 hash if archived
- watermark applied
- confidentiality notice included
- delivery method
- delivery date/time
- acknowledgement requested or received

## Strict Limits

Do not include:

- rebuild-level architecture
- full traversal mechanics
- source code
- full blueprint content
- unredacted SKG/DTN mechanics
- EIE implementation mechanics
- token/gate internals
- commercial package or pricing strategy

Do not claim:

- legal protection is guaranteed
- patent protection is complete
- university validation has occurred
- production readiness
- public deployment readiness
- external certification
