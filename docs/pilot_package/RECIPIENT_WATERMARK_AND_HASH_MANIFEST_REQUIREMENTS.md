# Recipient Watermark And Hash Manifest Requirements

Status: draft requirements for controlled university transmission.

This document defines minimum evidence controls for any SBP-LEX university
transmission. It does not create the final pilot package and does not guarantee
legal or patent protection.

## Required Package ID

Every transmitted package or document set must have a package ID:

```text
SBP-LEX-DUAL-V6-[DISCLOSURE_STAGE]-[RECIPIENT_INITIALS]-[YYYYMMDD]-[NN]
```

Example:

```text
SBP-LEX-DUAL-V6-FIRSTCONTACT-XX-20260708-01
```

## Required Watermark Text

Each non-first-contact file should include visible or metadata-level wording:

```text
Confidential SBP-LEX owner material.
Recipient: [RECIPIENT_NAME]
Institution/team: [INSTITUTION_OR_TEAM]
Package ID: [PACKAGE_ID]
Git commit: [GIT_COMMIT]
Date issued: [DATE_ISSUED]
No publication. No student access. No redistribution. No licence granted.
No ownership transfer.
```

Screenshots and PDFs should carry visible footer or corner watermark text. Text
documents should include a notice near the top. Hash manifests should record the
same recipient and package ID.

## Git Commit Reference Requirements

Each package manifest must record:

- repository name
- branch
- git commit hash
- package assembly date
- package assembler
- whether working tree was clean at assembly
- known deliberately excluded untracked paths

## SHA-256 Hash Manifest Requirements

Each transmitted package must include a manifest with:

- package ID
- recipient name
- institution/team
- git commit hash
- file path
- file classification
- disclosure stage
- SHA-256 hash for each file
- package-level SHA-256 hash if an archive is created
- watermark status for each file
- confidentiality notice status
- owner approval reference

Minimum manifest columns:

| Field | Required |
|---|---|
| package_id | YES |
| recipient_name | YES |
| institution_or_team | YES |
| git_commit | YES |
| file_path | YES |
| disclosure_stage | YES |
| classification | YES |
| sha256 | YES |
| watermark_applied | YES |
| confidentiality_notice_included | YES |
| owner_approval_reference | YES |

## Hash Command

Preferred command for local manifest generation:

```powershell
Get-FileHash -Algorithm SHA256 <path>
```

The final package creation task may use a scripted manifest builder, but the
result must remain reviewable as a plain text, CSV, JSON, or Markdown manifest.

## Transmission Log Linkage

The hash manifest must be linked to the transmission log by:

- package ID
- recipient name
- git commit
- package hash
- date/time transmitted
- delivery method

## Strict Exclusions

Do not include in a transmitted package unless separately approved:

- `baselines/`
- `runtime_artifacts/`
- raw repository source tree
- full bulk `reports/`
- deployment security notes
- unredacted attack reports
- unredacted blueprint/canon-candidate materials
- missing originals as authority
- commercial package/pricing strategy
- rebuild-level mechanics
