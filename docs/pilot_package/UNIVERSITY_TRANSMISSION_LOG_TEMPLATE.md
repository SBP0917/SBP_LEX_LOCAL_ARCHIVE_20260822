# University Transmission Log Template

Status: draft template.

Use this log for every university first-contact, confidentiality-stage, named
reviewer, demo-only, or package transmission event.

## Transmission Record

| Field | Value |
|---|---|
| transmission_id | `[TRANSMISSION_ID]` |
| package_id | `[PACKAGE_ID]` |
| disclosure_stage | `FIRST_CONTACT / NDA_ONLY / NAMED_REVIEWER_ONLY / DEMO_ONLY` |
| recipient_name | `[RECIPIENT_NAME]` |
| institution_or_team | `[INSTITUTION_OR_TEAM]` |
| recipient_role | `[RECIPIENT_ROLE]` |
| recipient_email_or_contact | `[CONTACT]` |
| owner_approval_reference | `[OWNER_APPROVAL_REFERENCE]` |
| date_prepared | `[DATE_PREPARED]` |
| date_transmitted | `[DATE_TRANSMITTED]` |
| delivery_method | `[EMAIL / SECURE_LINK / SCREEN_SHARE / OTHER]` |
| repository | `SBP0917/SBP_LEX_DUAL_V6` |
| branch | `[BRANCH]` |
| git_commit | `[GIT_COMMIT]` |
| package_sha256 | `[PACKAGE_SHA256_OR_NOT_APPLICABLE]` |
| manifest_path | `[MANIFEST_PATH]` |
| confidentiality_notice_included | `YES / NO` |
| watermark_applied | `YES / NO` |
| no_student_access_notice_included | `YES / NO` |
| no_publication_notice_included | `YES / NO` |
| no_redistribution_notice_included | `YES / NO` |
| no_licence_notice_included | `YES / NO` |
| no_ownership_transfer_notice_included | `YES / NO` |
| acknowledgement_requested | `YES / NO` |
| acknowledgement_received | `YES / NO / PENDING` |
| return_or_delete_condition_included | `YES / NO` |

## Files Transmitted

| File | Classification | SHA-256 | Watermarked | Notes |
|---|---|---|---|---|
| `[FILE_PATH]` | `[CLASSIFICATION]` | `[SHA256]` | `YES / NO` | `[NOTES]` |

## Material Explicitly Not Sent

| Material | Reason |
|---|---|
| `baselines/` | Excluded by containment gate. |
| `runtime_artifacts/` | Excluded unless regenerated and reviewed. |
| raw source tree | Withheld before owner-approved technical disclosure. |
| full bulk `reports/` | Too much rebuild/strategy detail. |
| deployment security notes | Do-not-send by default. |

## Recipient Acknowledgement Text

Suggested acknowledgement request:

```text
Please confirm receipt and acknowledge that this material is confidential
SBP-LEX owner material for named-reviewer evaluation only, with no publication,
no student access, no redistribution, no licence, and no ownership transfer.
```

## Notes

`[NOTES]`
