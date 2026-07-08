# Grant-Safe Attachment Boundary Rules

Status: draft for owner review.

These rules classify what can be attached to a grant application without
over-disclosing SBP-LEX Dual V6. They do not guarantee legal or patent
protection.

## SAFE_FOR_GRANT_SUMMARY

Use as short, high-level wording in the application body or a redacted
attachment.

Examples:

- `docs/grants/GRANT_SAFE_ONE_PAGE_PROJECT_SUMMARY.md`
- `docs/grants/GRANT_SAFE_PROBLEM_STATEMENT.md`
- `docs/grants/GRANT_SAFE_INNOVATION_STATEMENT.md`
- `docs/grants/GRANT_SAFE_PROTOTYPE_READINESS_STATEMENT.md`
- `docs/grants/GRANT_SAFE_UNIVERSITY_VALIDATION_PATHWAY.md`
- `docs/grants/GRANT_SAFE_FUNDING_USE_DRAFT.md`
- first-contact redacted summaries, after owner approval

## REDACT_BEFORE_ATTACHMENT

Use only after removing technical or sensitive detail.

Examples:

- `README.md`
- `START_HERE.md`
- `docs/UNIVERSITY_VALIDATION_DOSSIER.md`
- `outputs/university_validation_dossier/UNIVERSITY_HANDOFF_README.md`
- `docs/pilot_package/PILOT_PACKAGE_VALIDATION_CLAIMS_MATRIX.md`
- selected Phase 18/19 report summaries

## NDA_ONLY

Do not attach to ordinary grant applications. Provide only through a protected
process if the grant body requires technical due diligence and the owner
approves.

Examples:

- selected claims-to-evidence summaries
- selected validation reports
- selected hash/digest manifests
- selected technical reviewer instructions
- named-reviewer university validation materials

## DEMO_ONLY

Show through controlled screen share, screenshot, or walkthrough. Do not leave
raw files with the recipient by default.

Examples:

- cockpit/dashboard demonstration
- local validation run demonstration
- replay/audit evidence demonstration
- support/evidence tooling demonstration

## DO_NOT_ATTACH

Do not attach unless the owner later receives suitable advice and explicitly
approves the risk.

Examples:

- source code
- raw repository archive
- `baselines/`
- `runtime_artifacts/`
- full bulk `reports/`
- `DEPLOYMENT_SECURITY.md`
- unredacted RED-20 attack reports
- full blueprint/canon-candidate content
- detailed external substrate reports
- technical install/run command guides
- trust deed content
- private owner financial/tax materials
- package/pricing strategy

## Attachment Notice

Every grant attachment should include:

```text
Confidential SBP-LEX owner material. No publication. No redistribution. No
student access. No licence granted. No ownership transfer. Technical details are
intentionally redacted to protect the owner's IP position.
```
