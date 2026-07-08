# PHASE19D-GRANT-SUBMISSION-READINESS-01 Report

## Task Status

PASS.

This pass prepared no-money grant submission readiness guidance while preserving
the Phase 19C IP containment controls. It did not modify runtime code, modify
tests, promote canon, create the final pilot package, stage, commit, or push.

This report is not legal, patent, accounting, tax, commercial, or grant advice.
It does not confirm grant eligibility, university validation, production
readiness, or complete IP/legal protection.

## Files And Areas Reviewed

- `docs/pilot_package/UNIVERSITY_TRANSMISSION_CONTROL_PROTOCOL.md`
- `docs/pilot_package/CONFIDENTIALITY_NOTICE_TEMPLATE.md`
- `docs/pilot_package/RECIPIENT_WATERMARK_AND_HASH_MANIFEST_REQUIREMENTS.md`
- `docs/pilot_package/UNIVERSITY_TRANSMISSION_LOG_TEMPLATE.md`
- `outputs/university_validation_dossier/FIRST_CONTACT_REDACTED_COVER_SUMMARY.md`
- `outputs/university_validation_dossier/FIRST_CONTACT_SCOPE_AND_EXCLUSIONS_SUMMARY.md`
- `outputs/university_validation_dossier/FIRST_CONTACT_VALIDATION_QUESTIONS.md`
- `reports/PHASE19C_NO_MONEY_IP_CONTAINMENT_CONTROLS_02_REPORT.md`
- `docs/pilot_package/`
- `reports/`
- `outputs/university_validation_dossier/`
- `README.md`
- `START_HERE.md`
- `DEPLOYMENT_SECURITY.md`
- `docs/UNIVERSITY_VALIDATION_DOSSIER.md`

## Grant-Safe Materials

Grant-safe means suitable for use as a source for a redacted grant response, not
necessarily safe to attach raw.

- `outputs/university_validation_dossier/FIRST_CONTACT_REDACTED_COVER_SUMMARY.md`
- `outputs/university_validation_dossier/FIRST_CONTACT_SCOPE_AND_EXCLUSIONS_SUMMARY.md`
- `outputs/university_validation_dossier/FIRST_CONTACT_VALIDATION_QUESTIONS.md`
- `docs/pilot_package/CONFIDENTIALITY_NOTICE_TEMPLATE.md`
- `docs/pilot_package/UNIVERSITY_TRANSMISSION_CONTROL_PROTOCOL.md`
- `docs/pilot_package/RECIPIENT_WATERMARK_AND_HASH_MANIFEST_REQUIREMENTS.md`
- `docs/pilot_package/UNIVERSITY_TRANSMISSION_LOG_TEMPLATE.md`
- selected non-enabling wording from `README.md`
- selected non-enabling scope wording from `docs/UNIVERSITY_VALIDATION_DOSSIER.md`

Recommended use: quote or adapt short, high-level, non-technical paragraphs
only. Do not attach raw repository documents unless the grant portal requires
evidence and the owner approves the disclosure risk.

## Materials Requiring Redaction Before Grant Use

- `README.md`: remove PQC provider detail and runtime-control specifics before
  grant use.
- `START_HERE.md`: remove download, install, command, and dashboard launch
  steps.
- `docs/UNIVERSITY_VALIDATION_DOSSIER.md`: reduce to a short scope/evidence
  summary without detailed claims-to-evidence, implementation, or command paths.
- `outputs/university_validation_dossier/UNIVERSITY_HANDOFF_README.md`: redact
  technical review instructions and implementation-alignment detail.
- `outputs/university_validation_dossier/MASTER_CLAIMS_TO_EVIDENCE_INDEX.json`:
  summarise only; do not attach raw.
- `outputs/university_validation_dossier/SCOPE_AND_EXCLUSIONS_LOCK.json`:
  convert to readable summary.
- `docs/pilot_package/PILOT_PACKAGE_VALIDATION_CLAIMS_MATRIX.md`: summarise at
  grant level only.
- Phase 18/19 reports: use only aggregate validation-count/status wording, not
  internal phase mechanics.
- ODA/PVPL/SIM reports: summarise as support/evidence tooling only.

## Materials That Must Never Be Attached To A Grant Application

Unless the owner later obtains specific legal/commercial advice and explicitly
approves the risk, do not attach:

- raw repository source tree
- `baselines/`
- `runtime_artifacts/`
- full bulk `reports/`
- `DEPLOYMENT_SECURITY.md`
- unredacted RED-20 attack reports
- unredacted blueprint/canon-candidate documents or reports
- `reports/PHASE_18_8B_EXTERNAL_PRODUCTION_READINESS_GAP_REPORT.md`
- detailed external SKG/DTN bridge/readiness reports
- technical install/run command guides
- hash/evidence indexes that expose repository file structure
- final pilot package materials before owner approval
- any material containing rebuild-level architecture, full traversal mechanics,
  source code, SKG/DTN mechanics, EIE implementation mechanics, token/gate
  internals, or commercial package/pricing strategy

## Grant-Safe One-Page Summary Draft

SBP-LEX Dual V6 is a local/private Desktop V1 prototype for evidence-bound
decision-flow validation. It is designed to help reviewers assess whether
bounded technical claims are supported by repository-contained evidence,
controlled local tests, audit/replay records, and structured validation reports.

The current work is not a production deployment and is not a public release. It
is a validation prototype intended for staged university review under
confidentiality, with technical detail disclosed only to named reviewers after
owner approval.

The project need is practical and immediate: the owner has built a substantial
validation prototype and supporting evidence set, but does not currently have
funds for legal/IP review, grant writing, commercialisation support, paid
technical validation, or formal university review costs. Funding would support
controlled validation, IP-safe documentation, reviewer engagement, independent
technical feedback, and preparation for a responsible next-stage development
path.

Grant materials should remain high-level. They should not include source code,
full architecture, technical command packs, attack reports, raw evidence
indexes, or rebuild-level detail.

## Grant-Safe Problem Statement Draft

Complex AI and decision-support systems need more than output claims; they need
clear evidence that decision paths are bounded, reviewable, reproducible, and
tested against drift or unsupported escalation. Early-stage builders often lack
funding for independent validation, IP-safe disclosure planning, legal review,
and university engagement, which can leave promising control-plane prototypes
stuck between private development and credible external assessment.

SBP-LEX Dual V6 addresses this gap as a local/private validation prototype. The
next problem is not public deployment; it is safely obtaining independent
technical review without exposing the owner's source, sensitive architecture, or
future commercial pathway.

## Grant-Safe Innovation Statement Draft

SBP-LEX Dual V6 explores a structured approach to evidence-bound local
validation for controlled decision flow. Its innovation is not presented as a
finished product or certified system. The grant-safe claim is that the prototype
organises bounded claims, validation records, audit/replay evidence, and
reviewer-facing documentation so that independent reviewers can assess support
for selected technical claims without requiring immediate full disclosure of the
underlying source or architecture.

Sensitive internal mechanics, source code, and rebuild-level architecture should
remain withheld from grant attachments.

## Grant-Safe Prototype-Readiness Statement Draft

SBP-LEX Dual V6 is at Desktop V1 prototype validation status. The repository
contains local validation materials, evidence reports, scope/exclusion controls,
and no-money IP containment documents for staged university engagement.

The prototype is not production ready, not publicly deployed, not externally
certified, and not a completed commercial product. It is ready for a controlled
pre-validation pathway in which a named reviewer can inspect selected
watermarked materials after confidentiality terms are accepted.

## Grant-Safe University-Validation Pathway Statement Draft

The intended pathway is staged:

1. First contact with a redacted non-enabling summary.
2. Confidentiality or NDA acceptance before technical disclosure.
3. Named-reviewer selection and owner approval.
4. Recipient-specific watermarking and hash-manifested evidence package.
5. Private review of bounded claims and supporting evidence.
6. Reviewer feedback on whether claims are supported, unsupported, overbroad,
   ambiguous, or require narrowing.

This pathway does not claim university validation has already occurred. It is a
request for controlled assessment support.

## No-Money Funding-Need Statement Draft

The owner currently has no available funds for paid IP/legal review, paid grant
drafting, commercialisation support, formal technical validation, or university
review costs. Funding is needed to:

- obtain appropriate IP/legal guidance before deeper disclosure
- prepare grant-safe and reviewer-safe documentation
- support university validation or technical review costs
- prepare recipient-specific evidence packages
- create independent validation records
- support responsible commercialisation planning
- avoid premature public disclosure of sensitive architecture or source

Funds should not be described as supporting production deployment unless a later
approved phase changes scope.

## Non-Disclosure / IP-Protection Warning For Grant Attachments

Suggested wording:

```text
Attachment warning: SBP-LEX Dual V6 materials are confidential owner-controlled
prototype materials supplied only for grant assessment. They are not a public
release and do not grant any licence, ownership transfer, publication right,
teaching right, reuse right, redistribution right, or derivative-work right.
Please do not publish, forward, upload, teach from, copy beyond assessment need,
or share with students or unapproved reviewers without written owner approval.
The materials intentionally omit source code, full architecture, and
rebuild-level implementation detail to protect the owner's IP position.
```

This warning should appear on any grant attachment that leaves the owner's
control.

## Likely Grant Categories

Potentially relevant categories to investigate:

- Queensland innovation/startup
- AI safety/governance
- commercialisation
- research collaboration
- cyber/security
- responsible AI
- sovereign capability

Eligibility is not confirmed. The owner must check each program's rules, entity
requirements, location requirements, matched-funding requirements, eligible
costs, IP terms, and disclosure requirements.

## Owner Information Still Required

- ABN status
- GST status
- company/sole-trader status
- MVP status wording
- Queensland development location
- requested funding amount
- intended use of funds
- university validation cost/support need
- whether any university partner/contact has agreed to review
- owner legal name or applicant entity
- project address/location
- whether matched funding is available
- whether prior grant funding has been received
- whether any third-party code, data, or assets require disclosure
- whether the repository is currently private or public at time of submission

## Grant Attachment Boundary

Safe first-contact grant attachment candidates:

- redacted one-page summary
- redacted problem statement
- redacted innovation statement
- redacted prototype-readiness statement
- redacted university-validation pathway statement
- non-disclosure/IP-protection warning

Use with caution:

- high-level screenshots with watermark
- redacted scope/exclusions summary
- redacted validation questions

Do not attach:

- source code
- full repository archive
- raw technical dossier
- deployment security notes
- command guides
- evidence indexes
- attack reports
- full reports directory
- blueprint/canon materials
- package manifests exposing file structure

## Overclaim Guardrails

Grant wording must not claim:

- grant eligibility is confirmed
- university validation has occurred
- production readiness
- public deployment readiness
- legal protection is guaranteed
- patent protection is complete
- external certification
- safety-critical approval
- commercial revenue readiness
- full product completion

Preferred status wording:

```text
Desktop V1 local/private prototype validation status.
Controlled university validation pathway intended.
Technical disclosure subject to confidentiality and owner approval.
```

## Recommended Next Minimal Pass

Create grant-safe draft attachments as separate documents only after the owner
provides applicant/entity details, requested funding amount, intended use of
funds, Queensland location status, and preferred grant target.

## Required Confirmations

- No runtime code changed.
- No tests changed.
- No canon promotion.
- Final pilot package not created.
- Nothing staged.
- Nothing committed.
- Nothing pushed.
