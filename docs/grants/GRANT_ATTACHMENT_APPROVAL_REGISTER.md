# Grant Attachment Approval Register

Status: owner approval register. No attachment is approved until the owner marks
it approved for a specific grant.

## Classification Key

- APPROVED_FOR_GRANT_ATTACHMENT
- REDACT_BEFORE_ATTACHMENT
- NDA_ONLY
- DEMO_ONLY
- DO_NOT_ATTACH
- OWNER_DECISION_REQUIRED

## Attachment Register

| Material | Default classification | Notes | Owner approval |
|---|---|---|---|
| `docs/grants/GRANT_SAFE_ONE_PAGE_PROJECT_SUMMARY.md` | OWNER_DECISION_REQUIRED | Safe draft source, but owner must approve final wording. | OWNER TO DECIDE |
| `docs/grants/GRANT_SAFE_PROBLEM_STATEMENT.md` | OWNER_DECISION_REQUIRED | Safe draft source. | OWNER TO DECIDE |
| `docs/grants/GRANT_SAFE_INNOVATION_STATEMENT.md` | OWNER_DECISION_REQUIRED | Relationship-level only; check no overclaim. | OWNER TO DECIDE |
| `docs/grants/GRANT_SAFE_PROTOTYPE_READINESS_STATEMENT.md` | OWNER_DECISION_REQUIRED | Safe if status remains prototype only. | OWNER TO DECIDE |
| `docs/grants/GRANT_SAFE_UNIVERSITY_VALIDATION_PATHWAY.md` | OWNER_DECISION_REQUIRED | Safe if no validation-completed claim. | OWNER TO DECIDE |
| `docs/grants/GRANT_SAFE_FUNDING_USE_DRAFT.md` | OWNER_DECISION_REQUIRED | Needs owner amounts and target grant rules. | OWNER TO DECIDE |
| `docs/grants/GRANT_SAFE_ATTACHMENT_BOUNDARY_RULES.md` | REDACT_BEFORE_ATTACHMENT | May be useful internally; usually not needed as attachment. | OWNER TO DECIDE |
| `outputs/university_validation_dossier/FIRST_CONTACT_REDACTED_COVER_SUMMARY.md` | OWNER_DECISION_REQUIRED | First-contact safe after owner approval. | OWNER TO DECIDE |
| `outputs/university_validation_dossier/FIRST_CONTACT_SCOPE_AND_EXCLUSIONS_SUMMARY.md` | OWNER_DECISION_REQUIRED | First-contact safe after owner approval. | OWNER TO DECIDE |
| `outputs/university_validation_dossier/FIRST_CONTACT_VALIDATION_QUESTIONS.md` | OWNER_DECISION_REQUIRED | First-contact safe after owner approval. | OWNER TO DECIDE |
| `README.md` | REDACT_BEFORE_ATTACHMENT | Remove technical/provider/runtime detail first. | OWNER TO DECIDE |
| `START_HERE.md` | DO_NOT_ATTACH | Contains run/download commands and dashboard launch path. | OWNER TO DECIDE |
| `DEPLOYMENT_SECURITY.md` | DO_NOT_ATTACH | Contains deployment/security details. | OWNER TO DECIDE |
| `docs/UNIVERSITY_VALIDATION_DOSSIER.md` | NDA_ONLY | Too detailed for normal grant attachment. | OWNER TO DECIDE |
| `outputs/university_validation_dossier/*.json` | NDA_ONLY | May reveal evidence/file structure or command detail. | OWNER TO DECIDE |
| RED-20 reports | DO_NOT_ATTACH | Attack details and hardening information. | OWNER TO DECIDE |
| blueprint/canon-candidate material | DO_NOT_ATTACH | Architecture/canon risk. | OWNER TO DECIDE |
| source code or raw repository archive | DO_NOT_ATTACH | Over-disclosure risk. | OWNER TO DECIDE |
| screenshots/demo stills | DEMO_ONLY | Use only if watermarked and non-enabling. | OWNER TO DECIDE |
| trust deed content | DO_NOT_ATTACH | Private trust documentation. | OWNER TO DECIDE |

## Required Attachment Notice

Any approved attachment should include:

```text
Confidential SBP-LEX owner material. No publication. No redistribution. No
student access. No licence granted. No ownership transfer.
```
