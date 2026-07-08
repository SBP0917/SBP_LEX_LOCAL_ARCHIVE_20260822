# Grant Submission Decision Queue

Status: owner decision queue. No grant submission is authorised by this document.

## Decision Classes

- BLOCKER_BEFORE_SUBMISSION
- OWNER_REQUIRED
- CHECK_WITH_ABR_ATO
- CHECK_WITH_GRANT_BODY
- OPTIONAL
- FUTURE

## Decisions

| ID | Decision | Class | Risk if unresolved | Owner action |
|---|---|---|---|---|
| GSD-001 | Confirm legal applicant/entity wording | BLOCKER_BEFORE_SUBMISSION | Wrong applicant details could invalidate or delay application. | OWNER TO SUPPLY |
| GSD-002 | Confirm ABN use in formal fields only | OWNER_REQUIRED | ABN could be over-disclosed in public-facing materials. | OWNER TO APPROVE |
| GSD-003 | Confirm GST registration status | CHECK_WITH_ABR_ATO | Application could falsely claim GST registration. | CHECK ABR/ATO |
| GSD-004 | Confirm trust/trustee/trading-name presentation | CHECK_WITH_ABR_ATO | Entity name may be wrong for grants/invoices. | CHECK ABR/ATO |
| GSD-005 | Confirm company/Pty Ltd status wording | BLOCKER_BEFORE_SUBMISSION | Application could falsely claim company status. | OWNER TO SUPPLY |
| GSD-006 | Confirm Queensland location wording | BLOCKER_BEFORE_SUBMISSION | Location eligibility may fail or be unclear. | OWNER TO SUPPLY |
| GSD-007 | Confirm requested funding amount | BLOCKER_BEFORE_SUBMISSION | Budget cannot be prepared. | OWNER TO SUPPLY |
| GSD-008 | Confirm intended use of funds | BLOCKER_BEFORE_SUBMISSION | Application cannot align spend to grant rules. | OWNER TO SUPPLY |
| GSD-009 | Confirm university validation support need | OWNER_REQUIRED | Validation pathway may be under-described. | OWNER TO SUPPLY |
| GSD-010 | Verify grant is currently open | CHECK_WITH_GRANT_BODY | Application may target a closed or inactive program. | VERIFY LIVE |
| GSD-011 | Verify trust eligibility | CHECK_WITH_GRANT_BODY | Trust may be ineligible for some grants. | ASK GRANT BODY |
| GSD-012 | Verify matched funding requirement | CHECK_WITH_GRANT_BODY | Owner may be unable to meet co-contribution terms. | VERIFY LIVE |
| GSD-013 | Verify confidentiality/IP treatment | CHECK_WITH_GRANT_BODY | Attachments may become public or too widely shared. | ASK GRANT BODY |
| GSD-014 | Approve attachment set | BLOCKER_BEFORE_SUBMISSION | Sensitive material may be over-disclosed. | OWNER TO APPROVE |
| GSD-015 | Confirm no source/full repo attachment | BLOCKER_BEFORE_SUBMISSION | Source or architecture could be over-disclosed. | OWNER TO APPROVE |
| GSD-016 | Confirm university partner/contact status | OWNER_REQUIRED | Application may overstate partner involvement. | OWNER TO SUPPLY |
| GSD-017 | Confirm whether screenshots are needed | OPTIONAL | Application may lack visual support. | OWNER DECISION |
| GSD-018 | Later legal/IP review | FUTURE | No legal protection guarantee exists. | FUTURE WHEN FUNDED |

## Do-Not-Say Guard

Do not claim GST registration, Pty Ltd/company status, grant eligibility, current
grant opening, university validation, production readiness, patent/legal
protection completion, certification, or deployment readiness unless separately
confirmed and approved.
