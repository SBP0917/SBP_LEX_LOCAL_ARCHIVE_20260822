# Phase RED-20 Attack Plan

## Status

Planning and ranking only. No RED-20 attack has been implemented or executed. Phase 19 has not started.

## Purpose

Apply twenty historically significant high-severity computer attack classes to SBP-LEX controls, ordered from 20th to 1st by potential impact on canonical authority, historical integrity, confidentiality, and execution safety.

## Ranked attack classes — 20th worst to 1st worst

20. **Log injection and audit-context spoofing** — attempt to insert misleading fields, separators, identities, or stage labels into operator and audit records.

19. **Clock rollback and timestamp-authority forgery** — alter sequence markers or time authority to revive stale evidence or reorder history.

18. **Duplicate submission and replay attack** — resubmit valid signed requests, connector envelopes, tokens, or completed outcomes outside their original context.

17. **Path traversal and artifact overwrite** — attempt to escape intended local storage paths or replace trusted runtime artifacts.

16. **Unsafe deserialization and object-pollution attack** — inject structural keys or crafted objects that change validation or runtime behavior.

15. **Resource exhaustion and algorithmic denial of service** — overwhelm evidence, candidate, replay, audit, or validation paths while preserving fail-closed behavior.

14. **Authentication bypass and credential abuse** — test missing, duplicated, malformed, expired, or context-confused credentials at local/private interfaces.

13. **Confused-deputy authority attack** — induce a trusted internal component to exercise authority on behalf of an untrusted external package.

12. **TOCTOU state substitution** — mutate request, evidence, classification, tokens, or candidates between validation and use.

11. **Protocol and security downgrade attack** — substitute weaker versions, modes, thresholds, signing markers, or validation requirements.

10. **Signature wrapping and signed-field substitution** — preserve a valid signature while changing which payload, identity, or authority context it appears to cover.

9. **Canonicalization ambiguity and digest-confusion attack** — exploit duplicate fields, type coercion, encoding, ordering, or alternate representations to create inconsistent hashes.

8. **Rollback, fork, and split-history attack** — present competing valid-looking audit, persistence, chronology, or replay heads.

7. **Insider record manipulation** — use legitimate local access to delete, insert, reorder, or selectively disclose historical records without signing authority.

6. **Privilege escalation and authority-token theft** — move from untrusted context into canonical Governance, Domain, Aurion, or Execution authority.

5. **Command, code, and template injection** — turn request, evidence, operator, connector, or report data into unintended executable behavior.

4. **Persistence compromise and recovery poisoning** — corrupt stored integrity state, restart recovery, or replay inputs so compromised history becomes the new baseline.

3. **Signing-key compromise and forged canonical authority** — model loss of the deterministic signing secret and identify required production key-isolation controls.

2. **Control-flow hijack and stage-bypass attack** — jump across Hard Entry, Root of Trust, PT, Governance, Domain, Aurion, or Execution Gate ordering.

1. **Trusted build/supply-chain compromise** — alter canonical source, dependencies, tests, or release artifacts so malicious authority behavior is delivered as trusted runtime code.

## Planned execution rules

- Run attacks only against isolated copies, temporary stores, and deterministic fixtures.
- Require a valid baseline artifact before each mutation.
- Accept only explicit deterministic fail-closed outcomes.
- Preserve Hard Entry, Root of Trust, Procedural Truth, Governance, Domain, Aurion, Execution Gate, and Audit order.
- Do not activate external-package self-traversal or move authority into SKG/DTN.
- Stop immediately if an altered artifact validates or an attack requires weakening an existing control.

## Proposed evidence for each attack

Each RED-20 case should record the threat precondition, mutated surface, expected detector, deterministic failure code, affected authority boundary, replay result, audit result, and regression test. Final execution requires separate authorization; this document does not provide it.
