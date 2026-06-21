# Phase 18.6 Historical Audit Mutation Attack Report

## Decision

All 15 historical mutation attacks are detected and fail closed. Within the current Desktop V1 deterministic integrity and placeholder-signing threat model, no tested alteration can validate as legitimate history.

**TOP 10 SBP-LEX KILL TESTS COMPLETE**

Phase 19 was not started. Runtime activation, automatic traversal, and architecture redesign were not introduced.

## Attack cases executed

1. Historical audit payload field modified — blocked by audit hash/signature verification (`AUDIT_CORRUPTION_DETECTED`).
2. Stored PT outcome modified — blocked by audit/state lineage comparison (`LINEAGE_MISMATCH`).
3. PT envelope digest modified — blocked by envelope recomputation (`PT_ENVELOPE_MISMATCH`).
4. Request fingerprint lineage modified — blocked across audit, envelope, anchor, and hash chain (`REQUEST_IDENTITY_MISMATCH`).
5. SKG digest modified — blocked by PT-envelope and Root of Trust binding (`PT_ENVELOPE_MISMATCH`).
6. DTN digest modified — blocked by PT-envelope and Root of Trust binding (`PT_ENVELOPE_MISMATCH`).
7. Pre-context digest modified — blocked by PT-envelope and Root of Trust binding (`PT_ENVELOPE_MISMATCH`).
8. Root of Trust anchor modified — blocked by canonical anchor digest/signature and audit copy (`ROOT_OF_TRUST_MISMATCH`).
9. Execution result modified — blocked by signed execution attestation/state comparison (`LINEAGE_MISMATCH`).
10. Chronology marker modified — blocked by chronology hash verification (`chronology_hash_mismatch`).
11. Historical replay-ledger record removed — blocked by signed record-count/head checkpoint (`ledger_checkpoint_mismatch`).
12. Fabricated replay-ledger record inserted — blocked by sequence, link, signature, and checkpoint verification.
13. Replay-ledger records reordered — blocked by sequence/link verification.
14. Hash-chain continuity modified — blocked by canonical chain verification (`HASH_CHAIN_MISMATCH`).
15. Replay reference identifier modified — blocked by signed replay-result verification (`REPLAY_MISMATCH`).

## Failures found and fixes applied

The pre-test inspection found two deletion/rewrite gaps before final attack execution:

- An exported replay ledger had per-record hashes and signatures but no independently signed count/head commitment. Deleting the final record could otherwise leave the remaining links internally consistent. A deterministic signed replay-ledger checkpoint now binds record count and head hash.
- A replay result had a deterministic hash but no internal signature. An attacker able to rewrite the bundle could recompute that public hash. Replay results now carry a canonical-runtime signature and have an explicit verifier that recomputes reference/run mismatches.

A unified historical-state verifier was added to cross-check the signed audit record, audit-chain prefix, final hash-chain continuity, request identity, PT envelope digest, SKG/DTN/pre-context lineage, Root of Trust anchor, PT outcome, stage lineage, and execution attestation.

## Files added or changed

- `sbp_lex/audit/historical_integrity.py` — deterministic completed-state historical integrity verification.
- `sbp_lex/audit/pipeline_replay_ledger.py` — signed replay-ledger head/count checkpoints and exported-ledger verification.
- `sbp_lex/pipeline/replay_runner.py` — signed replay result and deterministic replay-result verification.
- `tests/test_phase_18_6_historical_audit_mutation.py` — 15 focused attack cases.
- `reports/PHASE_18_6_HISTORICAL_AUDIT_MUTATION_ATTACK_REPORT.md` — this report.
- `reports/PHASE_RED_20_ATTACK_PLAN.md` — ranked plan only; RED-20 is not implemented.

Earlier uncommitted Phase 18 and Phase 18.5 changes remain in the same working tree.

## Tests added

Fifteen tests reproduce every required attack against copied completed states, isolated chronology instances, isolated replay ledgers, and replay result bundles. The tests first prove the original artifact verifies, apply exactly one mutation, and then require a deterministic fail-closed result.

## Verification results

- `python -m compileall -q .` — PASS using Python 3.12.13. The access-restricted `.pytest_cache` directory could not be listed; source compilation completed with exit code 0.
- `python -m pytest -q` — PASS, 157 tests. One environmental warning reported that pytest could not write its cache under the access-restricted working copy.
- `scripts\run_tests.bat` — PASS, 157 tests.
- `python main.py` — PASS: `ALLOW`, `EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, and no token failures.
- `python main.py replay` — PASS: two runs matched with identical PT-bound lineage and no mismatches; the replay bundle carries a valid deterministic canonical-runtime signature.
- `git diff --check` — PASS; only informational LF-to-CRLF working-copy warnings were emitted.

## Final determination

Historical Audit Mutation does not remain silently viable under the tested Desktop V1 controls. Mutation of the audit payload, PT and substrate lineage, Root of Trust anchor, execution result, chronology, replay ledger membership/order, hash-chain continuity, or replay reference is detected.

This determination does not convert placeholder signing into production cryptography and does not claim resistance to compromise of the canonical signing secret itself. SKG/DTN remain external, Desktop V1 remains local/private, and canonical SBP-LEX remains the sole runtime authority.
