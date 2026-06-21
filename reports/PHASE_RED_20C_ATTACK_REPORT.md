# Phase RED-20C Attack Report

## Scope

RED-20C executed attack classes 10 through 6 only:

10. Rollback, fork, and split-history attack.
9. Insider record manipulation.
8. Privilege escalation and authority-token theft.
7. Command, code, and template injection.
6. Persistence compromise and recovery poisoning.

Phase 19 and RED-20D were not started. No runtime activation path or architecture redesign was introduced.

## Attacks executed

### Rollback, fork, and split history

- Generated competing signed chronology heads at the same event count; split history was detected.
- Generated competing signed replay-ledger heads; split history was detected.
- Re-signed a modified audit chain; audit/hash-chain lineage verification rejected it.
- Constructed two individually signed and internally valid histories for the same request; cross-history comparison detected the split.
- Presented an earlier valid replay checkpoint after a later trusted head; rollback was rejected.

### Insider record manipulation

- Modified a local signed audit payload; audit corruption was detected.
- Modified a replay-ledger record; record hash/signature verification failed.
- Modified a signed checkpoint head; checkpoint verification failed.
- Modified the execution attestation; historical lineage verification failed.

### Privilege escalation and authority-token theft

- Stole an Authority token from another request; request binding rejected it.
- Replayed a Governance token across requests; token verification rejected it.
- Changed Authority-token privilege content without signing authority; signature verification failed.
- Removed the Governance issuance trace while retaining the token; token-lineage verification rejected it.

### Command, code, template, and report injection

- Submitted shell-command syntax in request parameters; request validation rejected it.
- Submitted template-expression syntax in request metadata; validation rejected it.
- Submitted forged Markdown report headings through evidence; validation rejected it.
- Submitted template injection through signed connector metadata; connector schema validation rejected it.

### Persistence compromise and recovery poisoning

- Modified a signed connector-recovery record; recovery verification failed.
- Modified a persisted integrity record; hash/signature verification and aggregate poisoning detection failed closed.
- Removed the latest persistence record while retaining the trusted checkpoint; rollback was detected.
- Poisoned the persisted checkpoint and attempted restart/append; restart refused the compromised baseline.

## Weaknesses discovered

- Chronology had signed events but no signed count/head checkpoint or competing-head comparison.
- Replay checkpoints lacked explicit cross-head rollback/fork comparison.
- Historical verification validated one history at a time but did not compare multiple valid histories for the same request.
- Required tokens were cryptographically checked but not bound to exactly one matching issuance-trace record.
- Request/connector schema validation did not explicitly reject command, template, script/report injection syntax across nested data.
- Connector recovery history lacked a signed count/head checkpoint.
- Runtime integrity persistence had per-record signatures but no persisted signed count/head checkpoint, allowing final-record rollback to evade local chain-only inspection.
- Persistence parsing/verification did not prevent append after a poisoned restart baseline.
- The existing ignored default `runtime_artifacts/integrity_store.jsonl` was found to contain duplicate/out-of-order historical segments from earlier concurrent verification. The new guard rejected it. It was preserved untouched and never adopted as trusted history.

## Fixes applied

- Added signed chronology checkpoints plus rollback/split-head comparison.
- Added replay-ledger head comparison with fixed ledger identity and deterministic rollback/split categories.
- Added cross-history comparison for individually valid states sharing a request fingerprint.
- Historical verification now includes the signed controlled outcome.
- Canonical upstream validation now requires exactly one matching issuance-trace record for every required authority token.
- Added deterministic command, template, and report injection detection to request and connector schema validation.
- Added signed connector-recovery head/count checkpoints.
- Added persisted signed integrity-store checkpoints, sequence verification, restart poisoning rejection, and append refusal on compromised history.
- Added isolated pytest persistence configuration so security tests never inherit or rewrite an operator/runtime history file.

## Files added or changed for RED-20C

- `sbp_lex/api/schema_validation.py`
- `sbp_lex/audit/historical_integrity.py`
- `sbp_lex/audit/pipeline_replay_ledger.py`
- `sbp_lex/connector/recovery.py`
- `sbp_lex/persistence/integrity_store.py`
- `sbp_lex/runtime/chronology.py`
- `sbp_lex/security/authority_boundary.py`
- `tests/conftest.py`
- `tests/test_red_20c_attack_classes_10_6.py`
- `reports/PHASE_RED_20C_ATTACK_REPORT.md`

The verified but uncommitted RED-20A and RED-20B files remain in the same working tree and were preserved.

## Tests added

Twenty-one focused tests cover every required RED-20C attack. The full suite passed with 206 tests.

## Mandatory verification

- `python -m compileall -q .` - PASS. The existing inaccessible `.pytest_cache` directory produced a non-fatal listing notice.
- `python -m pytest -q` - PASS, 206 tests. One non-fatal Windows `.pytest_cache` permission warning was reported.
- `scripts\run_tests.bat` - PASS, 206 tests. The same non-fatal cache warning was reported.
- `python main.py` - PASS using the isolated RED-20C verification integrity store: `ALLOW`, `EXECUTE`, convergence matched, and no token failures.
- `python main.py replay` - PASS using the isolated RED-20C verification integrity store: two runs matched with no replay mismatches.
- `git diff --check` - PASS. Git reported line-ending conversion notices only.
- `git diff --stat` - PASS. The cumulative uncommitted RED-20A, RED-20B, and RED-20C tracked diff contains 24 files, 689 insertions, and 105 deletions; untracked reports, authority-boundary module, and focused tests are listed separately by status.
- `git status --short` - PASS review. The working tree contains only the intended cumulative RED-20A/RED-20B/RED-20C changes.

## Boundary determination

No altered artifact validated silently. Competing history did not become accepted history. Authority theft/escalation failed. Injection data was never interpreted as instructions. SKG and DTN remain external, canonical SBP-LEX remains the sole runtime authority, and Desktop V1 remains local/private.

Search verification found no `sbp_lex` imports in `external_substrates` and no prohibited topology terminology in active Python source. The only topology-term matches were the pre-existing negative guard literals in bridge-readiness tests. No Desktop UI files were changed. Dual Adaptive Deterministic Pipeline modes remain present and unchanged. Phase 19 and RED-20D were not started.
