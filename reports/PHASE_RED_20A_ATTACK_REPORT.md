# Phase RED-20A Attack Report

## Scope

RED-20A executed attack classes 20 through 16 only:

20. Log injection and audit-context spoofing.
19. Clock rollback and timestamp-authority forgery.
18. Duplicate submission and replay.
17. Path traversal and artifact overwrite.
16. Unsafe deserialization and object pollution.

Phase 19 was not started. RED-20B and attack classes 15–1 were not started. No external package gained traversal or runtime authority.

## Attacks executed and blocked

### Class 20 — Log injection and audit-context spoofing

- Injected CR/LF, tab, NUL, and forged execution text into event fields. Event text is now deterministically escaped before chronology storage.
- Injected a newline-bearing evidence source and a forged `stage=execution_gate` evidence field. The request schema rejects both the invalid source identity and unknown audit-context field.

### Class 19 — Clock rollback and timestamp-authority forgery

- Rewrote chronology sequence, timestamp, and timestamp authority, then recomputed the public event hash. Verification rejected the canonical marker violations and invalid signature.
- Rolled back an otherwise internally re-signed pre-context timestamp. Hard Entry rejected it before Root of Trust because the timestamp was not canonical.

### Class 18 — Duplicate submission and replay

- Raced 64 claims for one connector request identifier across 16 workers. Exactly one atomic reservation succeeded.
- Reclaimed an already completed connector request identifier. The replay claim was rejected.

### Class 17 — Path traversal and artifact overwrite

- Traversed outside the configured runtime-artifact directory with an integrity-store path. Construction failed before directory or file creation.
- Directed the external bridge demo manifest outside its package directory. The write was rejected and no escaped artifact was created.

### Class 16 — Unsafe deserialization and object pollution

- Submitted duplicate JSON keys and a non-finite `NaN` value. Strict JSON loading rejected both.
- Submitted a non-JSON Python object and `__proto__` pollution key. Schema validation rejected both.
- Loaded a persistence record with duplicate keys. The store recorded a deterministic parse failure and integrity verification failed closed.

## Proven gaps and fixes

- Evidence records lacked field-level allowlisting and source-identity validation. Added strict evidence schema checks.
- Runtime event strings preserved raw control delimiters. Added deterministic control-character escaping.
- Chronology entries were hashed but not signed, allowing public-hash recomputation after marker rewriting. Added canonical-runtime signatures and exact sequence/timestamp/authority verification.
- Connector duplicate detection used a non-atomic check-before-save sequence. Added locked request-ID reservation and protected recovery-store access.
- Integrity-store and demo-manifest paths were not confined. Added resolved-path containment checks and `.jsonl` enforcement for runtime integrity storage.
- JSON parsing accepted duplicate keys and non-finite constants; shape validation accepted unsupported Python objects. Added strict parsing and JSON-type enforcement.
- Persistence loading silently skipped malformed records. Parse failures now remain visible and make integrity verification fail closed.

## Files changed

- `sbp_lex/api/schema_validation.py`
- `sbp_lex/api/server.py`
- `sbp_lex/connector/fabric.py`
- `sbp_lex/connector/recovery.py`
- `sbp_lex/persistence/integrity_store.py`
- `sbp_lex/runtime/chronology.py`
- `sbp_lex/runtime/event_bus.py`
- `external_substrates/demo/validate_demo_bridge_package.py`
- `tests/test_red_20a_attack_classes_20_16.py`
- `reports/PHASE_RED_20A_ATTACK_REPORT.md`

## Tests added

Eleven focused tests cover all five authorized attack classes, including recomputed-hash clock forgery, concurrent duplicate claims, escaped artifact paths, duplicate JSON keys, non-finite values, object pollution, log delimiters, and malformed persisted records.

Interim full-suite result: 168 tests passed.

## Mandatory verification

- `python -m compileall -q .` — PASS using Python 3.12.13. The access-restricted `.pytest_cache` directory could not be listed; source compilation completed with exit code 0.
- `python -m pytest -q` — PASS, 168 tests. One environmental warning reported that pytest could not write its cache under the access-restricted working copy.
- `scripts\run_tests.bat` — PASS, 168 tests.
- `python main.py` — PASS: `ALLOW`, `EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, and no token failures.
- `python main.py replay` — PASS: two deterministic runs matched with identical PT-bound lineage and no mismatches.
- `git diff --check` — PASS; only informational LF-to-CRLF working-copy warnings were emitted.
- `git diff --stat` — eight tracked files changed with 219 insertions and 73 deletions; the focused test and this report are new untracked files.
- `git status --short` — exactly eight intended modified files and two intended new RED-20A files; no UI or unrelated files changed.
- external import search — no `sbp_lex` imports in `external_substrates`.
- active-source topology search — no prohibited topology terms.
- locality and pipeline search — loopback-only defaults and Dual Adaptive Deterministic Pipelines remain present.

## Authority and topology determination

RED-20A introduces no runtime activation, stage bypass, external Governance result, external execution permission, node, quorum, mesh, distributed runtime, cloud service, APK work, or UI change. Desktop V1 remains local/private; SKG and DTN remain external; canonical SBP-LEX remains the sole runtime authority.
