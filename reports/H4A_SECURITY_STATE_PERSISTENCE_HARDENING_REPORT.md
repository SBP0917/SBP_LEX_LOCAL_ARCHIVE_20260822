# H4A API Security-State Persistence Hardening Report

## Baseline and scope

- Starting commit: \`7042a29303b91b571fd999646e96a3dc0787cde2\`
- Ending commit: the single commit containing this report; the exact
  content-addressed hash is recorded in the final task handoff.
- Scope: SBP-LEX DUAL V6 Desktop V1, local/private, single-host.
- Architecture changes: none.
- No-node rule: preserved.

This store is an API security authority domain. It does not replace or merge
with runtime audit, EIE, Root of Trust, Procedural Truth, Classification,
Licensing, Governance, GRC, Domain, Aurion, Execution Gate, or Audit.

## Files changed

- \`sbp_lex/api/security_state_store.py\`
- \`sbp_lex/api/credential_lifecycle.py\`
- \`sbp_lex/api/request_auth.py\`
- \`sbp_lex/api/server.py\`
- \`tests/test_h4a_security_state_persistence.py\`
- \`DEPLOYMENT_SECURITY.md\`
- this report

## Persistence architecture

The local store uses four files beneath
\`runtime_artifacts/api_security_state\`:

1. append-only logical JSONL security-event ledger;
2. atomically replaced signed checkpoint containing reconstructed state;
3. atomically replaced signed rollback anchor binding checkpoint/head;
4. short-lived signed write-intent proving an exact interrupted write.

All records are domain-separated from runtime audit. Files are strict JSON,
paths are resolved beneath the approved root, extensions are restricted, and
symlink/reparse-point escapes are rejected where visible to Python.

## Record schema

Every event contains \`record_version\`, \`sequence\`, \`event_id\`,
\`event_type\`, safe credential/principal/request identifiers, nonce digest,
credential version, prior/new state, reason, issued/effective times,
\`previous_record_hash\`, \`record_hash\`, integrity signature,
\`runtime_instance_id\`, retention expiry, and integrity domain.

Raw secrets, bearer values, raw nonces, signing secrets, and reusable
authentication material are not persisted.

## Checkpoint, locking, and atomicity

The checkpoint binds record count, head sequence/hash, reconstructed state,
and state digest. The independent rollback anchor binds the checkpoint hash
and ledger head. Every event is hash-linked and integrity-signed.

An in-process reentrant lock serializes operations. A Windows \`msvcrt\`
one-byte file lock excludes a second authoritative writer. Lifecycle changes
persist before in-memory mutation. Nonce and request-ID registration occurs in
one durable event before protected request processing.

Ledger, checkpoint, anchor, and intent use exclusive temporary creation,
flush, \`fsync\`, and \`os.replace\`. Write or disk-full failure returns a
stable failure and does not advance protected in-memory state.

## Startup validation and crash recovery

Listener startup performs:

\`load -> strict parse -> sequence/hash/signature verification -> checkpoint
verification -> reconstruction -> checkpoint comparison -> rollback-anchor
verification -> writer acquisition -> bind\`.

A trailing incomplete uncheckpointed write is classified and removed only
when the prior checkpoint remains valid. A fully flushed one-record append
with its matching signed intent is rolled forward. A replaced checkpoint with
the prior anchor and matching intent is also rolled forward. Missing
components, middle corruption, stale state without intent, ambiguous state,
or broader rollback fail closed and block listener binding.

## Tamper and bounded-growth policy

Detection covers truncation, middle corruption, missing/reordered/duplicated
records, duplicate sequence, broken links, record-hash/signature failure,
checkpoint corruption/staleness, ledger rollback, checkpoint rollback, and
intent corruption.

- maximum event record: 64 KiB;
- warning threshold: 6 MiB;
- hard stop: 8 MiB;
- maximum replay retention: 300 seconds;
- live replay entries are never removed before protection expiry;
- credential lifecycle/revocation history is append-only and never cleaned;
- segmentation was not introduced.

## Tests and results

Added 26 H4A tests. Targeted H4A plus H1-H2C regression coverage: 207 passed.
Tests cover state/replay restart survival, rotation retirement, crash windows,
partial/truncated writes, all hash/link/signature/sequence mutations,
missing/reordered/deleted records, checkpoint/ledger rollback, concurrent
registrations, rotation/revocation race, second writer, path boundaries,
record/store limits, disk failure, secret scans, and startup bind blocking.

Commands and results:

- \`python -m compileall -q .\`: PASS
- targeted persistence/authentication tests: 207 passed
- full pytest: 926 passed
- \`scripts\\run_tests.bat\`: 926 passed
- local-trust validators, constitutional gates and toolchain guard: PASS
- evidence compare: zero changed items
- capstone: PASS
- runtime: ALLOW / EXECUTE / MODE_2_SPLIT_VALIDATOR; convergence matched
- replay: 2/2 matched; zero mismatches
- \`git diff --check\`: PASS before commit

## Security properties and remaining limitations

Established: crash-safe durable replay registration; lifecycle/revocation/
rotation restart survival; strict recovery; tamper/rollback evidence; atomic
replacement; writer exclusion; bounded records/store/retention; secret-free
persistence; and fail-closed startup.

Limitations: rollback anchoring remains local to the single host and therefore
does not claim protection against an administrator who can restore every
security-state file and its signing environment from one coherent old disk
image. Windows directory-entry durability depends on filesystem/platform
semantics after flushed file replacement. No network, quorum, database,
distributed ledger, cloud dependency, or architectural redesign was added.

The stash and cognitive branch, including their pre-existing untracked
artefacts and \`baselines/\`, were not modified, applied, merged, or
incorporated. No push was performed.
