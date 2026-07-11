# H2D Rate, Concurrency and Resource Admission Report

## Baseline and scope

- Starting commit: `d8ae87975ea50c1ab28f4d01a35010913e3a6612`
- Ending commit: the single local commit containing this report; its exact
  content-addressed hash is recorded in the final task handoff.
- Scope: SBP-LEX DUAL V6 Desktop V1, local/private, single-host.
- Architecture changes: none.
- No-node rule: preserved.

H2D is an API transport admission boundary. It does not create Governance
outcomes, canonical runtime states, nodes, distributed convergence, cloud
coordination, or cognitive behavior. H1A/H1B, H2A/H2B, H2C, H4A, canonical
traversal, deterministic replay, and request-envelope verification remain in
their existing authority domains.

## Files changed

- `sbp_lex/api/rate_limit.py`
- `sbp_lex/api/server.py`
- `sbp_lex/api/access_control.py`
- `sbp_lex/api/request_auth.py`
- `tests/test_h2d_admission_control.py`
- `tests/test_h4a_security_state_persistence.py`
- `DEPLOYMENT_SECURITY.md`
- this report

The H4A test file change replaces a time-of-day constant that expired while
this package was running with a test-run-relative UTC reference. It changes no
production behavior and preserves the intended replay-retention assertions.

## Admission model

Each admitted request is checked under a lock against independent, bounded
dimensions for source address, credential ID, principal ID, principal type,
endpoint, and duplicate request fingerprint. Values are converted to
domain-separated safe digests before storage. Attacker-controlled values,
raw credentials, bearer tokens, HMAC secrets, nonces, or reusable signatures
are not persisted or emitted as admission evidence.

Deterministic classes are `observation`, `operator_traversal`, `validator`,
`connector`, `replay`, `maintenance`, and `administration`. Administrative
and maintenance identities use ordinary bounded rate capacity. Class selection
does not authorize a request and cannot bypass H1/H2 checks.

Established authentication-failure and malformed-request cooldowns are
checked before authentication or body parsing. New requests are admitted only
after authorization has succeeded. A successful resource request holds an
admission lease through endpoint processing and releases it in `finally`.
Denied admission therefore cannot invoke traversal, replay, connector,
event-stream, or export work and cannot create partial canonical state.

Stable transport denials are:

- `api_rate_limit_exceeded`
- `api_concurrency_limit_exceeded`
- `authentication_failure_limit_exceeded`
- `runtime_capacity_unavailable`
- `admission_state_invalid`

These are HTTP/API results, not new canonical runtime outcomes.

## Configuration schema

| Environment variable | Default | Maximum |
|---|---:|---:|
| `SBP_LEX_ADMISSION_REQUESTS_PER_WINDOW` | 120 | 1000 |
| `SBP_LEX_ADMISSION_AUTH_FAILURES_PER_WINDOW` | 12 | 100 |
| `SBP_LEX_ADMISSION_MAX_CONCURRENT_TRAVERSALS` | 4 | 32 |
| `SBP_LEX_ADMISSION_MAX_CONCURRENT_REPLAYS` | 1 | 8 |
| `SBP_LEX_ADMISSION_MAX_CONCURRENT_CONNECTORS` | 4 | 32 |
| `SBP_LEX_ADMISSION_MAX_EVENT_SUBSCRIBERS` | 8 | 64 |
| `SBP_LEX_ADMISSION_MAX_EXPORTS` | 2 | 16 |
| `SBP_LEX_ADMISSION_MAX_TRACKED_IDENTITIES` | 1024 | 4096 |
| `SBP_LEX_ADMISSION_RETENTION_SECONDS` | 300 | 3600 |
| `SBP_LEX_ADMISSION_COOLDOWN_SECONDS` | 60 | 600 |
| `SBP_LEX_ADMISSION_WINDOW_SECONDS` | 60 | 300 |

Absent values use secure defaults. Explicit blank, zero, negative,
non-numeric, excessive, or internally inconsistent values raise a startup
configuration error before the listener binds. No permissive substitution is
performed for an explicitly invalid value.

## Endpoint, concurrency and fairness controls

| Endpoint/work | Admission class | Independent resource ceiling |
|---|---|---|
| health, status, dashboard, integrity, checkpoints | observation/identity class | request rate only |
| `/runtime/traverse` | operator traversal | traversal pool |
| `/runtime/replay` | replay | replay pool |
| connector submit/build | connector | connector pool |
| `/runtime/events` | observation/identity class | event-stream pool |
| `/desktop/export/*` | observation/identity class | export pool |

Rate keys include the deterministic workload class. Consequently a viewer
event-stream flood cannot consume traversal capacity, replay cannot consume
live traversal capacity, and connector traffic cannot consume health/status
observation capacity. Resource pools are separate and no priority class gains
unlimited execution. Authentication and scope evaluation still occur before a
request can enter governed work.

## Persistence and bounded cleanup

Restart-sensitive rate, failure, cooldown, and duplicate-fingerprint state is
atomically saved beneath `runtime_artifacts/api_security_state` as a bounded
signed snapshot. It reuses the approved local digest, signature, flushed
temporary-file, `fsync`, and atomic-replacement primitives while using the
separate integrity domain `SBP_LEX_DESKTOP_V1_H2D_ADMISSION_STATE`.

Admission state is not placed in the H4A credential-lifecycle reconstruction,
runtime audit ledger, or canonical governed state. Only safe digest keys and
timestamps are stored. Active concurrency leases are intentionally
process-lifetime state because no work survives a process restart.

Cleanup visits sorted keys, retains only configured bounded history, and caps
the total tracked-key set. A persisted high-water clock prevents rollback from
resetting a window. Corrupt maps, invalid timestamps, bad signatures, storage
overflow, atomic-write failure, or invalid active counters fail closed.

## Tests added and results

`tests/test_h2d_admission_control.py` adds 45 tests covering every required
identity dimension; source, credential, and principal bursts; identity churn;
authentication and malformed floods; all five concurrency ceilings; duplicate
fingerprints; window and cooldown expiry; restart survival; clock rollback and
jump; invalid/blank/negative/excessive configuration; cardinality exhaustion;
memory and persisted corruption; concurrent races; all three fairness cases;
all seven classes; bounded administration; secret leakage; no partial state;
and no unintended ALLOW.

Commands and final results:

- `python -m compileall -q .`: PASS
- H2D targeted tests: 45 passed
- H2D plus H1/H2/H4 regression tests: 244 passed
- `python -m pytest -q --basetemp=runtime_artifacts\pytest_tmp_main`: 971 passed
- `scripts\run_tests.bat --ignore=runtime_artifacts`: 971 passed; the ignore
  excludes only generated pytest basetemp trees with inherited sandbox ACLs,
  not repository tests or integrity gates
- local-trust manifest and execution-envelope validation: PASS
- evidence-chain validation/compare: PASS, zero changed evidence items
- regression matrix: PASS, 19/19
- constitutional gates: PASS, 24/24
- toolchain guard: PASS, 39/39
- local-trust capstone: PASS
- `python main.py`: ALLOW / EXECUTE / MODE_2_SPLIT_VALIDATOR; convergence matched
- `python main.py replay`: 2/2 matched; zero mismatches
- `git diff --check`: PASS before commit

A transient dependency-ordered rebuild of downstream local-trust outputs was
also exercised. Its generated timestamp/provenance rewrites were deliberately
restored to the starting-commit versions and not incorporated, because they
were unrelated to H2D. Final validation was performed against the retained
evidence chain.

## Security properties and remaining limitations

Established properties include deterministic multi-dimensional rate control,
bounded identity tracking, pre-processing abuse cooldowns, independent resource
leases, stable denial identifiers, restart-resistant safe state, atomic signed
persistence, rollback-resistant clocks, fail-closed corruption handling,
bounded cleanup, and workload-class fairness without authorization bypass.

Limitations are intentionally bounded to Desktop V1: admission is local to one
process/host; it provides no shared network rate, distributed lock, external
service, cloud durability, quorum, or cross-host fairness. A host administrator
who can coherently restore the admission snapshot and its signing environment
remains outside the local rollback claim. Fixed-window limits are transport
protection, not a governance decision or scheduling redesign.

The canonical architecture, deterministic replay, and no-node rule are
unchanged. The preserved stash and the detached cognitive branch—including its
pre-existing untracked `baselines/`, documentation, experiments, and report—
were not modified, applied, merged, or incorporated. GitHub was not contacted
for writes and no push was performed.
