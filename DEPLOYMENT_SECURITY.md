# SBP-LEX V1 Deployment Security Notes

## Local-first default

The runtime binds to localhost by default and is intended for local/runtime testing before public exposure.

## Private API mode

For Railway or any non-local deployment, set:

```text
SBP_LEX_API_SECURITY_MODE=private
SBP_LEX_REQUIRE_API_TOKEN=1
SBP_LEX_API_TOKEN=<strong bearer token>
SBP_LEX_SIGNING_SECRET=<strong signing secret>
```

## Do not expose without token mode

`SBP_LEX_API_SECURITY_MODE=disabled` is rejected unless an active pytest test
also sets `SBP_LEX_ALLOW_INSECURE_TEST_MODE=1`. It cannot be used to start a
normal runtime API process. Unknown or empty security modes also prevent API
startup.

Private-mode GET requests retain the configured bearer-token boundary only as
an explicit observation-only viewer compatibility identity. A legacy bearer
cannot authorize any POST. Every private-mode POST requires
X-SBP-LEX-Request-Auth: a signed,
short-lived, scoped-principal envelope bound to the exact canonical JSON body,
method, path, query, content type, credential, principal, device, scope, nonce,
and request ID. Bearer-only private POST authorization is not accepted.

Principal credentials are supplied as a JSON list in
SBP_LEX_API_PRINCIPALS. Credential secrets are used only for HMAC
verification and are never returned in access decisions, events, health
responses, exports, or exceptions.

Each SBP_LEX_API_PRINCIPALS entry is a strict lifecycle record containing
credential_id, principal_id, principal_type, credential_version,
credential_purpose, allowed_scopes, issued_at, not_before, expires_at, status,
rotation_group, replacement_credential_id, revoked_at, revocation_reason,
last_used_at, device_id, and secret. Unknown or incomplete records invalidate
the configured registry.

Credential states are PENDING, ACTIVE, ROTATING, EXPIRED, REVOKED, SUSPENDED,
and RETIRED. ACTIVE is the normal authenticating state. ROTATING is accepted
only during a maximum five-minute overlap when an ACTIVE, higher-version,
same-principal, same-type, equal-or-narrower replacement exists. Revocation is
immediate. REVOKED, SUSPENDED, RETIRED, EXPIRED, and unactivated PENDING
credentials fail closed.

## API security-state persistence

Before binding the API listener, Desktop V1 validates the separate
runtime_artifacts/api_security_state security ledger, checkpoint, rollback
anchor, and any crash-recovery intent. The store is single-host and has one
authoritative writer. Invalid, missing, stale, rolled-back, or ambiguous
security state prevents listener binding.

The append-only ledger contains domain-separated integrity signatures,
monotonic sequences, previous-record hashes, safe credential lifecycle state,
nonce digests, request IDs, and bounded retention metadata. It never stores
credential secrets, bearer values, raw nonces, or reusable signatures.

Ledger, checkpoint, anchor, and write-intent replacement use flushed temporary
files and atomic replacement. A proven one-step interrupted append or
checkpoint/anchor replacement is rolled forward; broader inconsistency fails
closed. Records are limited to 64 KiB, the active store to 8 MiB, replay
retention to five minutes, and a warning begins at 6 MiB.

## API admission limits

Desktop V1 applies deterministic, single-host admission before governed work.
Source, credential, principal, principal type, endpoint, duplicate request
fingerprint, authentication failure, and malformed-request activity are
bounded. Traversal, replay, connector, event-stream, and export work use
independent concurrency pools so observation, replay, and connector floods do
not consume live traversal capacity.

Secure defaults can be reduced, but never disabled, with:

```text
SBP_LEX_ADMISSION_REQUESTS_PER_WINDOW=120
SBP_LEX_ADMISSION_AUTH_FAILURES_PER_WINDOW=12
SBP_LEX_ADMISSION_MAX_CONCURRENT_TRAVERSALS=4
SBP_LEX_ADMISSION_MAX_CONCURRENT_REPLAYS=1
SBP_LEX_ADMISSION_MAX_CONCURRENT_CONNECTORS=4
SBP_LEX_ADMISSION_MAX_EVENT_SUBSCRIBERS=8
SBP_LEX_ADMISSION_MAX_EXPORTS=2
SBP_LEX_ADMISSION_MAX_TRACKED_IDENTITIES=1024
SBP_LEX_ADMISSION_RETENTION_SECONDS=300
SBP_LEX_ADMISSION_COOLDOWN_SECONDS=60
SBP_LEX_ADMISSION_WINDOW_SECONDS=60
```

Explicit blank, non-numeric, zero, negative, excessive, or inconsistent
values prevent listener startup. Rate/cooldown state is stored as bounded,
safe digests in a separately signed H2D admission snapshot. It is not
credential lifecycle, runtime audit, or canonical governed state.

## Runtime authority

The APK remains observational/orchestration only. Execution authority remains inside the canonical runtime.

## PQC Provider Requirement

SBP-LEX uses a real PQC provider contract for enforcement-evidence signatures:

```text
Policy: NIST_FIPS_203_204_205
Primary signature: ML-DSA
Backup signature policy: SLH-DSA
KEM basis: ML-KEM
Current provider: cryptography.mldsa
Tested cryptography version: 49.0.0
```

Provider availability is required. If the provider is unavailable, PQC signing
and verification fail closed. Placeholder/HMAC PQC signatures are not accepted,
and setting `verified=true` cannot make a token or signature valid.

Local deterministic `PLACEHOLDER` labels in local-trust evidence tooling are not
the active PQC provider path and must not be described as production
cryptography.
