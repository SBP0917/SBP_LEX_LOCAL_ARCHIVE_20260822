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

## Network and transport boundary

The actual socket peer is the authoritative transport origin. Forwarding
headers are ignored and evidenced unless the immediate peer matches an
explicit trusted proxy address or bounded network and supplies the configured
proxy identity. A trusted forwarding chain is strictly parsed, hop-bounded,
and rejected when malformed, duplicated, ambiguous, or routed through an
untrusted intermediary. An asserted localhost address never replaces the
socket peer for local-mode authorization.

Local mode accepts only validated IPv4 or IPv6 loopback bind literals. It
rejects wildcard, hostname, non-loopback, zone-qualified, and ambiguous
dual-stack binds before security-state initialization or socket creation.
Private mode additionally requires an exact `SBP_LEX_BIND_ADDRESS`, configured
API authentication, and an allowed transport profile.

The default profile is inactive-infrastructure `LOCAL_PRIVATE`. Pilot TLS
profiles are disabled until every activation and file setting is explicit:

```text
SBP_LEX_TRANSPORT_PROFILE=LOCAL_PRIVATE
SBP_LEX_ALLOWED_TRANSPORT_PROFILES=LOCAL_PRIVATE
SBP_LEX_PROXY_MODE=disabled

# Explicit trusted-proxy pilot settings
SBP_LEX_PROXY_MODE=trusted
SBP_LEX_TRUSTED_PROXY_ADDRESSES=<comma-separated exact IP literals>
SBP_LEX_TRUSTED_PROXY_NETWORKS=<optional bounded CIDRs>
SBP_LEX_MAX_FORWARD_HOPS=3
SBP_LEX_REQUIRED_PROXY_IDENTITY=<proxy identity>

# Explicit private TLS/mTLS pilot settings
SBP_LEX_TRANSPORT_PROFILE=PILOT_PRIVATE_TLS
SBP_LEX_ALLOWED_TRANSPORT_PROFILES=PILOT_PRIVATE_TLS
SBP_LEX_ENABLE_REMOTE_TRANSPORT=1
SBP_LEX_TLS_ENABLED=1
SBP_LEX_BIND_ADDRESS=<exact approved IP literal>
SBP_LEX_TLS_CERT_FILE=<server certificate PEM>
SBP_LEX_TLS_KEY_FILE=<server private-key PEM>

# Additional mTLS settings
SBP_LEX_TRANSPORT_PROFILE=PILOT_PRIVATE_MTLS
SBP_LEX_ALLOWED_TRANSPORT_PROFILES=PILOT_PRIVATE_MTLS
SBP_LEX_TLS_CA_FILE=<client CA PEM>
SBP_LEX_TLS_REQUIRED_SERVICE_IDENTITY=<exact certificate SAN identity>
SBP_LEX_TLS_REQUIRED_CERTIFICATE_PURPOSE=desktop-v1-transport
SBP_LEX_REVOKED_CERTIFICATE_FINGERPRINTS=<optional SHA-256 denylist>
```

`REMOTE_PRODUCTION_DISABLED` cannot be activated. Remote plaintext is denied.
Pilot TLS uses Python's server TLS context with TLS 1.2 minimum; pilot mTLS
also requires client certificates, validates the configured CA, clientAuth
purpose, expiry, exact service identity, and the bounded local fingerprint
denylist. No CRL, OCSP, public PKI, automated issuance, or real production
certificate infrastructure is claimed. Transport device identity never grants
API scope and does not replace signed API identity or canonical controls.

## Measured startup and runtime identity

Desktop V1 measures its approved engineering state before listener binding or
canonical traversal/replay. The approved H8 baseline covers all `sbp_lex`
Python modules, critical configuration and documentation, policy and schema
files, committed trust outputs, declared/installed dependency versions, the
Python executable, and security-critical environment configuration. Secret
configuration values are represented only by domain-separated digests and
length metadata; runtime identities and diagnostics never contain raw secrets.

The deterministic measured runtime identity binds the approved baseline ID and
the software, configuration, environment, dependency, executable, policy,
schema, trust-store, and documentation digests. A separately signed startup
attestation binds that stable identity to UTC startup timestamp evidence and a
monotonic local startup sequence.

The baseline store supports exactly one `APPROVED` baseline plus bounded
`PENDING` and `RETIRED` records. Changed measurements are never adopted
automatically. A pending baseline requires an explicit approval reference and
explicit retirement of the prior approved ID. The ignored runtime state folder
contains a signed high-water anchor and startup/failure evidence so previously
observed baseline rollback, attestation replay, and store corruption fail
closed.

Critical or unknown drift prevents listener binding and canonical execution.
The baseline manager is available through:

```text
python -m sbp_lex.runtime.measured_startup validate
python -m sbp_lex.runtime.measured_startup show
python -m sbp_lex.runtime.measured_startup propose --identifier <ID>
python -m sbp_lex.runtime.measured_startup approve --identifier <ID> --retire <OLD_ID> --approval-reference <REFERENCE>
```

The anchor is local single-host evidence. It does not claim TPM measured boot,
Secure Boot, hardware attestation, remote attestation, or protection against an
administrator coherently restoring the repository, anchor, runtime state, and
signing environment together.

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
