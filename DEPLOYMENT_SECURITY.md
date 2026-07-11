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
