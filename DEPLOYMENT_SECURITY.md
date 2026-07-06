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

Do not use `SBP_LEX_API_SECURITY_MODE=disabled` except isolated test harnesses.

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
