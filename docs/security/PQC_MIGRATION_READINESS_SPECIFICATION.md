# PQC Migration Readiness Specification

Status: historical Pass 8 readiness record; superseded for active behavior by
`PASS_09_CONTROLLED_PQC_MIGRATION_SPECIFICATION.md`

Current provider: `cryptography.mldsa`

Current algorithm identifier: `ML-DSA`

Profile version: `PASS8_CRYPTO_AGILITY_PROFILE_V1`

## Scope

Pass 8 inventories cryptographic boundaries, makes migration metadata explicit,
defines a strict verification-policy seam, measures the existing provider, and
tests provider-loss and downgrade behavior. It does not replace the provider,
merge detached PQC work, select a production migration target, certify an
implementation, or claim quantum safety.

## Required profile metadata

Every migration-aware signed object is capable of binding these fields into the
signed representation:

- profile and verification-policy versions;
- provider identifier and version;
- algorithm family and identifier;
- security profile and signature mode;
- explicit hybrid mode and components;
- key identifier and public-key fingerprint;
- creation and optional expiry time;
- revocation state;
- migration, legacy, and deprecation status.

The profile is evidence and policy input. It does not create trust or authority.
The underlying object signature covers both payload and crypto profile, so a
metadata substitution invalidates verification.

## No-silent-downgrade policy

Verification rejects:

- missing or unknown profile versions;
- provider substitution or unavailable mandatory provider;
- missing provider version;
- algorithm-family, algorithm, security-profile, or signature-mode substitution;
- verification-policy cross-version replay;
- missing, wrong, malformed, revoked, or expired key identity;
- malformed fingerprint or fingerprint mismatch;
- implicit, unapproved, or incomplete hybrid mode;
- components that are absent, invalid, or not explicitly named;
- legacy acceptance unless a future approved requirement explicitly permits it;
- a required migrated profile that is not marked `MIGRATED_APPROVED`;
- deprecated algorithm state;
- timeout, exception, or invalid object signature.

No implicit fallback is defined. Provider loss is a fail-closed condition where
the provider is mandatory.

## Provider abstraction status

The existing provider seam in `sbp_lex.security.pqc_provider` remains active and
unchanged. Pass 8 adds an explicit profile and requirement layer in
`sbp_lex.security.crypto_agility`; it does not route runtime signing to a new
provider. The provider remains `cryptography.mldsa`, reported version 49.0.0 in
the Pass 8 evidence environment.

Hybrid mode is representable but disabled by default. It requires an explicit
requirement, at least two named valid components, specialist review, migration
policy, interoperability evidence, recovery analysis, and owner approval before
any runtime use.

## Inventory method

The inventory records, per boundary: repository file and function, purpose,
protected object, algorithm/provider/version, cryptographic role, key-ID and
custody assumptions, rotation/revocation/expiry/recovery support, metadata gaps,
legacy requirements, expected lifetime, failure consequence, fail-closed
behavior, tests/evidence, Pass 9 action, and specialist-review requirement.

Twenty-two boundaries are inventoried across EIE, SKG/DTN source packages,
synthetic fixture signing, bridge and collective evidence, Root of Trust, token
and threshold proof, execution authority and attestation, state/hash chain,
audit, replay, integrity ledger, local trust, release/provenance, backup,
measured startup, update package, and delegated credentials.

The SHA-256 state/hash-chain and backup roles are explicitly classified as
digests, not signatures. The HMAC helper is explicitly classified as a
test-only synthetic placeholder and is prohibited from live/provider promotion.

## Key lifecycle readiness

Current key custody remains environment/public-verification-evidence based; no
private key is embedded by Pass 8. Rotation is restart-bound and requires
controlled evidence regeneration. Revocation and expiry are fully explicit in
the new profile contract, but the inventory records that enforcement is still
object-specific in the existing runtime. Pass 9 must decide per boundary how
profile versioning, key rotation, revocation, expiry, archive verification, and
recovery interact.

Wrong key IDs and fingerprints, revoked and expired profiles, malformed key
metadata, cross-version replay, provider substitution, and provider loss are
covered by focused negative tests.

## Performance baseline

`outputs/security/pqc_performance_baseline.json` is an engineering baseline, not
a cryptographic certification. It records platform, Python/provider versions,
warm-up method, key generation/provider startup, signing, verification, invalid
signature failure path, signature/public-key/storage sizes, traced memory, batch
sample count, rotation simulation, and archive re-signing estimate.

The Pass 8 run uses five warm-up operations and 25 measured samples. Results are
machine-specific and must not be generalized into a production capacity,
security-strength, or certification claim.

## Migration gates deferred to Pass 9 or later

Before migration, the owner-approved programme must select provider(s), define
single versus hybrid policy, establish key custody/rotation/revocation/expiry,
decide historical evidence and archive treatment, define version negotiation
without downgrade, test interoperability and recovery, complete threat and
performance analysis, obtain specialist review, and update every inventory
boundary with signed migration metadata.

Detached PQC work must remain detached until that programme explicitly approves
integration. Pass 8 does not merge, cherry-pick, or activate such work.

## Claims boundary

The inventory and tests demonstrate migration readiness and no-silent-downgrade
behavior only. They do not demonstrate completed PQC migration, general quantum
safety, production readiness, external certification, or final Windows IVVF.
