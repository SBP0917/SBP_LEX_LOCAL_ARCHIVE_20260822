# Pass 9 Controlled PQC Migration Specification

Status: repository profile migration implemented; owner activation and external
specialist/production approvals remain separately gated.

## Scope and result

Pass 9 retains the installed `cryptography.mldsa` ML-DSA provider and changes
the canonical signature contract from the legacy V2 envelope to
`PQC_01_PROVIDER_SIGNATURE_V3`. V3 signs the payload digest together with the
complete controlled migration profile. Runtime verification accepts V3 only.

This is a controlled profile, lifecycle, and no-downgrade migration around an
existing real provider. It is not a provider replacement, hybrid deployment,
quantum-safety certification, production approval, or Windows IVVF result.

## Enforced profile

The signed profile identifies the profile and verification-policy versions,
provider and exact installed provider version, algorithm family and identifier,
security policy, signature and hybrid modes, key identifier, public-key
fingerprint, activation and expiry, revocation state, migration and legacy
states, deprecation state, and an owner approval reference.

Runtime signing and verification require all of the following operator values:

- `SBP_LEX_SIGNING_SECRET`;
- `SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY`;
- `SBP_LEX_EXPECTED_SIGNER_FINGERPRINT`;
- `SBP_LEX_PQC_MIGRATION_STATUS=MIGRATED_APPROVED`;
- `SBP_LEX_PQC_MIGRATION_APPROVAL_REFERENCE`;
- `SBP_LEX_SIGNING_KEY_ID`;
- `SBP_LEX_SIGNING_KEY_ACTIVATED_AT`;
- `SBP_LEX_SIGNING_KEY_EXPIRES_AT`;
- an explicitly present `SBP_LEX_REVOKED_SIGNING_KEY_FINGERPRINTS` registry,
  using `NONE` when no key is revoked. The non-empty sentinel preserves the
  explicit registry across Windows subprocess boundaries.

Missing, malformed, future, expired, revoked, substituted, mismatched, or
unknown values fail closed. A signing identity or profile change in an active
process is rejected and requires restart. The private seed is never written to
Pass 9 evidence.

## Legacy and archive separation

V2 signatures are rejected by the runtime verifier. A separate archive-read
function exists for historical evidence only. It requires an approval reference
listed in `SBP_LEX_APPROVED_LEGACY_ARCHIVE_POLICIES`; an arbitrary non-empty
string is not approval. Archive verification never admits work, issues a token,
creates execution authority, or converts a V2 object to V3.

## Boundary inventory

The regenerated inventory contains 22 checked repository boundaries:

- 16 direct V3/profile-enforced signature boundaries;
- one indirect EIE digest bound by the profiled Root signature;
- two SHA-256 digest-only boundaries where PQC is not applicable;
- two deterministic HMAC/bridge test surfaces explicitly excluded from live
  provider promotion;
- one local credential lifecycle boundary deferred to the owner-approved APP
  identity and consent design.

Every referenced file and symbol is resolved during inventory generation. The
inventory corrects the Pass 8 readiness report's stale function names and its
earlier over-classification of digest and synthetic integrity surfaces.

## Recovery, provenance, and interoperability

Backup, restore, startup, audit, replay, release, provenance, and local-trust
objects use the canonical signing helper and therefore inherit V3. A profile
rollback inside a backup manifest invalidates its signature and is rejected.

`requirements-pass9.lock.txt` records the exact verified assurance environment
and is a required recovery-inventory item. Provider provenance binds the direct
requirements declaration, exact lock, installed versions, and selected ML-DSA
distribution files without recording private key material.

The public interoperability vector has deterministic payload, profile, message,
and public-key inputs. ML-DSA signatures produced by the provider are randomized,
so the signature bytes are not falsely claimed to be deterministic. Both the
repository provider wrapper and the provider's direct public verifier validate
the committed vector.

## Migration-aware soak

The Pass 9 four-hour mode retains the balanced Pass 8 workload and adds a fixed
profile digest to every synthetic workload plus recurring real ML-DSA V3
sign/verify checkpoints. It records the trust classification, provider/profile
identity, checkpoint attempts and failures, and no-private-material assertion.
It remains local and produces no live external effect.

## External gates

Repository completion does not self-issue independent specialist approval,
production HSM/TPM custody, trusted production time, live external-provider
assurance, APP/privacy requirements, production operations, certification, or
final native-Windows IVVF. Those remain explicit handoff gates.
