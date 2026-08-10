# Pass 9 Controlled PQC Migration Decision

Status: owner-approved engineering direction implemented in the repository;
owner activation and independent specialist/production review remain gated.

## Frozen baseline

- Branch: `main`
- Pass 8 ending commit: `bc516518cde54b41a1f358a88926fbf77a3970c2`
- Pass 8 working tree: clean
- Pass 8 remains immutable evidence. Pass 9 records a delta from this commit.

## Controlled migration decision

Pass 9 migrates the canonical signature envelope from readiness-only profile
scaffolding to a profile that is signed and enforced at every canonical signing
boundary. It does not replace the installed provider or change runtime authority.

- Provider: retain `cryptography.mldsa`.
- Algorithm: retain `ML-DSA`.
- Signature mode: single provider signature.
- Hybrid mode: disabled; no implicit second component.
- Runtime legacy policy: reject pre-migration signature envelopes.
- Archive legacy policy: permit verification only through a separate explicit,
  non-runtime archive-verification API with a recorded approval reference.
- Provider loss, profile loss, profile substitution, cross-version replay,
  revoked key, expired key, wrong key, unknown provider version, and missing
  approval reference: fail closed.
- Signing-key rotation: requires process restart, a newly pinned public identity,
  and regenerated trust evidence.
- Current key custody: external environment plus pinned public verification
  identity; no private key is committed.
- Production key custody and independent specialist approval: external gates,
  not self-certified by this repository.

The migration is an envelope/profile and lifecycle migration around the existing
real ML-DSA implementation. It is not an algorithm marketing claim and does not
establish general quantum safety or production certification.

## Boundary treatment

The Pass 8 inventory contains signatures, digests, and synthetic placeholder
integrity controls. Pass 9 must not describe all three as equivalent.

- Canonical ML-DSA signatures receive the signed Pass 9 profile and strict
  verification policy.
- External SKG/DTN source ML-DSA signatures receive a substrate-owned compatible
  profile without importing runtime authority packages.
- SHA-256 digest boundaries remain explicit integrity digests and are marked
  `PQC_NOT_APPLICABLE_DIGEST_ONLY`; they are not presented as signatures.
- The deterministic external HMAC fixture surface remains test-only and is
  marked `PQC_EXCLUDED_TEST_ONLY`; it may not be promoted as a live provider.
- The inventory must be regenerated from actual code and must record enforcement,
  lifecycle, archive, recovery, and review status for every boundary.

## Operator activation and evidence order

After code and focused tests are stable:

1. provision the owner-authorised signing seed and pinned public identity through
   a secure operator environment;
2. provision key activation, expiry, revocation, and migration-approval metadata;
3. run normal runtime and deterministic replay;
4. freeze the final implementation commit;
5. refresh measured-startup, evidence-chain, local-trust, release-integrity, and
   integrity-ledger evidence against that exact implementation;
6. run recovery, rotation, downgrade, archive, provider-loss, and full regression
   verification;
7. run the four-hour migration-aware soak;
8. seal the Pass 9 report and evidence without embedding secrets.

## Detached-clone decision

No detached PQC clone is required for correctness. No clone will be created merely
to remove a gap entry. Clone creation remains deferred until the owner selects the
future baseline for the planned clean clones.

## Comprehensive repository-contained closure

Pass 9 also includes all safe work that would otherwise cause avoidable repetition:

- provider/version provenance and dependency pin evidence;
- deterministic test vectors and public-verifier interoperability;
- key rotation, revocation, expiry, clock, restart, backup, and restore cases;
- legacy/archive separation and rollback prevention;
- documentation and inventory drift correction;
- migration-specific resource and performance baselines;
- four-hour soak telemetry and final regression evidence;
- a precise handoff register for external APP, provider, production, IVVF, and
  certification owners.

## External ownership gates

The following cannot be truthfully self-issued by local repository work:

- independent cryptographic specialist approval;
- HSM/TPM or equivalent production key custody;
- live external-provider credentials and service assurance;
- APP/privacy implementation without its approved requirements and data model;
- production deployment, monitoring, incident-response operation, and legal or
  regulatory acceptance;
- external certification or university validation;
- final native-Windows IVVF, which remains reserved for Pass 10.

Pass 9 will complete repository-side readiness for these gates and provide exact
handoff evidence. It will not relabel an external dependency as locally complete.

## Non-drift boundary

No architecture redesign, authority reassignment, traversal reorder, recovery
override, live service, APP activation, clone merge, production claim,
certification claim, quantum-safe claim, or final Windows IVVF claim is authorised
by this decision.
