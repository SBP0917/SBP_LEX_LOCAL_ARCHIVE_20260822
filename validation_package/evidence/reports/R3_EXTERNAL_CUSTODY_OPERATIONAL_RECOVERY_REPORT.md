# R3 External Custody, Key Custody and Operational Recovery Assurance

## Mission scope

R3 extends Desktop V1 assurance beyond repository storage through deterministic,
offline custody records and verification. It does not provide physical media,
hold external keys, contact cloud services, introduce nodes, distribute
authority, or execute a live restore.

Actual starting commit: `da2e90bed64169caad3989fe9557fd30e6a8a107`.
The attached mission text listed the earlier R1 commit `42b17ba`; using it would
have discarded the completed R2 baseline, so no rewind was performed.

Desktop V1 remains local-first, private, deterministic, single-host, no-node,
authority-first, and fail-closed. Canonical traversal, runtime authority,
governance, execution, measured-startup architecture, and Local Trust
architecture are unchanged.

## Custody architecture

R3 adds a detached `sbp_lex.custody` assurance package with five linked control
planes:

1. validated R1 recovery package export/import;
2. sealed off-host custody manifest;
3. public-only external key-custody records;
4. recovery-media identity and lifecycle records;
5. signed custody-chain and end-to-end continuity verification.

Canonical records use sorted JSON, SHA-256 identities, strict schemas, portable
identifiers, explicit UTC event times, and the existing domain-separated PQC
provider. Private-key material is never accepted or serialized.

## Off-host backup custody

An off-host package wraps—not reimplements—a validated R1 backup. Export uses a
staging directory and publishes only after validation. The custody manifest
binds:

- R1 backup identifier, generation, aggregate digest, and full package digest;
- repository commit;
- measured baseline and runtime identity;
- custody package and chain identifiers;
- custody sequence and predecessor;
- external key-custody manifest digest;
- explicit export time.

Import revalidates the complete R1 package, completion markers, package digest,
manifest signature, expected repository/baseline/runtime, generation floor, and
replay registry. Unexpected root members, symlinks, stale generations, replayed
identifiers, substitutions, corruption, and foreign bindings fail closed.

## External key custody

R3 models external custody using public information only:

- public-key trust records;
- external signing request and response envelopes;
- key-custody manifest;
- revocation records;
- rotation records;
- distinct external-signing and recovery-only roles;
- two-distinct-authority control preparation.

Signing requests bind a payload digest, purpose, key, custody identifier, and
dual approvals. Responses bind the exact request digest and active public trust
record. Unknown, mismatched, revoked, duplicated, or incorrectly purposed keys
fail closed. R3 does not generate, import, escrow, recover, or persist private
keys.

## Operational recovery media

Recovery-media records bind media identity, custody package, custody-manifest
digest, package checksum, copy number, maximum-copy policy, offline/read-only
classification, and lifecycle status. The deterministic lifecycle permits only:

- active to failed or retired;
- failed to retired or destroyed;
- retired to destroyed.

Destroyed media cannot reactivate. Duplication is capped at two identified
copies. Recovery invocation requires two distinct approvals. Failure,
retirement, destruction, and incident evidence are procedural signed records;
no physical-media action is claimed.

## Custody-chain verification

Every custody event binds the chain, package, sequence, action, operator role,
event time, predecessor digest, and optional receipt or incident reference.
Validation requires an export genesis, contiguous sequences, exact predecessor
digests, correct chain/package identities, and receipts for receipt events.

End-to-end verification requires export, receipt, media creation, and independent
verification events, then checks:

```text
Repository / R1 backup
  -> custody package and manifest
  -> external public-key custody
  -> recovery media
  -> custody-chain verification
  -> optional restore result
  -> measured startup
  -> runtime
  -> deterministic replay
```

If restore evidence is supplied, restore, measured startup, runtime, and replay
must all pass. No broken link has a warning-mode continuation.

## Operational procedures

The record model supports repository operator, custody operator, custody
administrator, recovery operator, and auditor roles. Deterministic records cover
transfer, receipt, recovery authorization, verification, incident, retirement,
and destruction. These are engineering evidence primitives, not human workflow
software and not delegated execution authority.

## Adversarial testing

The targeted R3 suite passes `35/35`. It covers modified, substituted, stale,
replayed, corrupted, foreign, and unexpected-member packages; repository,
baseline, and runtime mismatch; broken chains; unknown custody identifiers;
incorrect receipts; duplicate or improperly separated keys; insufficient dual
control; revoked keys; mismatched signing responses; corrupted or over-duplicated
media; invalid lifecycle transitions; missing media; incomplete custody chains;
and failed post-restore assurance.

The pre-approval focused R3, R2, R1, H4A, H6GHI, H7, and PHQ integration
suite passes `552/552`, with three expected Windows symlink skips.

## Measured baseline and runtime linkage

R3 changes protected assurance software, tests, schemas, and documentation. The
intended successor is `DESKTOP_V1_R3_APPROVED_2026_07_12_16`, retiring
`DESKTOP_V1_R2_APPROVED_2026_07_12_15` under approval reference
`R3_EXTERNAL_CUSTODY_OPERATIONAL_RECOVERY_2026_07_12`.

The final R2 supply-chain manifest is refreshed after R3 protected evidence and
baseline approval. The R3 operational profile then binds that supply-chain
identity, final measured baseline, and runtime identity.

## Verification summary

Required verification includes targeted and focused integration tests,
compileall, the complete direct suite, the batch wrapper, measured startup,
Local Trust evidence comparison, Constitutional Gates, Toolchain Guard, Release
Integrity, Capstone, R2 offline verification, R3 profile validation, runtime,
replay, and Git checks. Final complete totals are returned with the mission
outcome after the explicit measured-baseline transition.

## Limitations

- R3 provides deterministic custody evidence and verification, not physical
  storage, media handling, courier services, or human authorization.
- External signatures are schema- and trust-record-bound; actual external HSM
  signing and independent key ceremony remain operator-controlled activities.
- No external timestamp authority, transparency log, hardware attestation, or
  third-party custodian is contacted.
- A real operational export, transfer, receipt, physical recovery drill, and
  destruction ceremony require separately authorized human execution.

## Architectural impact

There is no canonical runtime or authority change. R3 is detached,
non-authoritative operational assurance. It introduces no node, quorum, remote
execution, cloud service, or distributed topology.
