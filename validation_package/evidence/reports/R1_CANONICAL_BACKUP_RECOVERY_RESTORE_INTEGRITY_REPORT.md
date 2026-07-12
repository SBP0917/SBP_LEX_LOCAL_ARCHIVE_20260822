# R1 — Canonical Backup, Recovery and Restore Integrity Report

## Status

Implementation complete. Final evidence-chain transition and verification are
performed after this protected report is finalised, in the mission-specified
order.

## Starting and ending commits

- Starting commit: `517d9346a208a6043440dfd61a2c9d5c36aaf2dc`
- Ending commit: created after all gates pass; the commit cannot self-reference
  inside its own content. The final mission return records the exact hash.
- Starting branch: `main`
- Starting divergence: `0 ahead / 0 behind origin/main`

## Scope

R1 adds bounded, local, fail-closed backup and restoration assurance for
SBP-LEX Dual V6 Desktop V1. It does not add cloud backup, remote authority,
nodes, quorum, distributed recovery, public deployment, execution authority,
control-token issuance, or runtime-decision mutation.

The package is under `sbp_lex/recovery/` and consists of:

- strict common/path/integrity primitives;
- recovery inventory construction and validation;
- sealed backup-manifest construction and validation;
- domain- and sensitivity-separated atomic backup creation;
- restore pre-flight and immutable staged restoration;
- atomic authoritative-generation pointer publication;
- deterministic local recovery drill;
- two JSON schemas;
- protected machine inventory and drill evidence;
- adversarial R1 tests.

## Recovery-critical inventory

`outputs/recovery_critical_inventory.json` is a machine-readable point-in-time
inventory built from the canonical repository before the R1 measured-baseline
transition. It contains 19 present artefacts. Optional authoritative ledgers are
included only when they exist; their absence is not represented as fabricated
state.

Each artefact records:

- logical name;
- authority domain;
- portable source path;
- portable recovery path;
- required or optional status;
- sensitivity class;
- format;
- SHA-256 content digest and byte size;
- sequence and predecessor identity;
- deterministic restore order;
- validation method;
- writer authority.

The inventory rejects duplicate logical names, duplicate recovery locations,
unknown required artefacts, incomplete required inventories, ambiguous domains,
absolute paths, path traversal, symlink sources, invalid sequences, invalid
predecessors, invalid formats, invalid sensitivity classes, and invalid restore
order. The protected snapshot aggregate digest is:

`cef1145b39a172d025d4fd36834250d97efb9bf0311b03b6d3fc9b22bf57e7ff`

## Authority domains

The enforced dependency/domain order is:

1. configuration;
2. security state;
3. external identity and replay;
4. execution integrity;
5. audit and attestations;
6. measured startup;
7. Local Trust;
8. formal assurance.

Each artefact belongs to exactly one domain. Every domain has a separately
digested domain manifest. Package storage is further separated into
`public_evidence` and `protected_private` subtrees. A path, manifest entry, or
domain package cannot be substituted into another domain or sensitivity class.

## Backup-manifest schema

The sealed manifest binds:

- `R1_DESKTOP_V1_SEALED_BACKUP_MANIFEST_V1`;
- exact Desktop V1 local/private/single-host/no-node scope;
- deterministic backup identifier;
- repository commit;
- approved measured-baseline identifier;
- runtime identity;
- UTC creation timestamp;
- backup generation and predecessor backup identifier;
- complete artefact inventory;
- ordered authority-domain manifests;
- per-artefact digests, sequences, predecessors, and recovery paths;
- aggregate canonical digest;
- the established PQC-provider integrity envelope.

Strict JSON duplicate-key rejection occurs before schema validation. Portable
evidence contains no absolute host paths. Exact repository, measured baseline,
runtime identity, scope, lineage, and aggregate binding are mandatory.

## Backup publication method

Backup creation requires an explicitly approved backup root. It:

1. acquires an exclusive publication lock;
2. creates a unique same-volume staging directory;
3. checks every source against the pre-built inventory;
4. rejects symlinks and secret material;
5. writes and flushes each member atomically;
6. verifies every staged digest;
7. re-reads every authoritative source to detect mid-snapshot mutation;
8. writes and verifies the sealed manifest;
9. writes the final completion marker;
10. atomically publishes the complete directory;
11. flushes the parent directory where supported.

Failure removes the staging directory. Collision with another backup writer
fails closed. A crash before publication exposes no valid package; a crash
after publication exposes a complete verified package.

## Restore pre-flight

Pre-flight is completed before destination mutation. It validates:

- strict package and manifest schemas;
- integrity signature and aggregate digest;
- completion marker and exact package-member set;
- every artefact digest and size;
- secret-material boundary;
- repository commit, Desktop V1 scope, measured baseline, and runtime identity;
- authority-domain separation;
- generation continuity and predecessor backup identity;
- backup-identifier replay;
- per-artefact sequence and predecessor continuity;
- ledger sequence, order, hash linkage, and canonical integrity-store
  checkpoint/signature validation where applicable;
- approved destination root and symlink safety;
- empty/unmanaged destination rejection.

No operator flag bypasses rollback or compatibility protection.

## Staging model and atomic authoritative replacement

Restore extracts only into a unique staging area. Every staged artefact is
validated again. The complete staging tree is atomically published as an
immutable generation below `.recovery_generations/`.

The new generation becomes authoritative through one flushed, signed,
atomically replaced `recovery.current.json` pointer. This avoids multi-file
mixed state: before pointer publication the old complete generation remains
authoritative; after publication the new complete generation is authoritative.
An orphan complete generation created by interruption is not authoritative.

An unexpected file in an authoritative generation, a missing file, or a digest
substitution makes validation fail closed.

## Restore ordering

The enforced numerical ranges follow actual dependencies:

```text
configuration 100–199
→ security state 200–299
→ external identity/replay 300–399
→ execution integrity 400–499
→ audit/attestations 500–599
→ measured startup 600–699
→ Local Trust 700–799
→ PHQ formal assurance 800–899
```

Order values must be strictly increasing, unique, and inside the artefact's
authority-domain range.

## Rollback and substitution protection

R1 rejects:

- older or repeated backup generations;
- generation gaps;
- replayed backup identifiers;
- missing, unknown, or forked predecessor backup identities;
- lower artefact sequence;
- changed content at the same protected sequence;
- changed content without the exact prior digest as predecessor;
- duplicate/reordered ledger sequence;
- broken hash linkage;
- stale or substituted checkpoints/anchors through digest, signature, sequence,
  generation, and predecessor checks;
- repository, baseline, runtime, Desktop scope, domain, sensitivity, and path
  substitutions;
- partial or truncated packages;
- unknown package/generation members.

A deliberate operator request does not bypass these checks. Deliberate rollback
would require a separate visible evidence-producing process not implemented by
R1.

## Crash consistency

Fault injection covers interruption:

- after backup staging creation;
- during member staging;
- before backup publication;
- after backup publication;
- during restore extraction;
- after partial staged-domain extraction;
- during offline validation;
- before authoritative generation replacement;
- after generation publication but before pointer publication;
- before pointer durability flush;
- after pointer durability and before fresh-process startup.

Observed invariant: either no/new pointer exists and the previous complete state
remains authoritative, or the new complete generation is authoritative. No
mixed generation is accepted.

## Fresh-process validation

Fresh-process commands are trusted caller policy, never package-controlled
commands. They run with `shell=False`, bounded timeout, and digest-only captured
evidence. A non-zero result fails the restore and writes a persistent signed
`recovery.inoperable.json` marker. Subsequent authoritative validation remains
fail-closed until a separately authorised resolution occurs.

Repository-wide post-restore assurance is separately run in new processes:
measured startup, runtime identity, Local Trust comparison, Constitutional
Gates, Toolchain Guard, release integrity, capstone, H7, PHQ, runtime smoke,
deterministic replay, and audit continuity.

## Recovery drill

`outputs/r1_recovery_drill.json` records a deterministic local drill using only
temporary approved roots and synthetic non-secret state. It:

1. creates an eight-domain fixture;
2. builds and seals a backup;
3. validates it;
4. restores through staging;
5. publishes one authoritative generation;
6. validates in a new Python process;
7. verifies expected/restored identities;
8. corrupts a package member and proves rejection;
9. replays a backup identifier and proves rejection;
10. confirms live canonical state was not modified.

Result: `RECOVERY_DRILL_PASS`
Backup identifier: `R1_BACKUP_00000001_817AB8955EF3A92E96231BC4`
Result digest: `a45c4b82d6083aa2dc33762f9cb2772ba3e98d1e2c9e19c601e31fa986fad227`

## Tests added

`tests/test_r1_canonical_backup_recovery.py` includes deterministic and
parameterised coverage for every required adversarial class, including valid
backup/restore, deterministic manifests, required/unknown artefacts, all
manifest/member corruption classes, sequence/linkage failures, rollback,
lineage fork, repository/runtime/foreign substitution, domain substitution,
path and symlink escape, approved roots, partial/interrupted creation and
restore, concurrent writers, secret leakage, ambiguous completion,
fresh-process failure, Local Trust mismatch, H7 inconsistency, PHQ inconsistency,
and audit-continuity failure.

Current targeted result: **63 passed, 2 skipped**. The skipped cases are the two
adversarial symlink-creation tests on a Windows execution identity without
symlink creation privilege; production code still rejects symlinks and all
non-symlink path-escape cases pass.

Current focused R1 + H4A + H6GHI + H7 + H8 + PHQ result:
**511 passed, 2 skipped**. Both skips are the Windows symlink-privilege cases.

## Commands and pre-evidence results

Commands used during implementation include:

```text
python -m pytest -q tests\test_r1_canonical_backup_recovery.py
python -m pytest -q tests\test_r1_canonical_backup_recovery.py tests\test_h4a_security_state_persistence.py tests\test_h6ghi_external_identity_trust_replay.py tests\test_h7_deterministic_execution_integrity.py tests\test_h8_measured_startup_runtime_identity.py tests\test_phq_formal_deterministic_architecture.py
python -m sbp_lex.recovery.inventory build --output outputs\recovery_critical_inventory.json
python -m sbp_lex.recovery.inventory validate --output outputs\recovery_critical_inventory.json
python -m sbp_lex.recovery.recovery_drill --root <approved-temporary-root> --output outputs\r1_recovery_drill.json
```

The required pre-transition direct-suite diagnostic reached the entire suite:
**1,515 passed, 2 skipped, 28 failed closed**. Every failure was a runtime test
blocked by H8 `runtime_measurement_drift`, which is the required behavior after
protected software/configuration changes and before explicit approval of the
successor measured baseline. No functional R1, H4A, H6GHI, H7, H8, or PHQ test
failed. The complete direct suite, batch wrapper, Local Trust chain, all gates,
runtime, and replay are rerun after the measured-baseline reconciliation;
their exact final results are returned with the mission outcome.

## Secret-handling boundary

No reusable secret is written into source, reports, fixtures, inventory, or
portable manifest evidence. Source and staged bytes are scanned for private-key
PEM material and credential-like values. Public evidence and protected private
state are stored in separate package subtrees. The public manifest exposes only
portable metadata, hashes, sizes, authority, sequence, predecessor, and writer
identity—not private content.

R1 does not implement key escrow or export private signing keys. External key
custody remains outside this bounded local mission.

## Measured-baseline transition

- Pre-R1 approved baseline: `DESKTOP_V1_INTEGRATED_APPROVED_2026_07_12_10`
- Pre-R1 runtime identity: `4533b496bdd7729e330e3f3288ae8e3e14e005baf9ff703cca4eb95f040382ce`
- Final successor: `DESKTOP_V1_R1_APPROVED_2026_07_12_13`
- Final approval reference: `R1_FINAL_EVIDENCE_RECONCILIATION_2026_07_12`

Two explicitly approved intermediate R1 baselines (`..._11` and `..._12`) were
retired during final evidence ordering: the first preceded the finalized
Local Trust outputs, and the second preceded the protected report whitespace
correction and resulting evidence refresh. Neither baseline was silently
accepted or retained as approved.

The successor is proposed only after protected content and Local Trust evidence
are final. It is explicitly approved, the exact predecessor retired, and a real
runtime process advances the persisted anchor.

## Architecture and no-node confirmation

Canonical traversal is unchanged. EIE placement, SKG/DTN externality, State
Construction ordering, Root of Trust, Procedural Truth, Classification,
Licensing, Governance, GRC, Domain, Aurion, Execution Gate finality, H7
execution integrity, and PHQ's non-authoritative status are unchanged.

Desktop V1 remains local, private, single-host, fail-closed, deterministic, and
no-node. R1 creates no network listener and no distributed topology.

## Stash and cognitive-branch preservation

- Existing Phase 19D-D stash is not applied, changed, dropped, or incorporated.
- `phase19e-cognitive-pipelines-experimental` remains untouched.
- Untracked `baselines/`, Phase 19E contract/skeleton, and cognitive reports are
  not incorporated.

## Limitations

- R1 is bounded local backup/restore assurance, not geographic disaster
  recovery or availability assurance.
- It does not provide cloud replication, removable-media policy, HSM escrow,
  external notarisation, or remote custody.
- The authoritative-generation pointer model must be used by a separately
  authorised consumer before restored state can replace a live subsystem.
  R1 deliberately does not overwrite the live canonical repository.
- Optional API security, external replay, or H7 lifecycle ledgers cannot be
  restored if they never existed at backup time; R1 never manufactures them.
- Full repository validation remains required after any real restoration.

## Push status

No force-push is permitted. A normal push is allowed only after every required
gate and post-commit clean verification succeeds.
