# EIE, Hard Entry, Canonical State and Collective Attachment Runtime Specification

Status: Desktop V1 Runtime Pass 3 implementation contract
Scope: external request through Collective Signal Attachment only
Provider mode: deterministic local synthetic fixtures only

## Locked flow

```text
External Request
→ Adapter
→ EIE
→ Synthetic SKG Validation
→ Synthetic DTN Validation
→ Bridge Validation
→ Hard Entry Gate
→ Canonical State Construction
→ Collective Signal Attachment
→ Root of Trust
```

This pass stops at the Root of Trust input boundary. It does not change Root of
Trust authority, Procedural Truth, Classification, Licensing, Governance,
Domain, Aurion, or Execution Gate authority.

## Boundary invariants

1. The adapter is non-authoritative. It validates a closed request contract,
   normalizes Unicode and mapping order deterministically, enforces structural
   and byte limits, rejects undeclared fields and direct internal-state keys,
   and creates the normalized-request digest/request fingerprint.
2. One EIE is built from the immutable adapter serialization. The production
   path passes that same EIE into synthetic package construction and validation;
   neither package validation nor state construction rebuilds it.
3. The EIE has schema `desktop-v1.eie.v1`. Its digest excludes only its own
   `eie_hash` field. Adding, removing, or changing any other field changes the
   digest and is rejected.
4. Authority declarations in the EIE remain inputs with status
   `UNVALIDATED_INPUT`. No Governance, Classification, Licensing, Root of Trust,
   Procedural Truth, Domain, Aurion, or execution result is permitted in the EIE.
5. Hard Entry accepts only a losslessly serialized, digest-sealed
   `HardEntryAdmission`. It is not an authority or execution token.
6. Invalid ingress produces `HardEntryDenialEvidence`; it produces no canonical
   state, no authority token, no Governance result, no execution result, and no
   downstream stage traversal.
7. `build_state(HardEntryAdmission)` is the sole canonical state constructor.
   A raw request or signal package cannot call it successfully.
8. Raw SKG/DTN package bodies never enter canonical state. State receives only
   verified references, validation status, package digests, and the bridge
   result digest.
9. Collective attachment occurs once, after state construction. It attaches a
   closed minimal projection, builds the PT evidence envelope, binds request,
   EIE, digest, freshness, and validated substrate references, and appends an
   attachment hash to the state hash chain.
10. Both Desktop V1 pipelines materialize the same sealed attached initial
    state. Exact equality is required for the EIE, substrate references, state
    construction hash, collective package, and state-hash basis. No near-match
    reconciliation exists.

## Adapter contract

The request contract remains JSON-only and closed at every declared control
structure. The required fields are `action`, `payload`, `resolved_authority`,
`jurisdiction`, `context`, and `safety_profile`. Optional EIE input declarations
are `objective`, `actor`, `principal`, and `authority_claims`.

Opaque application values under declared `parameters` and `metadata` remain
bounded JSON data, but internal state/control keys are rejected recursively.
Limits are enforced by `sbp_lex.api.schema_validation`, including:

- maximum canonical request size: 65,536 UTF-8 bytes;
- maximum JSON depth: 8;
- maximum keys: 160;
- maximum string length: 8,192;
- maximum list length: 128;
- maximum evidence items: 25.

The adapter output is stored as lossless canonical JSON in frozen
`AdapterResult`. Mutating the caller's request after adaptation cannot change
the adapter serialization, fingerprint, or digest.

## Canonical EIE

The EIE binds:

- normalized request fingerprint and source-payload hash;
- action, intent, objective, actor, and principal declarations;
- unvalidated authority claim inputs and jurisdiction declaration;
- AP-ACF/autonomy/deployment declarations;
- consequence profile and environment modifiers;
- deterministic SKG and DTN package reference digests;
- logical issued-at, validity window, nonce, and replay scope.

The synthetic SKG/DTN packages bind the EIE digest. Because a content digest
cannot cryptographically contain package digests that themselves contain that
same EIE digest, the EIE holds deterministic package *reference digests*.
Validated package content digests are bound immediately afterward in Hard Entry
admission and canonical state's `verified_substrate_references`.

Freshness uses `REQUEST_FINGERPRINT_LOGICAL_CLOCK_V1`. The issued-at value is
derived from the request fingerprint, the validity window is 300 logical
seconds, and the nonce binds request fingerprint, traversal identity, and
logical issue time. This keeps valid builds and replay verification
deterministic while allowing caller-owned replay registries and explicit stale
tests.

## Hard Entry

Hard Entry validates, in order:

- immutable adapter seal and normalized request fingerprint;
- exact EIE schema, digest, request binding, mandatory/forbidden fields,
  freshness, and nonce/replay scope;
- canonical collective-signal schema, digest, PQC signature, request binding,
  EIE binding, timestamp, freshness window, and nonce;
- SKG context verification and DTN-to-SKG constraint verification;
- SKG and DTN validation statuses and package reference/digest presence;
- bridge status and deterministic bridge result digest;
- raw-package isolation and direct-state-write denial;
- caller-owned EIE nonce/digest replay registry.

Replay state is caller-owned. A single dual-pipeline traversal consumes one EIE
admission once and shares its prepared initial state with both pipelines.
Intentional replay verification uses a fresh admission domain per recorded run;
reusing a registry rejects the duplicate nonce and EIE digest.

## Canonical state construction

The sole builder is `sbp_lex.shared.state_builder.build_state`. It accepts only a
validated `HardEntryAdmission`. The state schema is
`desktop-v1.canonical-state.v1` and begins from explicit controlled defaults.

Protected fields include state/request versions, immutable request snapshot and
fingerprint, traversal and EIE identity, source payload, action/payload/context,
authority and jurisdiction declarations, verified substrate references, and
Hard Entry evidence. Their digest is stored under `boundary_protection` and is
verified before attachment, before Root of Trust, and before terminal pipeline
finalisation.

The state construction hash is deterministic and is computed before attachment.
State construction does not contain raw substrate packages, collective context
objects, or a PT evidence envelope.

## Collective Signal Attachment

Attachment requires state status `UNATTACHED`. A second call raises
`collective_signal_already_attached`. Before any write it verifies the protected
state digest. It then verifies the collective package and the request/EIE,
authority, jurisdiction, digest, freshness, and SKG/DTN bindings.

The attached projection contains only the fields required by later unchanged
runtime logic: bounded signals, SKG/DTN context digests, timestamp/nonce,
collective digest, and the verified local PQC signature. Raw SKG/DTN contexts and
synthetic substrate evidence are excluded.

The attachment record binds:

- request fingerprint;
- EIE digest;
- collective signal digest;
- logical timestamp and freshness window;
- pre-attachment state hash;
- SKG package digest;
- DTN package digest;
- bridge result digest.

Its `attachment_hash` is included in the `collective_attach` hash-chain entry.
Failed validation sets attachment status `REJECTED`, denies and halts that
already-constructed state, and cannot enter Root of Trust. In the normal
external path the same failures are caught by Hard Entry and therefore form no
state at all.

## Exact dual-pipeline parity

`prepare_pipeline_boundary` performs Hard Entry, the sole state construction,
and the sole attachment once. It serializes the result in
`PreparedPipelineBoundary`. Pipeline A and Pipeline B each materialize an exact
copy only after the seal, state digest, construction hash, attachment hash, and
protected-field digest pass.

`pipeline_initial_parity` records both initial hashes and exact field equality.
Any mismatch halts execution and registers divergence. `near_match_reconciliation_used`
is permanently `false`.

## Deterministic denial evidence

`HardEntryDenialEvidence` contains the stable failure set, stop point, available
request/EIE digests, and a denial evidence digest. It explicitly records:

- `governed_state_formed: false`;
- `authority_token_issued: false`;
- `governance_result_issued: false`;
- `downstream_stage_reached: false`.

It intentionally contains no state version, decision, Governance result, or
execution result.

## Verification and evidence

Focused verification is `tests/test_runtime_pass3_eie_state_boundary.py`.
Runtime evidence is generated by:

```text
python -m sbp_lex.runtime.eie_state_boundary_evidence
```

The generated artifact is
`outputs/runtime/eie_state_boundary_evidence.json`. It records the normalized
request, EIE, SKG, DTN, bridge, initial state, attachment, and both pipeline
initial hashes plus exact parity, invalid-ingress, bypass, runtime, and replay
results.

## Explicit non-changes

No live external provider, network linkage, credential, cloud service, sensor,
node, mesh, quorum, or distributed execution path is introduced. No second
state constructor is introduced. Pipeline order is unchanged. Governance,
Classification, Licensing, Domain, Aurion, and Execution Gate authority are
unchanged.
