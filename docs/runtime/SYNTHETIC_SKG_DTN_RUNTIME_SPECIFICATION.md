# Synthetic SKG/DTN Runtime Specification

Status: Desktop V1 Runtime Pass 2 implementation contract

Scope: deterministic local/synthetic external substrate handling only

## Invariants

The canonical order is:

`External Request → Adapter → EIE → synthetic SKG → synthetic DTN → contract validation → bridge validation → Hard Entry → State Construction → attachment`

SKG and DTN remain external, evidence-only substrates. They do not own or write
Governance, Procedural Truth, Domain, Aurion, the Execution Gate, governed state,
or execution results. Raw packages stop at the bridge. The bridge emits only a
locally signed minimal pre-context signal package already supported by Hard Entry.

Desktop V1 permits only `synthetic_local` provider mode and only
`CONTROLLED_LOCAL_HMAC_SHA256_V1` for synthetic package fixtures. This signature
mode is deterministic, local, and explicitly non-production. Managed/live signing,
URLs, network activity, provider credentials, cloud endpoints, sensor feeds,
external services, and live ingestion are denied.

## EIE-first binding

`build_execution_intent_envelope` closes the request-to-EIE contract before any
substrate package exists. The EIE explicitly binds action/objective, authority,
jurisdiction, autonomy, deployment, environment, consequence, request fingerprint,
and deterministic SKG/DTN package references. Both packages carry the exact EIE
digest and their assigned reference. Downstream SKG/DTN enrichment fields are
excluded from the immutable EIE digest payload, so attachment cannot change the
digest to which the packages were bound.

## SKG contract

Schema: `desktop-v1.synthetic.skg.v1`

Executable schema:
`external_substrates/shared/schemas/synthetic_skg_package.schema.json`

The closed package contains its type/version/reference, request fingerprint, EIE
digest, authority hierarchy, jurisdiction, legitimacy, precedence, procedural
obligation references, evidentiary references, substrate constraints, provenance,
issued time, freshness window, deterministic nonce, signature mode, digest, and
signature.

Acceptance requires exact allowed fields and types; the locked schema version;
valid request/EIE bindings; locally allowed provenance; legitimate authority;
resolved precedence; non-empty procedure and evidence references; evidence backed
by provenance; valid freshness; canonical digest; valid controlled-local signature;
and no forbidden authority key or value.

## DTN contract

Schema: `desktop-v1.synthetic.dtn.v1`

Executable schema:
`external_substrates/shared/schemas/synthetic_dtn_package.schema.json`

The closed package contains its type/version/reference, request fingerprint, EIE
digest, SKG constraint digest, authority and jurisdiction references, operational
and environmental context, feasibility constraints, dependencies, pathway
viability, consequence/risk context, provenance, issued time, freshness window,
deterministic nonce, signature mode, digest, and signature.

Acceptance requires exact allowed fields and types; the locked schema version;
valid request/EIE/SKG bindings; satisfied feasibility constraints; available and
complete dependencies; a viable pathway; consequence/risk structure; valid
provenance/freshness/digest/signature; and no authority leakage.

## Bridge and replay

`validate_synthetic_bridge` runs both separate validators and then proves:

- matching request fingerprints and EIE digests;
- matching jurisdiction and valid DTN authority reference into the SKG hierarchy;
- equal issuance time and source provenance;
- exact SKG constraint digest application;
- no prohibited SKG pathway selected by DTN;
- no missing DTN pathway dependency; and
- caller-owned nonce/digest replay registration.

Any failure yields a deterministic ordered tuple of stable failure codes and no
signals. Replay state is external validation state and has no governed-state
reference. A fresh registry permits deterministic observational replay; reuse of
the same registry rejects the same package with equal nonce/digest replay results.

## Fixture clock and serialization

Fixture issuance is explicitly `2026-08-07T00:00:00Z`; validation time is separately
declared. Builders have no implicit clock. Canonical serialization is sorted,
UTF-8 JSON with compact separators, no NaN, and deterministic collection ordering.
Freshness is evaluated only against the declared validation time.

The named fixture corpus is produced by
`external_substrates/demo/synthetic_runtime_fixtures.py` and covers valid SKG,
valid DTN, valid pair, malformed, stale, replayed, request mismatch, EIE mismatch,
digest mismatch, signature mismatch, jurisdiction conflict, authority conflict,
forbidden authority leakage, and provider activation.

## Hard Entry isolation

`validate_raw_synthetic_chain` accepts canonical raw JSON, validates the provider
posture, reconstructs the request-bound EIE, verifies package references, runs the
separate validators and bridge, and discards the raw objects. Only the existing
minimal local signal shape is signed and returned. The function accepts no state
object and exposes no Governance, Domain, Aurion, or Execution writer.

Malformed, absent, invalid, stale, replayed, mismatched, leaking, or provider-mode
packages produce `signals=None`. Hard Entry now requires a non-null signal package,
so invalid substrate input cannot construct governed state.

## Forbidden authority vocabulary

Every participating boundary consumes the shared immutable vocabulary. Forbidden
keys include `execution_permission`, `execution_result`, `execution_verified`,
`governance_result`, `external_governance_result`, `runtime_authority`, and
`final_admissibility`. Forbidden decision values are `ALLOW`, `DENY`, `ESCALATE`,
`EXECUTE`, and `HALT`, at any depth.

## Architecture boundary

This pass adds no live linkage, production API, cloud connection, credential,
sensor ingestion, node, mesh, quorum, distributed runtime, or direct substrate
execution authority. It changes no canonical authority ownership and introduces
no new architecture.
