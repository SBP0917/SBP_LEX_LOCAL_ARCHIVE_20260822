# SKG/DTN Runtime Gap Register

Audit pass: Runtime Pass 1 — Synthetic SKG/DTN External Substrate Alignment Audit

Repository: SBP0917/SBP_LEX_DUAL_V6

Exact commit: 00fb5979f5830f4f9f2591485d5a2a070c36eb59

Branch: main

Audit date: 2026-08-07

This is an inspection-only register. Required corrections are closure criteria for a separately authorized pass; none were implemented here.

## Classification legend

| Classification | Meaning |
|---|---|
| VERIFIED_IMPLEMENTED | Implementation and directly relevant repository tests/evidence are present. |
| IMPLEMENTED_NOT_TESTED | Implementation exists but directly relevant coverage is missing. |
| IMPLEMENTED_NOT_EVIDENCED | Evidence is insufficient to verify the implementation in the audited environment. |
| PARTIAL | Some behavior exists, but semantics, integration or enforcement is incomplete. |
| DOCUMENTED_NOT_IMPLEMENTED | The blueprint requires the behavior, but executable implementation was not found. |
| IMPLEMENTED_WITH_BLUEPRINT_CONFLICT | Implementation exists but conflicts with the locked flow or requirement. |
| NOT_APPLICABLE_DESKTOP_V1 | The capability is intentionally outside Desktop V1. |
| REQUIRES_OWNER_DECISION | An owner decision is needed before one canonical correction can be specified. |

## Ordered register

| Order | Gap ID | Classification | Priority | Missing behaviour |
|---:|---|---|---|---|
| 1 | GAP-SD-001 | IMPLEMENTED_WITH_BLUEPRINT_CONFLICT | P0 — CRITICAL | EIE-first construction and one active path matching the locked sequence. |
| 2 | GAP-SD-002 | DOCUMENTED_NOT_IMPLEMENTED | P0 — CRITICAL | Canonical EIE package references, package-to-EIE digest fields/checks, and canonical EIE signature mode. |
| 3 | GAP-SD-003 | PARTIAL | P0 — CRITICAL | One mandatory active integration path through all strong validators. |
| 4 | GAP-SD-004 | IMPLEMENTED_WITH_BLUEPRINT_CONFLICT | P0 — CRITICAL | Mandatory package presence and stable missing-package failures on the active external path. |
| 5 | GAP-SD-005 | IMPLEMENTED_WITH_BLUEPRINT_CONFLICT | P1 — HIGH | Resolvable schemas, schema/sample/type agreement, exact allowed fields and version parity. |
| 6 | GAP-SD-006 | PARTIAL | P1 — HIGH | external_governance_result, runtime_authority and identical EXECUTE/HALT/value vocabularies across all boundaries. |
| 7 | GAP-SD-007 | PARTIAL | P1 — HIGH | Fail-closed semantic enforcement and propagation of legitimacy, precedence, procedure and evidence sufficiency. |
| 8 | GAP-SD-008 | PARTIAL | P1 — HIGH | End-to-end propagation and decisive feasibility/pathway/consequence enforcement. |
| 9 | GAP-SD-009 | DOCUMENTED_NOT_IMPLEMENTED | P1 — HIGH | Canonical EIE digest input; semantic authority/jurisdiction comparisons; complete conflict rules. |
| 10 | GAP-SD-010 | PARTIAL | P1 — HIGH | Mandatory use by translator/active runtime, shared freshness policy, replay registration and nonce correlation. |
| 11 | GAP-SD-011 | PARTIAL | P2 — MEDIUM | Explicit objective/autonomy/deployment/environment/consequence fields, closed schema and direct authority/jurisdiction comparison. |
| 12 | GAP-SD-012 | DOCUMENTED_NOT_IMPLEMENTED | P2 — MEDIUM | Synthetic-only mode, egress guard, local URI allow-list, cloud/sensor denial, credential denial and startup assertion. |
| 13 | GAP-SD-013 | REQUIRES_OWNER_DECISION | P2 — MEDIUM | Approved rule for synthetic signature_mode, managed signature use and schema representation. |
| 14 | GAP-SD-014 | PARTIAL | P2 — MEDIUM | Explicit fixture-clock policy separating deterministic issuance from declared validation time. |
| 15 | GAP-SD-015 | IMPLEMENTED_NOT_TESTED | P2 — MEDIUM | Executable schema, external EIE digest, exact missing leakage tokens, semantic SKG/DTN conflicts, provider controls and one locked-flow test. |
| 16 | GAP-SD-016 | IMPLEMENTED_NOT_EVIDENCED | P1 — HIGH ASSURANCE | Current-pass Git cleanliness/diff, full compile, exact-commit approved test and exact-commit replay evidence. |

## GAP-SD-001 — P0 — CRITICAL

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-001 |
| Classification | IMPLEMENTED_WITH_BLUEPRINT_CONFLICT |
| Blueprint requirement | Locked flow is External Request → Adapter → EIE → synthetic SKG → synthetic DTN → contract validation → bridge → Hard Entry → State Construction → attachment. |
| Repository file | README.md<br>sbp_lex/pipeline/runner.py<br>sbp_lex/shared/state_builder.py<br>sbp_lex/collective/context_interface.py |
| Class/function/schema | run_pipeline; build_state; prepare_pre_context_signals |
| Observed implementation | The active runner prepares and validates internal SKG/DTN-style signals before build_state constructs the EIE; the richer external substrate chain is not called. |
| Missing behaviour | EIE-first construction and one active path matching the locked sequence. |
| Risk | Packages cannot be proven to derive from the canonical EIE and runtime order conflicts with the blueprint. |
| Required correction | In a later authorized pass, wire one synthetic-only EIE-first path without changing downstream authority. |
| Tests required | Exact stage-order, EIE-before-SKG, bypass-rejection and pipeline-mode parity tests. |
| Evidence required | A trace showing identical request/EIE/package/pre-context digests through the locked stages. |
| Priority | P0 — CRITICAL |
| Closure condition | Every external request follows the exact locked flow and no substrate signal is created or attached before EIE. |

## GAP-SD-002 — P0 — CRITICAL

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-002 |
| Classification | DOCUMENTED_NOT_IMPLEMENTED |
| Blueprint requirement | SKG/DTN/bridge must bind to the canonical EIE digest, and EIE must hold package references and digest/signature bindings. |
| Repository file | sbp_lex/shared/state_builder.py<br>sbp_lex/shared/control_chain_validation.py<br>external_substrates/shared/external_boundary.py<br>sbp_lex/phase19a/pre_context_translator.py |
| Class/function/schema | build_state; validate_eie_binding; ExternalIngressEnvelope; translate_external_pre_context |
| Observed implementation | The internal EIE has eie_hash; a detached candidate ingress envelope can carry package digests. |
| Missing behaviour | Canonical EIE package references, package-to-EIE digest fields/checks, and canonical EIE signature mode. |
| Risk | Request equality does not prove packages belong to the exact canonical EIE instance. |
| Required correction | Add approved immutable package-reference and EIE-digest fields and validators while preserving EIE-first order. |
| Tests required | EIE digest/reference mismatch, EIE field tamper, signature-mode mismatch and cross-EIE replay tests. |
| Evidence required | Closed digest-chain trace from request through EIE, packages, bridge and attachment. |
| Priority | P0 — CRITICAL |
| Closure condition | Every accepted package validates the exact canonical EIE digest and all references are schema-valid. |

## GAP-SD-003 — P0 — CRITICAL

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-003 |
| Classification | PARTIAL |
| Blueprint requirement | EIE-bound packages must pass hardened substrate contracts and bridge validation before Hard Entry. |
| Repository file | external_substrates/shared/external_boundary.py<br>external_substrates/shared/bridge_validator.py<br>sbp_lex/phase19a/pre_context_translator.py<br>sbp_lex/pipeline/runner.py |
| Class/function/schema | adapt_external_chain; validate_external_chain; validate_bridge; translate_external_pre_context; run_pipeline |
| Observed implementation | Hardened adapter, bridge and translator exist, but translator is runtime_attached=false, uses compatibility validators, and runner uses internal generators. |
| Missing behaviour | One mandatory active integration path through all strong validators. |
| Risk | Trust, replay, schema and freshness checks are bypassed because active runtime never invokes them. |
| Required correction | Converge split stacks behind one synthetic-only entry point and prohibit alternate attach paths. |
| Tests required | Call-graph proof, validator invocation counts, bypass rejection and per-stage failure propagation. |
| Evidence required | Coverage/trace proving the active path traverses hardened boundary, bridge, translator and Hard Entry. |
| Priority | P0 — CRITICAL |
| Closure condition | Exactly one active substrate path exists and every strong validator is mandatory. |

## GAP-SD-004 — P0 — CRITICAL

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-004 |
| Classification | IMPLEMENTED_WITH_BLUEPRINT_CONFLICT |
| Blueprint requirement | Missing SKG or DTN packages must fail closed. |
| Repository file | sbp_lex/pipeline/runner.py<br>sbp_lex/shared/hard_ingress.py<br>sbp_lex/phase19a/pre_context_translator.py |
| Class/function/schema | run_pipeline; validate_pre_context_signal_package; translate_external_pre_context |
| Observed implementation | Translator rejects missing packages, but active runner auto-generates signals and Hard Entry accepts signals=None. |
| Missing behaviour | Mandatory package presence and stable missing-package failures on the active external path. |
| Risk | Required substrate stages can be silently replaced by an internal fallback. |
| Required correction | Require the locked synthetic fixture package set for external requests; isolate any diagnostic fallback as noncanonical if owner-approved. |
| Tests required | Missing/null/empty SKG, DTN and pre-context plus fallback-bypass tests. |
| Evidence required | Active traces ending before state construction with stable failure codes. |
| Priority | P0 — CRITICAL |
| Closure condition | No external request reaches state construction with any required package absent. |

## GAP-SD-005 — P1 — HIGH

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-005 |
| Classification | IMPLEMENTED_WITH_BLUEPRINT_CONFLICT |
| Blueprint requirement | Validators must enforce coherent required/allowed fields, types and versions through executable schemas. |
| Repository file | external_substrates/shared/schemas/skg_signal_package.schema.json<br>external_substrates/shared/schemas/dtn_signal_package.schema.json<br>external_substrates/shared/schemas/skg_authority_link_signal.schema.json<br>external_substrates/shared/schemas/dtn_operational_context_signal.schema.json<br>external_substrates/skg/validator.py<br>external_substrates/dtn/validator.py |
| Class/function/schema | package schemas; signal $ref targets; validate_skg_signal_package; validate_dtn_signal_package |
| Observed implementation | Schema families and Python validators exist, but signal $refs target absent package $defs, samples use signature strings while schemas require objects, and runtime does not execute JSON Schema. |
| Missing behaviour | Resolvable schemas, schema/sample/type agreement, exact allowed fields and version parity. |
| Risk | A package may pass compatibility validation while violating its declared contract. |
| Required correction | Repair references, resolve signature representation, and execute schemas at the approved boundary. |
| Tests required | Resolve every $ref, validate all samples, reject unknown fields/types/versions, compare Python and schema outcomes. |
| Evidence required | Schema compilation, sample conformance, negative corpus and validator-equivalence logs. |
| Priority | P1 — HIGH |
| Closure condition | All schemas resolve, canonical samples conform, and invalid cases fail identically. |

## GAP-SD-006 — P1 — HIGH

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-006 |
| Classification | PARTIAL |
| Blueprint requirement | Packages must not emit governance_result, external_governance_result, execution_permission, runtime_authority, ALLOW, DENY, ESCALATE, EXECUTE or HALT. |
| Repository file | external_substrates/shared/validation.py<br>external_substrates/shared/bridge_validator.py<br>sbp_lex/shared/hard_ingress.py<br>sbp_lex/phase19a/pre_context_translator.py<br>tests/test_phase19a_bounded_translator.py |
| Class/function/schema | forbidden key/value sets and recursive scanners |
| Observed implementation | governance_result and execution_permission are blocked; stronger paths block ALLOW/DENY/ESCALATE; translator adds EXECUTE/HALT. |
| Missing behaviour | external_governance_result, runtime_authority and identical EXECUTE/HALT/value vocabularies across all boundaries. |
| Risk | Path-dependent scans can let authority-shaped content survive as context. |
| Required correction | Use one immutable shared vocabulary and recursive scanner at every boundary. |
| Tests required | Every exact key/value at each depth and boundary, variants, and vocabulary-parity test. |
| Evidence required | Generated matrix showing all locked tokens rejected by all entry points. |
| Priority | P1 — HIGH |
| Closure condition | Every boundary consumes the same vocabulary and all locked tokens fail before state construction. |

## GAP-SD-007 — P1 — HIGH

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-007 |
| Classification | PARTIAL |
| Blueprint requirement | SKG must enforce authority, jurisdiction, legitimacy, precedence, procedure, evidence and provenance. |
| Repository file | external_substrates/skg/legitimacy_resolver.py<br>external_substrates/skg/precedence_resolver.py<br>external_substrates/skg/evidence_registry.py<br>external_substrates/skg/signal_builder.py<br>external_substrates/dtn/constraint_applier.py<br>external_substrates/shared/pre_context_schema.py |
| Class/function/schema | resolve_legitimacy; resolve_precedence; EvidenceRegistry; procedural_requirement_signal; apply_skg_constraints; PRE_CONTEXT_SIGNAL_TYPES |
| Observed implementation | The richer SKG builds most categories, but legitimacy/evidence are not decisive, precedence need not resolve, and procedural_requirement_signal is dropped. |
| Missing behaviour | Fail-closed semantic enforcement and propagation of legitimacy, precedence, procedure and evidence sufficiency. |
| Risk | Structurally valid packages can lack required truth-foundation semantics. |
| Required correction | Make every required semantic signal validated, decisive and preserved into DTN/pre-context. |
| Tests required | Illegitimate authority, unresolved precedence, unmet procedure, insufficient evidence, conflicts and propagation. |
| Evidence required | Decision table and traces showing each failed predicate blocks DTN/bridge. |
| Priority | P1 — HIGH |
| Closure condition | Every required SKG semantic is generated, enforced and retained through attachment. |

## GAP-SD-008 — P1 — HIGH

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-008 |
| Classification | PARTIAL |
| Blueprint requirement | DTN must supply environment, operation, feasibility, dependency, pathway, risk and consequence after SKG constraints. |
| Repository file | external_substrates/dtn/signal_builder.py<br>external_substrates/dtn/constraint_applier.py<br>external_substrates/shared/pre_context_schema.py<br>external_substrates/shared/pre_context_package.py<br>sbp_lex/phase19a/pre_context_translator.py |
| Class/function/schema | build_dtn_signal_package; apply_skg_constraints; PRE_CONTEXT_SIGNAL_TYPES; _build_runtime_dtn_context |
| Observed implementation | Detached DTN constructs the categories, but environment, capability, feasibility, pathway and cascade are dropped by composition/translation; prohibited_pathway_ids is always empty. |
| Missing behaviour | End-to-end propagation and decisive feasibility/pathway/consequence enforcement. |
| Risk | Hard Entry can receive reduced context omitting material constraints. |
| Required correction | Align allow-lists with the approved DTN contract and make nonviable pathways decisive. |
| Tests required | Environment mismatch, infeasible request, missing dependency/capability, prohibited pathway, cascade failure and propagation parity. |
| Evidence required | Field lineage for every required DTN signal through validated attachment. |
| Priority | P1 — HIGH |
| Closure condition | All required DTN semantics survive translation and failed constraints block state construction. |

## GAP-SD-009 — P1 — HIGH

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-009 |
| Classification | DOCUMENTED_NOT_IMPLEMENTED |
| Blueprint requirement | Bridge must prove EIE, request, jurisdiction and authority consistency and reject semantic conflicts. |
| Repository file | external_substrates/shared/bridge_validator.py<br>external_substrates/dtn/constraint_applier.py<br>docs/blueprint_alignment/EIE_SKG_DTN_DOMAIN_BOUNDARY_MAP.md |
| Class/function/schema | validate_bridge; apply_skg_constraints |
| Observed implementation | Bridge correlates request fingerprints and package/pre-context digests and checks declared consistency flags. |
| Missing behaviour | Canonical EIE digest input; semantic authority/jurisdiction comparisons; complete conflict rules. |
| Risk | Digest-consistent packages can remain mutually inconsistent in authority or jurisdiction. |
| Required correction | Extend the approved bridge contract with normalized EIE, authority and jurisdiction assertions and stable conflict codes. |
| Tests required | EIE, jurisdiction, authority lineage, precedence, procedure and pathway conflict cases. |
| Evidence required | Positive/negative semantic bridge decision corpus. |
| Priority | P1 — HIGH |
| Closure condition | Bridge acceptance proves exact request/EIE identity and semantic authority/jurisdiction consistency. |

## GAP-SD-010 — P1 — HIGH

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-010 |
| Classification | PARTIAL |
| Blueprint requirement | Freshness, provenance, managed signature, replay and nonce status must be enforced before bridge acceptance. |
| Repository file | external_substrates/shared/external_boundary.py<br>external_substrates/shared/external_replay_store.py<br>external_substrates/shared/source_attestation.py<br>external_substrates/shared/bridge_validator.py<br>sbp_lex/phase19a/pre_context_translator.py |
| Class/function/schema | validate_external_chain; adapt_external_chain; ExternalReplayStore; validate_bridge; translate_external_pre_context |
| Observed implementation | Hardened boundary enforces time windows, provenance, trust-store signatures and durable replay/rollback. |
| Missing behaviour | Mandatory use by translator/active runtime, shared freshness policy, replay registration and nonce correlation. |
| Risk | Strong detached controls provide no runtime assurance when bypassed. |
| Required correction | Make hardened validation and replay registration prerequisites for bridge and translation. |
| Tests required | Stale/future time, duplicate nonce/digest, rollback, unknown signer, weak provenance and restart durability. |
| Evidence required | Replay-store records and active traces proving validation/registration before state construction. |
| Priority | P1 — HIGH |
| Closure condition | No acceptance occurs without hardened freshness, provenance, signature and replay checks. |

## GAP-SD-011 — P2 — MEDIUM

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-011 |
| Classification | PARTIAL |
| Blueprint requirement | Canonical EIE must explicitly bind action, objective, authority, jurisdiction, autonomy, deployment, environment and consequence. |
| Repository file | sbp_lex/shared/state_builder.py<br>sbp_lex/shared/control_chain_validation.py<br>fixtures/phase19a/schemas/eie.schema.json<br>sbp_lex/api/schema_validation.py |
| Class/function/schema | build_state; validate_eie_binding; eie.schema.json; validate_request_schema |
| Observed implementation | Action, authority and jurisdiction are copied; payload/context and request fingerprint indirectly bind other inputs. |
| Missing behaviour | Explicit objective/autonomy/deployment/environment/consequence fields, closed schema and direct authority/jurisdiction comparison. |
| Risk | Indirect nesting makes presence and semantic binding difficult to prove. |
| Required correction | Add explicit approved fields and validation without changing authority semantics. |
| Tests required | Omission/type/range and request-to-EIE mismatch for every field plus serialization stability. |
| Evidence required | Canonical examples and field-by-field binding trace. |
| Priority | P2 — MEDIUM |
| Closure condition | Closed EIE schema/validator explicitly covers every locked field and mismatch. |

## GAP-SD-012 — P2 — MEDIUM

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-012 |
| Classification | DOCUMENTED_NOT_IMPLEMENTED |
| Blueprint requirement | Active controls must block live calls, credentials, uncontrolled URLs, cloud endpoints, sensors and external permissions. |
| Repository file | README.md<br>external_substrates/EXTERNAL_SUBSTRATE_LOCK.md<br>external_substrates/shared/source_attestation.py<br>external_substrates/shared/source_crypto.py |
| Class/function/schema | Desktop scope declarations; build_source_attestation; provider configuration search |
| Observed implementation | No live network/cloud/sensor implementation was found; local fixtures and public verification material are used. |
| Missing behaviour | Synthetic-only mode, egress guard, local URI allow-list, cloud/sensor denial, credential denial and startup assertion. |
| Risk | Absence is not an active control and can drift. |
| Required correction | Add an approved synthetic-only invariant and testable source/egress/credential guards without adding live capability. |
| Tests required | Network client, nonlocal URI, cloud host, sensor source, credential config and external permission rejection. |
| Evidence required | Startup posture and negative-test logs for all forbidden provider surfaces. |
| Priority | P2 — MEDIUM |
| Closure condition | Synthetic-only mode is mandatory and every forbidden surface actively fails closed. |

## GAP-SD-013 — P2 — MEDIUM

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-013 |
| Classification | REQUIRES_OWNER_DECISION |
| Blueprint requirement | Synthetic packages and EIE must expose one coherent signature or signature-mode binding. |
| Repository file | external_substrates/shared/signing.py<br>external_substrates/shared/source_crypto.py<br>external_substrates/shared/schemas/skg_signal_package.schema.json<br>external_substrates/shared/schemas/dtn_signal_package.schema.json |
| Class/function/schema | placeholder HMAC; managed ML-DSA; schema signature properties |
| Observed implementation | Compatibility fixtures use a signature string while managed validation and schemas expect structured ML-DSA evidence. |
| Missing behaviour | Approved rule for synthetic signature_mode, managed signature use and schema representation. |
| Risk | Validators accept different shapes under one package version. |
| Required correction | Owner selects the canonical Desktop V1 synthetic signature contract; then align schemas, samples, validators and EIE. |
| Tests required | Allowed-mode matrix, forbidden mode, schema parity, downgrade prevention and replay. |
| Evidence required | Owner decision plus regenerated sample/schema results. |
| Priority | P2 — MEDIUM |
| Closure condition | One approved signature-mode policy is uniformly enforced. |

## GAP-SD-014 — P2 — MEDIUM

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-014 |
| Classification | PARTIAL |
| Blueprint requirement | Synthetic fixtures and freshness handling must be deterministic and replayable. |
| Repository file | external_substrates/skg/signal_builder.py<br>external_substrates/dtn/signal_builder.py<br>external_substrates/demo/build_demo_chain.py<br>external_substrates/shared/external_boundary.py |
| Class/function/schema | builder timestamp defaults; build_demo_chain; freshness validation |
| Observed implementation | Committed demo uses a fixed timestamp and reproduces exact digests; generic builders default to current UTC. |
| Missing behaviour | Explicit fixture-clock policy separating deterministic issuance from declared validation time. |
| Risk | Omitted timestamps are nonreplayable while fixed timestamps become stale under wall-clock checks. |
| Required correction | Make fixture issuance time and validation clock explicit and digest-bound. |
| Tests required | Cross-process repeat, injected clock, freshness edges, historical replay and no implicit clock. |
| Evidence required | Byte-equality and freshness traces using declared clocks. |
| Priority | P2 — MEDIUM |
| Closure condition | Every fixture declares its time mode and reproduces while freshness is deterministic for declared time. |

## GAP-SD-015 — P2 — MEDIUM

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-015 |
| Classification | IMPLEMENTED_NOT_TESTED |
| Blueprint requirement | Tests must cover schema, EIE binding, full leakage vocabulary, semantic conflicts, provider blocking and active integration. |
| Repository file | external_substrates/tests<br>tests/test_phase19a_bounded_translator.py<br>tests/test_h6ghi_external_identity_trust_replay.py<br>tests/test_eie_pt_sufficiency_rebuild.py |
| Class/function/schema | existing SKG/DTN/bridge/translator/trust suites |
| Observed implementation | Strong tests exist for determinism, digests, request correlation, selected leakage, detached replay and direct injection. |
| Missing behaviour | Executable schema, external EIE digest, exact missing leakage tokens, semantic SKG/DTN conflicts, provider controls and one locked-flow test. |
| Risk | Passing existing suites can coexist with this pass's alignment gaps. |
| Required correction | Add missing tests only after contracts/corrections are approved in a later pass. |
| Tests required | All tests named by GAP-SD-001 through GAP-SD-014. |
| Evidence required | Fresh exact-commit per-requirement test report. |
| Priority | P2 — MEDIUM |
| Closure condition | Every corrected matrix row has passing positive and negative coverage. |

## GAP-SD-016 — P1 — HIGH ASSURANCE

| Required field | Record |
|---|---|
| Gap ID | GAP-SD-016 |
| Classification | IMPLEMENTED_NOT_EVIDENCED |
| Blueprint requirement | Git state, compile, approved tests and replay must run against the exact checkout inspected. |
| Repository file | scripts/run_tests.sh<br>main.py<br>reports/DOUBLE_TRIPLE_PRE_HANDOVER_ASSURANCE_REPORT.md<br>reports/R4_INDEPENDENT_VERIFICATION_PACKAGE_REPORT.md |
| Class/function/schema | approved wrapper; main replay; assurance reports |
| Observed implementation | Exact remote commit/branch were established and focused fixture validation passed; workspace was not a checkout, pytest was absent and partial mirror lacked full runtime imports. |
| Missing behaviour | Current-pass Git cleanliness/diff, full compile, exact-commit approved test and exact-commit replay evidence. |
| Risk | Historical reports do not substitute for fresh execution against the audited worktree. |
| Required correction | In a separate verification pass, use the exact laptop checkout with dependencies and rerun prescribed nonmutating commands. |
| Tests required | git status/branch/rev-parse/diff; compileall; scripts/run_tests; main.py replay. |
| Evidence required | Raw logs tied to commit 00fb5979f5830f4f9f2591485d5a2a070c36eb59 and its worktree state. |
| Priority | P1 — HIGH ASSURANCE |
| Closure condition | All commands execute against the same checkout and raw outputs are retained/dispositioned. |

## Stop condition

No corrections were implemented in Runtime Pass 1. This register closes the inspection task only; it does not close any listed runtime gap.
