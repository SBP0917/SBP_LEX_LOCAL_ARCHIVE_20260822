# EIE / PT / SKG / DTN Control-Plane Handover Readiness Report

Status: Repository-side handover readiness report for `SBP0917/SBP_LEX_DUAL_V6`.

This report covers the current adjusted repository after the EIE, SKG, DTN, Root of Trust Anchorage, Procedural Truth Evidentiary Sufficiency, Execution Gate, audit/replay, and university dossier updates. It is not a production certification, external validation result, legal opinion, patent opinion, or security certification.

## Executive assessment

The current repository is now structurally coherent as a local deterministic SBP-LEX control-plane prototype. The traversal is robust enough to demonstrate the intended control-plane purpose inside the repository's current local/private scope: adapter/request material is formalised into an EIE, SKG and DTN enrich the EIE without becoming authority, Root of Trust binds the evidence set, Procedural Truth certifies evidentiary sufficiency, downstream layers are gated, Execution Gate enforces certification, and audit/replay preserves metadata.

It is not yet robust enough to claim production-grade safety, external validation, certified post-quantum compliance, live distributed operation, or operational deployment authority. The main reasons are remaining key-custody and certification gaps around the implemented PQC provider contract, compatibility defaults for new evidence metadata, limited schema depth for production EIE/source semantics, and local single-process assumptions.

## Repo evidence for current strengths

- EIE formalisation: `sbp_lex/shared/state_builder.py` creates `ExecutionIntentEnvelope`, `canonical_traversal_state`, `eie_hash`, `source_payload_hash`, and `traversal_id`.
- SKG enrichment: `external_substrates/skg/signal_builder.py` emits `skg_truth_foundation_metadata` and `skg_enrichment_hash`.
- DTN enrichment: `external_substrates/dtn/signal_builder.py` emits `dtn_contextual_verification_metadata` and `dtn_enrichment_hash`.
- PT envelope support: `sbp_lex/governance/procedural_truth_envelope.py` preserves SKG/DTN metadata, source independence, provenance, integrity, authority, jurisdiction, runtime validity, and contradiction flags.
- PT certification: `sbp_lex/governance/procedural_truth_engine.py` returns `procedural_truth_certification` with PASS/REFINE/ESCALATE/DENY, CERTIFIED/NOT_CERTIFIED, sufficiency factors, reason codes, PT token fields, request fingerprint, EIE hash, state hash, and traversal ID.
- Root anchorage: `sbp_lex/authority_first/root_of_trust_runner.py` binds EIE identity, source payload hash, adapter/source identities, SKG/DTN statuses and enrichment hashes, evidence package hash, authority reference hash, state hash, traversal ID, token-chain reference, and audit-chain reference.
- Execution enforcement: `sbp_lex/execution/execution_gate.py` denies on missing/mismatched PT certification, EIE hash, request fingerprint, PT token hash, Root/SKG/DTN status, sufficiency factor failure, unresolved contradiction, or unmet consequence burden.
- Audit/replay preservation: `sbp_lex/audit/audit_engine.py` records EIE hash, traversal ID, PT certification, SKG metadata, DTN metadata, and Root anchor; `sbp_lex/audit/historical_integrity.py` verifies the expanded Root anchor subset.
- Focused tests: `tests/test_eie_pt_sufficiency_rebuild.py` covers EIE preservation, SKG/DTN enrichment, Root anchorage, independence failure, contradiction denial, PT token mismatch, and audit metadata.

## Weak points and reasons

1. Active PQC provider use is real but not production certification.
   - Evidence: `sbp_lex/security/pqc.py`, `sbp_lex/security/pqc_provider.py`, and `tests/test_pqc_01_provider_contract.py` now bind the active PQC provider path to `cryptography.mldsa` with ML-DSA signatures. Placeholder/HMAC PQC signatures are no longer accepted in that active provider path, and provider-unavailable behavior fails closed.
   - Remaining limitation: this is an implemented provider contract, not certified PQC compliance or full post-quantum security. Local-trust deterministic `PLACEHOLDER` labels still exist only as local evidence labels and must not be described as production cryptography. Older placeholder cryptography references are historical/stale unless they explicitly refer to local-trust deterministic evidence labels.
   - Complete fix plan: introduce role-separated signing keys for request/EIE, Root, PT token, audit, release, and execution attestation; move signing behind a least-privilege signing interface; add key IDs, rotation epochs, revocation records, external custody policy, and negative tests for wrong-key, stale-key, revoked-key, provider-unavailable, and cross-role-signature substitution.

2. EIE adapter ingress is structurally present but not yet backed by multiple real adapter contracts.
   - Evidence: `state_builder.py` defaults to `LOCAL_RUNTIME_ADAPTER`, `LOCAL_RUNTIME`, and `runtime_request` when adapter identity is absent.
   - Why weak: without concrete adapter schemas, real native protocols could be translated inconsistently and still look valid under local defaults.
   - Complete fix plan: add explicit adapter contract schemas, adapter identity registry, native-format version checks, source-system allowlist, adapter negative tests, and per-adapter request fixtures.

3. New evidentiary metadata supports compatibility defaults.
   - Evidence: `procedural_truth_envelope.py` treats several fields such as provenance, integrity, authority, jurisdiction, runtime validity, and chain of custody as valid by default when legacy records omit them.
   - Why weak: compatibility defaults are useful for preserving existing tests, but production evidentiary sufficiency should require explicit positive evidence for high-consequence tiers.
   - Complete fix plan: introduce tiered strictness so LOWER may tolerate compatibility defaults only in local demo mode, while MEDIUM/TOP/EXTREME require explicit fields; add tests for omitted provenance, omitted authority, omitted jurisdiction, omitted runtime validity, and omitted chain-of-custody by tier.

4. SKG/DTN enrichment is metadata-preserving, not independently authoritative verification.
   - Evidence: `external_substrates/skg/signal_builder.py` and `external_substrates/dtn/signal_builder.py` build deterministic enrichment metadata from declared local inputs.
   - Why weak: this supports traversal proof but not real-world verification against authoritative external sources, live operational sensors, or independent institutional records.
   - Complete fix plan: define source adapter interfaces for authoritative registries, time/freshness authorities, attestation providers, and operational state providers; keep them outside execution authority; add fixture-backed contract tests and fail-closed behavior for unavailable providers.

5. Root of Trust Anchorage binds current metadata but remains local and single-process.
   - Evidence: `root_of_trust_runner.py` signs Root anchor payload inside the canonical runtime.
   - Why weak: local runtime signing cannot prove separation between state construction, Root anchorage, and PT certification under process compromise.
   - Complete fix plan: split Root anchor signing into a minimal trust service or isolated local module with narrow input schema, tamper-evident key ID, rotation, audit-chain checkpointing, and tests proving PT cannot self-anchor or re-anchor altered EIE metadata.

6. Execution Gate is strong in code-level checks but depends on complete upstream metadata.
   - Evidence: `execution_gate.py` verifies PT certification fields and tokens, but upstream omitted-field compatibility can still produce certified states for local legacy records.
   - Why weak: gate checks are only as strong as upstream certification inputs.
   - Complete fix plan: pair Execution Gate tests with strict-mode PT evidence tests; require explicit strict certification level in PT result; make Execution Gate require strict mode for TOP/EXTREME or externally submitted requests.

7. Governance, GRC, Domain, and Aurion receive the certified path but have limited semantic depth for production deployment.
   - Evidence: `sbp_lex/governance`, `sbp_lex/domains`, and `sbp_lex/aurion15` use deterministic local rules and candidate selection.
   - Why weak: the control plane can demonstrate ordering and fail-closed behavior but does not yet encode a full real-world legal/regulatory/domain ontology or live operational constraints.
   - Complete fix plan: add domain-specific rule packs, versioned policy registries, jurisdictional schema validation, domain negative tests, and Aurion pathway constraints that consume PT consequence burden and DTN affected-dependency metadata.

8. Audit/replay is deterministic but not yet append-only external custody.
   - Evidence: `audit_engine.py`, `historical_integrity.py`, and local artifact outputs store local signed records and hashes.
   - Why weak: local deterministic replay catches mutation in the repo context but cannot alone prove external timestamping, immutable storage, or independent custody.
   - Complete fix plan: add append-only local ledger file with monotonic checkpointing, independent timestamp authority interface, optional offline notarisation export, and tests for deletion, reordering, checkpoint rollback, and duplicate traversal IDs.

9. Dossier and local-trust artifacts are evidence tooling, not runtime authority.
   - Evidence: `sbp_lex/local_trust/*`, `outputs/university_validation_dossier/*`, and the updated scope lock state review-readiness only.
   - Why weak: dossier readiness is useful for handover but should not be mistaken for validation, certification, or runtime proof under live external conditions.
   - Complete fix plan: keep clear scope wording, bind rebuild artifacts and tests as evidence, and add reviewer-facing unsupported-claim prompts. This report and the updated dossier now implement that clarification.

## Complete fix roadmap

1. Add strict production evidence mode:
   - `pt_certification_mode: LOCAL_COMPAT | STRICT_REVIEW | PRODUCTION_STRICT`.
   - Require explicit provenance, independence, integrity, authority, jurisdiction, chain-of-custody, runtime validity, and consequence metadata in strict modes.
   - Add failing tests for missing fields at MEDIUM/TOP/EXTREME.

2. Add adapter contract layer:
   - `sbp_lex/adapter/` with schemas for adapter identity, native format, source system, source payload hash, and source timestamp.
   - Add per-adapter fixtures and malformed-adapter tests.

3. Separate signing roles:
   - Root, PT token, execution attestation, audit, and release signatures use separate key IDs and verification paths.
   - Add wrong-role and revoked-key tests.

4. Strengthen SKG/DTN inputs:
   - Add versioned source schemas for authority records, evidence records, operational context, locality, dependencies, and consequences.
   - Preserve non-authority boundary while requiring explicit source status for strict tiers.

5. Add policy/domain rule packs:
   - Version Governance/GRC/Domain rules and prove Domain/Aurion consume upstream PT/GRC certification rather than bypassing it.

6. Harden audit/replay custody:
   - Add append-only checkpoints, timestamp authority reference, and deletion/reorder/rollback tests.

7. Keep local-trust/dossier packages separate:
   - Evidence packages should describe and test the control plane, not become authority.

## Extra tests added or required

Added:

- `tests/test_eie_pt_sufficiency_rebuild.py`
- Expanded historical integrity verification for the enlarged Root anchor.
- Updated local-trust repository-control tests to allow only the authorised EIE/PT rebuild touch points and reject unrelated protected runtime changes.
- Updated dossier tests to cover dynamic claim/question/command counts and new rebuild scope flags.

Passed:

- Full repository suite: `583 passed in 273.51s`.

Still recommended:

- Strict-mode omitted-field tests for every new sufficiency factor.
- Adapter contract tests for at least two real adapter types.
- Role-separated signing tests.
- Append-only audit checkpoint tests.
- Domain/Aurion consequence-burden propagation tests.

## Non-runtime or support code inventory

These items are not part of the core control-plane traversal execution path. They may still be useful for operator UX, evidence, handover, demos, or historical traceability.

| Location | Files | Size bytes | Conceptual reason it exists | Control-plane relevance |
|---|---:|---:|---|---|
| `sbp_operator_assistant/` | 33 | 98,880 | Local productivity/operator assistant package. | Support-only; not required for EIE/PT traversal. |
| `sbp_lex/desktop/` | 10 | 3,038,176 | Desktop/dashboard visual surface and static assets. | UI/support; not required for headless control-plane enforcement. |
| `external_substrates/demo/` | 17 | 49,357 | Demo package builders and sample SKG/DTN/pre-context packages. | Demo/support; not required for runtime traversal if real packages are supplied. |
| `sbp_lex/local_trust/` | 90 | 1,027,256 | Local evidence, release, dossier, adversarial harness, and validation tooling. | Handover/evidence; not execution authority. |
| `docs/` | 38 | 96,216 | Documentation, demo evidence pack, blueprint addenda. | Handover/reference; not runtime code. |
| `reports/` | 24 | 124,321 | Phase reports and this readiness report. | Evidence/reference; not runtime code. |
| `outputs/` | 22 | 245,202 | Generated local trust, release, and dossier artifacts. | Evidence artifacts; not runtime code. |
| `baselines/` | 268 | 23,705,645 | Untracked historical/baseline copy area present in workspace. | Out of scope for this rebuild; should not influence current repo logic. |
| `__pycache__/` | 1 | 3,367 | Python bytecode cache. | Generated cache; no conceptual control-plane role. |

Do not delete support items automatically. For handover, preserve evidence and documentation. For a lean runtime distribution, exclude `baselines/`, `__pycache__/`, historical `outputs/`, `reports/`, `docs/`, `sbp_operator_assistant/`, and demo assets unless the release package explicitly needs review evidence.

## Handover conclusion

The repository is ready for a bounded handover review after the dossier rebuild and tests pass. It should be presented as a local deterministic control-plane prototype with strong traversal-order, fail-closed, EIE/PT certification, Root anchorage, and audit/replay evidence. It should not be presented as production-certified, externally validated, or ready for live safety-critical deployment until the fix roadmap above is implemented and independently reviewed.

## Phase 18.8B Final Repository-Contained Hardening

Phase 18.8B pushed repository-contained hardening as far as the local deterministic control-plane prototype can honestly go without redesigning traversal or adding external production infrastructure.

What was hardened after 18.8A:

- Shared EIE/SKG/DTN/Root control-chain validation in `sbp_lex/shared/control_chain_validation.py`.
- Explicit EIE hash semantics through `canonical_eie_digest`.
- Stable Root-bound state hash preservation through `root_anchor_bound_state_hash`.
- Root pre-anchor validation of EIE/SKG/DTN bindings.
- Canonical upstream checks for Classification, Licensing, Governance, and Execution Gate.
- Execution Gate independent Root anchor and control-chain verification.
- Expanded audit and replay metadata.
- Dossier positive overclaim detection.
- Focused negative tests in `tests/test_phase_18_8b_repository_hardening.py`.
- The 13-document canonical blueprint series under `docs/canonical_blueprint_series/`.

A rogue, fraudulent, malformed, mismatched, stale, weakly evidenced, contradictory, unanchored, or token-invalid EIE is designed to fail closed before Classification and before Governance under the Phase 18.8B repository-contained control-chain checks.

Pre-governance hardening now checks request identity, stage lineage, token validity, semantic token payloads, EIE/SKG/DTN binding, and Root anchorage. Token-chain enforcement covers threshold bundle, PT token hash, required layer tokens, signed token payloads, request fingerprint, token trace continuity, master convergence token, and execution attestation.

External production dependency remains for isolated verifier processes, hardware-backed key custody, real adapter contracts, deployed SKG/DTN services, authoritative source registries, external audit custody, independent timestamping, formal safety/security/legal review, and independent university or third-party validation.

SBP-LEX Dual V6 is presented as a local deterministic control-plane prototype suitable for university technical review, validation discussion, architectural assessment, stress testing, and further hardening feedback.

Production-grade readiness, formal university validation, safety-critical operational approval, and external certification are not claimed.
