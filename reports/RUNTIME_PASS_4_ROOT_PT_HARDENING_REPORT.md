# Runtime Pass 4 — Root of Trust and Procedural Truth Hardening Report

Date: 2026-08-07

## Status

PASS 4 STATUS: PASS / CLOSED

UNRESOLVED ROOT OF TRUST GAPS: 0

UNRESOLVED PROCEDURAL TRUTH GAPS: 0

REMAINING OWNER DECISIONS: 0

READY FOR PASS 5: YES

## Repository record

| Item | Exact result |
|---|---|
| Starting commit | `7cf107245ec561e927bfa178f35a7d49a4da129b` |
| Tested implementation commit | `e53bf8f560b3ad62a7d4a9104ba53153860e3729` |
| Evidence/lineage commit | The commit containing this report; its exact hash is emitted in the final handoff because a committed file cannot contain its own commit hash. |
| Branch | `main` |
| Starting worktree | Clean |
| Final worktree | Clean after the evidence/lineage commit and final Git checks |
| Implementation diff | 32 files; 6,682 insertions; 597 deletions |

No STOP condition was encountered. Work remained inside Root of Trust,
Procedural Truth, evidence sufficiency, tier/corroboration conditioning, and
the immediate downstream invariants needed to prove that Root/PT failure
cannot be bypassed.

## Engineering outcome

### Root of Trust

The runtime now enforces the exact chain:

```text
anchor_validation
→ attestation
→ attestation_consensus
→ truth_anchor
→ truth_continuity
→ truth_expiry
→ truth_revocation
→ procedural_truth foundation
```

| Required outcome | Result | Deterministic proof |
|---|---|---|
| Root chain completeness | PASS. Seven stages execute once, in order, and produce a signed aggregate record. | `test_valid_root_chain_is_exact_complete_and_signed` |
| Root failure isolation | PASS. The first failing stage stops traversal before PT; PT/downstream eligibility and tokens are cleared. | 14 parametrised `test_each_root_failure_isolated_before_pt` cases |
| Request/EIE/state binding | PASS. Root validates request fingerprint, EIE digest, current Root-entry state hash, collective package and attachment bindings. | `test_root_input_mutation_fails_closed`; `test_wrong_request_and_eie_bindings_fail_root`; `test_post_root_state_hash_mutation_cannot_enter_pt` |
| Authority legitimacy | PASS. Authority, jurisdiction and admitted SKG validation basis are exact and request-bound. | invalid/substituted/unresolved authority cases |
| Authority expiry/revocation | PASS. Expired, future-issued and revoked authority fail at the responsible stage. | expiry/future/revocation Root cases |
| Attestation validity and consensus | PASS. Identity, subject, signature, bindings, freshness, expiry, revocation and exact consensus are validated; no scoring or tolerance is used. | malformed/substituted/expired/revoked/inconsistent attestation cases |
| Truth-anchor integrity | PASS. The anchor is constructed only after prerequisite Root stages and is signed and bound. | `test_truth_anchor_and_continuity_tamper_are_detected` |
| Truth continuity | PASS. Predecessor, authority, attestation, request/EIE, collective and state references must match. | continuity-break and hash-chain tamper cases |
| Cross-request reuse/mutation | PASS. Root evidence, anchor and authority-token grafting or mutation are rejected. | `test_cross_request_root_reuse_and_root_token_mutation_fail` |
| Root audit/replay evidence | PASS. Result, reason, stage vector, bindings, digest and bounded hash/audit lineage are recorded. | `test_root_pt_hash_chain_and_audit_lineage_are_complete`; failed-Root replay test |

### Procedural Truth, evidence, tier and tokens

There remains one authoritative PT path. A single deterministic source
assessment feeds evidence validation, corroboration, sufficiency, threshold
conditioning and final certification.

| Required outcome | Result | Deterministic proof |
|---|---|---|
| PT source verification | PASS. Unverified evidence does not qualify. | invalid evidence-dimension matrix |
| PT attestation | PASS. Unattested evidence does not qualify. | invalid evidence-dimension matrix |
| PT freshness | PASS. Stale evidence does not qualify. | invalid evidence-dimension matrix |
| PT provenance | PASS. Invalid provenance does not qualify; stable provenance identities drive deduplication. | provenance and alias cases |
| PT consistency | PASS. Inconsistent evidence does not qualify. | invalid evidence-dimension matrix |
| Independence/relevance/binding | PASS. Non-independent, irrelevant, request-, EIE-, collective- or action-mismatched sources do not qualify. | independence/relevance and four explicit binding cases |
| Evidentiary sufficiency | PASS. Count alone cannot certify PT; relevance, provenance, temporal validity, consistency and completeness are distinct and digested. | `test_count_sufficient_but_incomplete_evidence_is_not_certified` |
| LOW two-source rule | PASS with 2; `PT_REFINE` with 1. | locked corroboration matrix |
| MEDIUM three-source rule | PASS with 3; `PT_REFINE` with 2. | locked corroboration matrix |
| TOP five-source rule | PASS with 5; `PT_ESCALATE` with 4. | locked corroboration matrix |
| Duplicate-source rejection | PASS. Five duplicate/aliased TOP entries produce one qualifying identity and cannot satisfy TOP. | `test_duplicate_and_alias_sources_cannot_inflate_top` |
| Financial input/bands | PASS. Strict finite non-negative input; locked AUD bands remain `499.99→LOW`, `500→MEDIUM`, `49,999.99→MEDIUM`, `50,000→TOP`; maximum factor wins. | financial/factor tests |
| Dynamic escalation | PASS. LOW→MEDIUM, LOW→TOP and MEDIUM→TOP are deterministic and monotonic. | `test_dynamic_tier_escalation` |
| No tier downgrade | PASS. Attempted MEDIUM→LOW, TOP→MEDIUM and TOP→LOW retain the high-water tier and record a deterministic failure. | `test_tier_downgrade_attempt_is_preserved_and_rejected` |
| PT evidence and token binding | PASS. Signed PT evidence precedes token issuance; PT and threshold tokens exist only after certified PASS and bind the full Pass 4 state. | `test_pt_token_has_complete_pass4_bindings_and_failure_has_no_token`; tamper tests |
| Failed PT token cleanup | PASS. Failed or merely count-sufficient/incomplete PT emits no PT or threshold-bundle token. | incomplete evidence and failure-path tests |
| Cross-state PT grafting | PASS. PT evidence/tokens from another same-request Root state cannot be reused. | `test_pt_evidence_and_tokens_cannot_be_grafted_across_rooted_states` |

The normal evidence snapshot is MEDIUM with 3/3 unique qualifying sources,
all source dimensions valid, evidentiary sufficiency `SUFFICIENT`, PT `PASS`,
and reason `procedural_truth_certified`.

### Immediate downstream invariants

These changes do not transfer or redesign downstream authority. They enforce
only the Root/PT eligibility invariant at existing entry points.

| Boundary | Result |
|---|---|
| Classification | PASS — Root failure, PT FAIL or PT ESCALATE cannot become Classification `ALLOW`. |
| Licensing | PASS — a valid licence/classification cannot restore PT-invalid eligibility. |
| Governance | PASS — Governance `ALLOW` is ineffective when Root/PT or corroboration is invalid. |
| GRC | PASS — GRC may structure control/re-entry but cannot transform PT failure into execution permission. |
| Domain | PASS — Domain pass cannot restore Root/PT-invalid state. |
| Aurion | PASS — candidate/pathway resolution cannot restore Root/PT-invalid state. |
| Execution Gate | PASS — rejects PT failure, insufficient corroboration, tier inconsistency, missing/tampered tokens, and request/EIE/state-hash mismatch. |
| Persistent inoperability | PASS — failed Root/PT requires corrected evidence and full canonical retraversal. |

Proof is provided by the six-runner downstream matrix,
`test_genuine_pt_escalation_cannot_reach_classification_allow`,
`test_execution_gate_rejects_pt_corroboration_tier_and_token_invariants`, and
`test_pt_failure_remains_inoperable_and_requires_full_retraversal`.

### Dual-pipeline and replay determinism

- Pipeline A/B Root basis and aggregate Root digests are identical.
- Pipeline A/B PT evidence sets, source count, sufficiency, tier,
  corroboration and PT digests are identical.
- Exact Root parity: true.
- Exact PT parity: true.
- Tier parity: true.
- Corroboration parity: true.
- Initial parity: true.
- Convergence matched: true.
- Near-match reconciliation used: false.
- Successful replay: two runs matched, zero mismatches.
- Focused tests also prove three-run successful replay and exact failed Root/PT
  replay.
- Injected Root/PT convergence mismatch fails closed with `ESCALATE / HALT`.

## Changed files

Root and collective boundary:

- `sbp_lex/collective/context_interface.py`
- `sbp_lex/authority_first/anchor_validation_engine.py`
- `sbp_lex/authority_first/attestation_engine.py`
- `sbp_lex/authority_first/attestation_consensus_engine.py`
- `sbp_lex/authority_first/truth_anchor_engine.py`
- `sbp_lex/authority_first/truth_continuity_engine.py`
- `sbp_lex/authority_first/truth_expiry_engine.py`
- `sbp_lex/authority_first/truth_revocation_engine.py`
- `sbp_lex/authority_first/root_of_trust_runner.py`
- `sbp_lex/shared/control_chain_validation.py`

PT, evidence and threshold conditioning:

- `sbp_lex/api/schema_validation.py`
- `sbp_lex/config/thresholds.py`
- `sbp_lex/governance/procedural_truth_envelope.py`
- `sbp_lex/governance/evidence_engine.py`
- `sbp_lex/governance/corroboration_engine.py`
- `sbp_lex/governance/threshold_conditioning_engine.py`
- `sbp_lex/governance/procedural_truth_engine.py`
- `sbp_lex/governance/procedural_truth_runner.py`
- `sbp_lex/governance/grc.py`
- `sbp_lex/security/threshold_tokens.py`
- `sbp_lex/security/authority_boundary.py`

Parity, replay and audit:

- `sbp_lex/pipeline/dual_runner.py`
- `sbp_lex/pipeline/replay_runner.py`
- `sbp_lex/shared/convergence.py`
- `sbp_lex/audit/audit_engine.py`

Tests and runtime documentation/evidence:

- `tests/test_runtime_pass4_root_pt_hardening.py`
- `tests/test_eie_pt_sufficiency_rebuild.py`
- `tests/test_phase_15_5a_alignment.py`
- `tests/test_phase_18_8b_repository_hardening.py`
- `tests/test_runtime_pass3_eie_state_boundary.py`
- `docs/runtime/ROOT_OF_TRUST_PROCEDURAL_TRUTH_RUNTIME_SPECIFICATION.md`
- `docs/runtime/ROOT_PT_PASS4_GAP_CLOSURE_REGISTER.md`
- `outputs/runtime/root_pt_runtime_evidence.json`
- `outputs/runtime/root_pt_parity_evidence.json`
- `reports/RUNTIME_PASS_4_ROOT_PT_HARDENING_REPORT.md`
- `reports/RUNTIME_PASS_4_ROOT_PT_LINEAGE_REPORT.md`

## Functions and schemas changed

Principal functions hardened or added include `attach_collective_signals`,
`validate_collective_signal_package`, all seven `run_*` Root subengines,
`run_root_of_trust`, `_root_context`, `_root_record`, `_fail_root`,
`validate_root_input_bindings`, `validate_root_of_trust_evidence`,
`assess_source_records`, `source_is_qualified`, `build_pt_evidence_envelope`,
`validate_pt_evidence_envelope`, `run_evidence_validation`,
`run_corroboration_validation`, `apply_thresholds`,
`run_threshold_conditioning`, `finalize_procedural_truth`,
`validate_procedural_truth_evidence`, `validate_root_pt_eligibility`,
`verify_threshold_bundle`, `run_grc`, `run_dual_pipeline`,
`build_pipeline_convergence_proof`, `verify_convergence_proof`,
`build_replay_summary`, and `run_audit`.

Schemas introduced or hardened:

- `desktop-v1.root-trust-material.v1`
- `desktop-v1.collective-attachment-attestation.v1`
- `desktop-v1.collective-attachment.v1`
- `desktop-v1.root-context.v1`
- `desktop-v1.root-evidence-payload.v1`
- `desktop-v1.root-evidence.v1`
- `desktop-v1.truth-anchor.v1`
- `desktop-v1.pt-evidence-envelope.v2`
- `desktop-v1.pt-source-assessment.v1`
- `desktop-v1.pt-source-binding.v1`
- `desktop-v1.pt-qualification-basis.v1`
- `desktop-v1.evidentiary-sufficiency.v1`
- `desktop-v1.procedural-truth-evidence.v1`
- `desktop-v1.threshold-conditioning.v1`
- `desktop-v1.pipeline-initial-parity.v1`

## Tests added and adjusted

The new focused suite contains 77 passing cases:

- Root: 29
- PT/tier/token: 34
- downstream/replay/parity: 14

Four legacy suites were minimally aligned with the now-strict canonical Root/PT
path and unique-source semantics. No existing downstream authority was changed.

## Verification results

| Verification | Exact result |
|---|---|
| `python -m compileall -q .` | PASS, exit 0. Historical inaccessible pytest cache/temp paths emitted non-fatal `Can't list` notices. |
| Focused Pass 4 suite | PASS — 77 passed in 21.02s. |
| Directly affected regression batch | PASS — 167 passed in 101.07s. |
| Full approved Windows wrapper | PASS — 1,951 passed, 7 skipped in 2,126.93s (35:26); wrapper exit 0 and `[PASS] Requested test run passed.` |
| Normal runtime | PASS — `ALLOW / EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, no token failures, measured startup approved. |
| Replay | PASS — 2 runs matched; zero mismatches; Root/PT fields included. |
| Deterministic parity | PASS — initial, Root, PT, tier and corroboration parity exact; convergence matched; near-match false. |
| Current-state trust/integrity | PASS — `RELEASE_INTEGRITY_PASS`, `LOCAL_TRUST_CAPSTONE_PASS`, `ADVERSARIAL_NEGATIVE_HARNESS_PASS`; all exit 0 under the repository-approved test-local trust bootstrap. |
| `git diff --check` | PASS. |
| Final Git metadata | `main`; exact evidence/lineage commit in final handoff; worktree clean. |

The default persisted Phase 18.7 bundle is a historical generated artifact
anchored to `f5ba5b2b7da8fbc63f1ddac1a3bce2cb1112ea5b`. A direct diagnostic correctly
reported it stale after subsequent source commits. It was not rewritten in this
bounded runtime pass. The authoritative current-state validation used the same
ephemeral local trust-root bootstrap as the full approved suite and normal
runtime; no external service or credential was used.

## Explicit scope declarations

ARCHITECTURE CHANGED: NO

CANON CHANGED: NO

RUNTIME AUTHORITY OWNERSHIP CHANGED: NO

TRAVERSAL ORDER CHANGED: NO

SKG/DTN REMAIN EXTERNAL: YES

LIVE LINKAGE INTRODUCED: NO

CLOUD/NODES/MESH/QUORUM/DISTRIBUTED RUNTIME INTRODUCED: NO

NEAR-MATCH RECONCILIATION INTRODUCED: NO

## Pass 5 handoff boundary

Work stops at the certified PT state entering Classification. That state is
Hard Entry-admitted, canonically constructed, collective-signal attached,
Root-anchored, authority-legitimate, attestation-valid, truth-continuous,
non-expired, non-revoked, evidence/source/corroboration-qualified,
tier-computed, no-downgrade protected, PT-certified, request/EIE/state-bound,
and deterministic across both pipelines.

Classification is the next owner. No Pass 5 Classification, Licensing,
Governance or GRC hardening was begun.
