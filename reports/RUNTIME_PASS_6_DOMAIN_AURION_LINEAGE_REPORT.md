# Runtime Pass 6 — Domain, Aurion and Controlled Re-entry Lineage Report

Date: 2026-08-08

## Commit lineage

```text
Pass 5 evidence / Pass 6 baseline
067bf77cac99b6e6aee6167a4f29eb26369b03be
    ↓
Pass 6 runtime and focused-test implementation
d9f4a5b2b472035784452f6140e926698d73cfce
    ↓
Pass 6 evidence-only recording commit
the Git commit containing this file; supplied in final handoff
```

Branch: `main`

The evidence-only recording commit contains the three Pass 6 JSON evidence
files and these two reports. Runtime, tests and the gap register are fixed at
the implementation commit above. No commit was pushed.

## Requirement-to-runtime-to-evidence lineage

| Requirement | Runtime module | Function or schema | Permanent focused proof | Durable evidence | Result |
|---|---|---|---|---|---|
| Valid GRC-governed Domain entry | `sbp_lex/security/authority_boundary.py`, `sbp_lex/domains/runner.py` | `validate_governed_domain_handoff`, `run_domain_wrap` | `test_domain_rejects_missing_grc_evidence_or_token`; `test_public_domain_and_aurion_boundaries_deny_noncanonical_state` | Runtime Domain-boundary and negative-matrix records | CLOSED |
| Domain rule identity and order | `sbp_lex/domains/runner.py` | `_domain_engine_configuration_failures`, `_evaluate_domains` | `test_missing_or_duplicate_domain_rules_fail_closed`; `test_same_name_domain_implementation_substitution_fails_closed` | Gap `GAP-DA-001`; Domain failure evidence | CLOSED |
| Deterministic Domain outcome | `sbp_lex/domains/runner.py` | `build_domain_fallback_candidate`, `_evaluate_domains`, `run_domain_wrap` | `test_empty_domain_rule_set_never_produces_permission`; `test_malformed_or_exceptional_domain_rules_fail_closed` | Signed Domain result/reason/attempt/result digests | CLOSED |
| Tightened Domain scope survives | `sbp_lex/domains/runner.py`, `sbp_lex/security/domain_aurion_evidence.py` | `_state_for_domain_candidate`, `constraint_snapshot`, `domain_effective_scope` | `test_domain_fallback_preserves_original_and_binds_effective_scope` | Domain candidate and constraint snapshot | CLOSED |
| Exact Domain evidence/token | `sbp_lex/security/domain_aurion_evidence.py` | `build_stage_evidence`, `validate_stage_evidence`, `stage_token_payload`; `desktop-v1.domain-aurion-stage-evidence.v1` | `test_valid_domain_aurion_evidence_tokens_and_handoff_are_exactly_bound`; `test_deleted_domain_feedback_cannot_enter_aurion` | Runtime stage lineage | CLOSED |
| Append-only Domain history | `sbp_lex/security/domain_aurion_evidence.py` | `append_stage_history`, `validate_stage_history` | `test_prior_audit_lineage_deletion_cannot_cross_pass6_boundaries` | Domain history/digest/validation | CLOSED |
| Domain-to-Aurion exclusivity | `sbp_lex/security/authority_boundary.py`, `sbp_lex/aurion15/runtime/runner.py` | `validate_domain_handoff_to_aurion`, `run_aurion_runtime` | `test_aurion_rejects_missing_domain_evidence_or_token`; `test_deleted_domain_feedback_cannot_enter_aurion` | Aurion entry-boundary matrix | CLOSED |
| Canonical candidate set | `sbp_lex/aurion15/candidate/generator.py`, `sbp_lex/aurion15/runtime/runner.py` | `generate_candidates`, `CANONICAL_CANDIDATE_GENERATOR`, `_candidate_set_failures` | `test_empty_malformed_or_duplicate_candidate_sets_fail_closed`; `test_schema_valid_forged_candidate_set_cannot_replace_canonical_output` | Generated/admissible/rejected set digests | CLOSED |
| Exact candidate constraints | `sbp_lex/aurion15/runtime/constraint_validator.py` | `validate_candidate_constraints`; `desktop-v1.aurion-candidate.v1` | `test_candidate_binding_scope_tier_autonomy_and_authority_mutations_reject`; `test_cross_request_candidate_is_rejected` | Candidate validation and binding records | CLOSED |
| Bounded numeric state | `sbp_lex/aurion15/runtime/constraint_validator.py` | `validate_candidate_constraints` | `test_nonfinite_and_boolean_candidate_values_fail_closed` | Negative candidate matrix | CLOSED |
| Deterministic ranking | `sbp_lex/aurion15/candidate/ranker.py`, `sbp_lex/aurion15/runtime/runner.py` | `candidate_rank_score`, `rank_candidates`, `_expected_ranked_candidates` | `test_ranker_cannot_mutate_validated_candidate_content`; `test_same_id_pathway_mutation_is_rejected_by_direct_execution_gate` | Ordered-set and selected-pathway digests | CLOSED |
| Validator output integrity | `sbp_lex/aurion15/runtime/runner.py` | `_validate_candidate_fail_closed` | `test_malformed_candidate_validator_record_fails_closed` | Candidate validation failure records | CLOSED |
| Aurion cannot manufacture permission | `sbp_lex/aurion15/runtime/runner.py`, `sbp_lex/security/domain_aurion_evidence.py` | `run_aurion_runtime`, `neutralize_denied_execution_state` | `test_failed_domain_and_aurion_outputs_neutralize_forged_authority`; `test_pre_gate_execution_authority_substitution_is_rejected` | Fail-closed runtime and handoff evidence | CLOSED |
| Governance DENY and Domain failure supremacy | `sbp_lex/security/authority_boundary.py`, Domain/Aurion runners | `_pre_execution_authority_failures`, all three Pass 6 boundary validators | `test_pre_gate_execution_authority_substitution_is_rejected`; `test_direct_gate_rejects_forged_pre_execution_control_state` | Adversarial closure matrix | CLOSED |
| Controlled re-entry eligibility | `sbp_lex/security/authority_boundary.py`, `sbp_lex/security/domain_aurion_evidence.py` | `_validate_controlled_reentry`, `controlled_denial_proof_details` | `test_controlled_reentry_requires_signed_prior_denial_lineage` | Re-entry proof and denial-origin records | CLOSED |
| Single-use bounded denial proof | `sbp_lex/security/domain_aurion_evidence.py` | `_ControlledReentryReplayRegistry`, `apply_controlled_reentry_proof_use_guard`; `desktop-v1.controlled-reentry-proof-use.v1` | `test_controlled_reentry_requires_signed_prior_denial_lineage` | Capacity 4,096; accepted/replayed results | CLOSED |
| Immutable full-retraversal replay | `sbp_lex/pipeline/runner.py`, `sbp_lex/pipeline/dual_runner.py`, `sbp_lex/pipeline/replay_runner.py` | `PreparedPipelineBoundary`, `prepare_pipeline_boundary`, `_run_dual_prepared_pipeline`, `run_replay_check` | `test_fresh_reentry_replay_clones_one_consumed_prepared_boundary`; `test_repeated_domain_and_aurion_entry_cannot_reuse_prior_permission` | Re-entry and replay evidence | CLOSED |
| Denial/audit history preservation | `sbp_lex/security/domain_aurion_evidence.py`, `sbp_lex/audit/audit_engine.py` | `audit_lineage_projection`, `append_stage_history`, `run_audit`; `desktop-v1.pass6-domain-aurion-lineage.v1` | `test_prior_audit_lineage_deletion_cannot_cross_pass6_boundaries`; `test_malformed_audit_trace_is_a_controlled_pass6_denial` | Signed audit-prefix and stage history | CLOSED |
| State/token/hash continuity | `sbp_lex/security/domain_aurion_evidence.py`, `sbp_lex/shared/hash_chain.py` | `live_state_hash_valid`, `hash_chain_valid`, `append_stage_finalisation`, `validate_stage_evidence` | `test_pass6_handoff_requires_exact_stage_order_and_hash_chain_tail`; valid binding test | Runtime chain and finalisation lineage | CLOSED |
| No hidden permission fields | `sbp_lex/security/authority_boundary.py`, `sbp_lex/security/domain_aurion_evidence.py` | `_nested_permission_field_paths`, `_pre_execution_authority_failures`, `neutralize_denied_execution_state` | `test_handoff_rejects_unknown_signed_token_and_permission_fields`; `test_handoff_rejects_premature_terminal_control_fields` | Negative handoff matrix | CLOSED |
| Valid Execution Convergence handoff | `sbp_lex/security/domain_aurion_evidence.py`, `sbp_lex/security/authority_boundary.py` | `build_execution_convergence_handoff`, `validate_handoff_evidence`, `validate_execution_convergence_handoff`; `desktop-v1.execution-convergence-handoff.v1` | `test_valid_domain_aurion_evidence_tokens_and_handoff_are_exactly_bound`; handoff-order tests | Valid signed digest `c2428319e1637b10438d9bb85ed9112befe4d4243c613ae6694b1b5cc46029c4` | CLOSED |
| Legacy helpers have no authority | `sbp_lex/security/domain_admissibility.py`, `sbp_lex/aurion15/candidate_resolution.py`, `sbp_lex/aurion15/runtime_constraint_engine.py` | `evaluate_domain`, `evaluate_candidate`, `evaluate_runtime_constraint` | `test_standalone_legacy_domain_helper_is_integrity_only`; `test_standalone_legacy_aurion_helpers_are_integrity_only` | `allowed=false`, `execution_convergence_eligible=false` | CLOSED |
| Exact A/B parity | `sbp_lex/shared/convergence.py`, `sbp_lex/pipeline/dual_runner.py` | `DOMAIN_AURION_PARITY_FIELDS`, `domain_aurion_summary`, `_domain_aurion_parity_from_proof`, `verify_convergence_proof` | `test_convergence_detects_same_result_domain_aurion_pathway_mutation` | 39/39 exact; near-match false | CLOSED |
| Exact replay | `sbp_lex/pipeline/replay_runner.py` | `REPLAY_COMPARISON_FIELDS`, `build_replay_summary`, `verify_replay_result` | `test_replay_projection_detects_same_result_aurion_pathway_mutation`; immutable re-entry replay test | Runtime replay PASS | CLOSED |

## Gap-to-file-to-test closure matrix

| Gap | Principal implementation | Principal proof | Durable closure evidence |
|---|---|---|---|
| `GAP-DA-001` | `domains/runner.py`, `security/domain_aurion_evidence.py`, `security/authority_boundary.py` | exact evidence/token, missing/malformed/substituted Domain rule and deleted feedback tests | Signed Domain projection, token, attempts/results/candidate/history digests |
| `GAP-DA-002` | `security/authority_boundary.py`, `aurion15/runtime/runner.py` | incomplete prefix, missing Domain evidence/token, noncanonical boundary tests | Complete Domain-to-Aurion validation record |
| `GAP-DA-003` | `domains/runner.py`, `aurion15/candidate/generator.py` | fallback effective-scope preservation test | Signed effective Domain scope in every Aurion candidate |
| `GAP-DA-004` | `aurion15/runtime/constraint_validator.py`, candidate generator/runtime | malformed, forged, cross-request and monotonic-mutation matrices | Candidate binding/constraint validation digests |
| `GAP-DA-005` | `aurion15/candidate/ranker.py`, `aurion15/runtime/runner.py` | ranker mutation, duplicate set and same-ID pathway substitution tests | Ordered-set, rejection, selected candidate/pathway digests |
| `GAP-DA-006` | `security/domain_aurion_evidence.py`, `pipeline/runner.py`, `pipeline/replay_runner.py` | repeated-stage, signed-denial and immutable prepared-boundary tests | Single-use proof result and full-retraversal replay lineage |
| `GAP-DA-007` | three legacy helper modules | standalone Domain/Aurion integrity-only tests | Explicit non-authoritative result fields |
| `GAP-DA-008` | `shared/convergence.py`, dual/replay runners, `audit/audit_engine.py` | same-result convergence/replay mutation and audit-deletion tests | Exact 39-field parity, replay and signed audit lineage |

GAPS IDENTIFIED: 8

GAPS CLOSED: 8

GAPS REMAINING: 0

## Exact 39-field Domain/Aurion parity contract

The same canonical list is used by convergence and replay. All 39 fields
matched exactly, and near-match reconciliation was not used:

1. `domain_result`
2. `domain_reason`
3. `domain_state_digest`
4. `domain_live_state_digest`
5. `domain_evidence_valid`
6. `domain_evidence_failures_digest`
7. `domain_evidence_digest`
8. `domain_token_digest`
9. `domain_history_digest`
10. `domain_history_valid`
11. `domain_history_failures_digest`
12. `domain_attempt_count`
13. `domain_max_attempts`
14. `domain_attempts_digest`
15. `domain_results_digest`
16. `domain_candidate_digest`
17. `aurion15_result`
18. `aurion_reason`
19. `aurion_state_digest`
20. `aurion_live_state_digest`
21. `aurion_evidence_valid`
22. `aurion_evidence_failures_digest`
23. `aurion_evidence_digest`
24. `aurion_token_digest`
25. `aurion_history_digest`
26. `aurion_history_valid`
27. `aurion_history_failures_digest`
28. `candidate_attempt_count`
29. `generated_candidate_set_digest`
30. `candidate_validations_digest`
31. `admissible_candidate_set_digest`
32. `ordered_candidate_set_digest`
33. `rejected_candidates_digest`
34. `selected_candidate_digest`
35. `selected_pathway_digest`
36. `domain_aurion_constraint_digest`
37. `execution_convergence_handoff_digest`
38. `execution_convergence_handoff_valid`
39. `execution_convergence_handoff_failures_digest`

## Signed schema and state lineage

| Record | Canonical schema/function | Bound lineage | Validation result |
|---|---|---|---|
| Domain evidence | `desktop-v1.domain-aurion-stage-evidence.v1`; `build_stage_evidence` | Request, EIE, collective signal, traversal, entry/before-token state hash, chain head, tier, authority, upstream tokens/evidence, exact stage projection | PASS |
| Aurion evidence | `desktop-v1.domain-aurion-stage-evidence.v1`; `build_stage_evidence` | Domain prefix plus complete generated/validated/admissible/ordered/rejected candidate sets and selected candidate/pathway | PASS |
| Domain/Aurion histories | `append_stage_history`, `validate_stage_history` | Request/EIE/traversal, result/reason/failures, prior record and audit-prefix digests | PASS |
| Controlled proof use | `desktop-v1.controlled-reentry-proof-use.v1`; `apply_controlled_reentry_proof_use_guard` | Signed prior denial, denied request, changed request and first-use result | PASS |
| Execution Convergence handoff | `desktop-v1.execution-convergence-handoff.v1`; `build_execution_convergence_handoff` | Exact stage prefix, Aurion finalisation tail, Domain/Aurion evidence/tokens, candidate/pathway/set, constraints, re-entry and histories | PASS; digest `c2428319e1637b10438d9bb85ed9112befe4d4243c613ae6694b1b5cc46029c4` |
| Audit lineage | `desktop-v1.pass6-domain-aurion-lineage.v1`; `run_audit` | Both stages, evidence/tokens, histories, feedback, candidate/pathway, constraints and handoff | PASS |

## Controlled re-entry lineage

```text
canonical denied outcome and controlled-outcome hash
    ↓ signed prior-denial proof
materially changed request with preserved denial/failure history
    ↓ first-use process-local proof registration
one sealed PreparedPipelineBoundary
    ↓ immutable clones
complete canonical A/B or replay retraversal
    ↓
new Domain → Aurion finalisations → valid signed handoff
```

The first distinct live use is accepted. Reuse is reported as replayed and
denied; stale/substituted proofs and deleted histories are rejected. The
registry is private, lock protected, bounded to 4,096 proof digests and cannot
be overridden through public pipeline APIs. Deterministic replay clones the one
already prepared boundary rather than consuming the denial proof again.

## Verification lineage

| Gate | Result |
|---|---|
| Compile | PASS |
| Focused Pass 6 and Phase 15.5b | 68 passed in 72.02s |
| Directly affected regressions | 296 passed in 289.24s |
| Full approved Windows suite | 2,060 passed, 7 skipped in 2,436.60s |
| Runtime | PASS |
| Replay | PASS; deterministic |
| A/B parity | EXACT 39/39; near-match false |
| Domain bypass protection | PASS |
| Aurion bypass protection | PASS |
| Denial and Domain-failure supremacy | PASS |
| Exclusive mediation | PASS within Desktop V1 scope |
| Controlled re-entry | PASS |
| Monotonic tier/autonomy/authority/scope | PASS |
| State/token/hash continuity | PASS |
| Execution Convergence handoff | PASS |
| Release integrity | `RELEASE_INTEGRITY_PASS` |
| 25-year capstone | `LOCAL_TRUST_CAPSTONE_PASS` |
| Adversarial harness | `ADVERSARIAL_NEGATIVE_HARNESS_PASS` |

The authoritative suite used the existing Python 3.12.13 validation
environment. A separate CPython 3.14 captured-output attempt produced Windows
`WinError 6`; it was an environment-only diagnostic, not an implementation
failure.

## Durable artifact lineage

- `outputs/runtime/domain_aurion_runtime_evidence.json`
- `outputs/runtime/domain_aurion_parity_evidence.json`
- `outputs/runtime/domain_aurion_reentry_evidence.json`
- `reports/RUNTIME_PASS_6_DOMAIN_AURION_HARDENING_REPORT.md`
- `reports/RUNTIME_PASS_6_DOMAIN_AURION_LINEAGE_REPORT.md`

All five files belong only to the evidence/lineage commit identified as
`the Git commit containing this file; supplied in final handoff`. They record
measurements from implementation commit
`d9f4a5b2b472035784452f6140e926698d73cfce`. The JSON evidence contains no
signing seed, private key, credential, signature blob or external-provider
secret.

## Boundary and unresolved findings

UNRESOLVED DOMAIN GAPS: 0

UNRESOLVED AURION GAPS: 0

UNRESOLVED RE-ENTRY GAPS: 0

EXECUTION CONVERGENCE MODIFIED OR HARDENED: NO

EXECUTION GATE MODIFIED OR HARDENED: NO

PASS 7 DEFERRAL: Execution Convergence and Execution Gate hardening

READY FOR PASS 7: YES

Pass 6 ends at the validated input to Execution Convergence. No claim in this
report extends authority into Execution Convergence, Execution Gate or an
external effect boundary.
