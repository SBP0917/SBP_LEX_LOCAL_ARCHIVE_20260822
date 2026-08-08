# Runtime Pass 6 gap register

Baseline: `067bf77cac99b6e6aee6167a4f29eb26369b03be`

Scope: the valid GRC-governed state entering Domain, Domain admissibility,
Aurion constrained pathway resolution, the existing controlled full-retraversal
mechanism, and the state handed to Execution Convergence. This register does
not reopen Passes 1-5 and does not harden Execution Convergence or Execution
Gate.

| ID | Observed condition and baseline reproduction | Repository requirement and affected path | Risk | Bounded correction and verification |
|---|---|---|---|---|
| GAP-DA-001 | Domain issued a token containing only its result and final engine results. Deleting attempts/feedback, altering the reason, or grafting a same-request Domain PASS token and marker remained Aurion-eligible. | The Domain blueprint requires GRC, EIE/request identity, constraints, and token lineage as inputs, with Domain result, feedback, token, denial reason, audit, and replay output. Affected: `sbp_lex/domains/runner.py`, `sbp_lex/security/authority_boundary.py`. | Forged, stale, substituted, or incomplete Domain state could cross the Domain-to-Aurion boundary. | Add exact signed Domain evidence, exact token semantics, GRC/upstream digests, selected candidate/attempt/result/constraint binding, latest hash finalisation, and negative mutation/graft tests. |
| GAP-DA-002 | Aurion requested only Governance and Domain tokens; deleting the GRC token/evidence or changing live GRC/Domain feedback still returned `pass`. | Aurion may run only after valid GRC and exact Domain admissibility. Affected: `sbp_lex/aurion15/runtime/runner.py`, `sbp_lex/security/authority_boundary.py`. | An incomplete prefix or upstream prohibition could be treated as pathway authority. | Add a dedicated Domain-to-Aurion validator requiring the complete Root/PT/Classification/Licensing/Governance/GRC/Domain chain, live state/hash integrity, monotonic constraints, and controlled-reentry continuity. |
| GAP-DA-003 | Domain fallback constraints were applied only to a temporary evaluation state. A second-attempt Domain scope such as `controlled_test:bounded:1` reverted to `controlled_test` in Aurion. | Domain may tighten but Aurion may not discard Domain constraints or broaden Licensing. Affected: `sbp_lex/domains/runner.py`, `sbp_lex/aurion15/candidate/generator.py`. | A pathway could silently escape the narrower condition under which Domain passed it. | Persist the internally selected Domain candidate separately, sign its effective constraint snapshot, and require exact propagation into every Aurion candidate. |
| GAP-DA-004 | Empty constraints/pathways and non-finite autonomy validated; candidates lacked request, EIE, traversal, state, authority, tier, licence, GRC, Domain, and evidence bindings. | Only valid Domain-admissible candidates may participate and every upstream control must remain monotonic. Affected: `sbp_lex/aurion15/runtime/constraint_validator.py`, candidate generator/ranker/runtime. | Forged or malformed candidates could participate, expand authority/scope/autonomy, lower tier, or reverse a prohibition. | Enforce exact candidate/pathway schemas, complete bindings/constraints, non-Boolean bounded integers, monitoring/preservation rules, full-set validation, duplicate rejection, exact equality with the canonical generator output, and permanent negative tests. |
| GAP-DA-005 | Equal-score selection depended on caller order; duplicate IDs were accepted; the selected pathway and ordered admissible set were not signed. | Aurion selection, admissible set, ordering, and result must be deterministic and replayable. Affected: `sbp_lex/aurion15/candidate/ranker.py`, `sbp_lex/aurion15/runtime/runner.py`. | Reordering or same-ID substitution could change a pathway without changing the old semantic token check. | Add a canonical score/ID/digest tie-break, unique ID/digest checks, validate the complete candidate set, and sign ordered-set, rejection, selected-candidate, and pathway digests. |
| GAP-DA-006 | Re-running Domain or Aurion on a completed traversal issued another PASS token and appended another completion entry. | Re-entry is permitted only through the existing materially changed request plus full canonical retraversal; failure history must survive. Affected: both runners and Pass 6 evidence utilities. | Same-state or denial-proof replay could bypass the rejecting stage or erase a prior failure. | Add completion/supersession guards, descendant invalidation, signed prior-denial proof validation, a bounded internal single-use proof registry, immutable prepare-once replay, append-only stage/audit histories, full-retraversal enforcement, and repeat/stale/history-deletion tests. |
| GAP-DA-007 | Standalone legacy Domain/candidate/runtime helpers signed caller-provided data and returned `allowed: True` without canonical lineage. They had no canonical callers. | Desktop V1 exclusive mediation must not expose an apparent alternate route around Domain/Aurion. Affected: `sbp_lex/security/domain_admissibility.py`, `sbp_lex/aurion15/candidate_resolution.py`, `sbp_lex/aurion15/runtime_constraint_engine.py`. | A dormant compatibility helper could be mistaken for runtime permission. | Preserve integrity checking but mark successful records explicitly non-authoritative, never execution-convergence eligible, and always `allowed: False`; prove with negative tests. |
| GAP-DA-008 | Convergence and replay compared only `domain_result` and `aurion15_result`; audit omitted exact Aurion candidate/pathway and Domain/Aurion evidence/token validity. Same-result mutations still matched. | Pass 6 requires exact A/B parity, deterministic replay, audit visibility, and traceability-ready lineage. Affected: `sbp_lex/shared/convergence.py`, `sbp_lex/pipeline/dual_runner.py`, `sbp_lex/pipeline/replay_runner.py`, `sbp_lex/audit/audit_engine.py`. | Material Domain/Aurion divergence or deleted prior audit entries could be silently accepted and later evidence could not prove enforcement. | Add one shared exact Pass 6 summary across parity/replay/audit, signed stage-specific audit-prefix digests, compare live projections against signed evidence, include tokens/histories/candidates/pathway/constraints/handoff, and fail closed on any mismatch. |

## Bounded implementation decisions

- Existing Domain engines, Aurion role, result families, token names, traversal
  order, and authority ownership remain unchanged.
- Signed Domain/Aurion records are evidence for the existing `domain` and
  `aurion` tokens; they are not new tokens, stages, authorities, or decision
  engines.
- The existing GRC-owned materially changed request mechanism remains the only
  governed re-entry route. Pass 6 adds signed prior-denial proof validation,
  bounded process-local single use, same-traversal replay rejection,
  prepare-once deterministic replay, and lineage preservation, not a new loop.
- Domain fallback scope is retained as an internal tighter constraint. It does
  not rewrite the request, Classification, or Licensing state.
- The execution-convergence handoff is a signed validation record consumed at
  the existing boundary. Execution Convergence and Execution Gate internals are
  unchanged.
- Legacy standalone helpers remain import-compatible but explicitly possess no
  runtime or execution authority.

## Closure standard

Each gap closes only when its focused positive and adversarial tests, affected
regressions, full approved Windows suite, runtime, replay, exact A/B parity,
release integrity, 25-year capstone, adversarial harness, `git diff --check`,
and clean-worktree checks pass and the Pass 6 evidence/report artifacts map the
requirement to the implementation, test, runtime proof, and commits.
