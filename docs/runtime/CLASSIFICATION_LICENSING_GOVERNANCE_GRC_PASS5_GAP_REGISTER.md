# Runtime Pass 5 gap register

Baseline: `2e02b18c7e25f4160f3d2cf3645e3f6cc18fe4e9`

Scope: the certified Procedural Truth handoff through Classification, Licensing,
Governance, GRC, and the governed-state admission check at Domain ingress. This
register does not reopen Pass 4 and does not harden Domain reasoning, Aurion, or
Execution.

| ID | Observed defect | Reproduction at baseline | Required closure |
|---|---|---|---|
| GAP-CLG-001 | Classification authority did not bind its complete result, reason, state, scope, environment, restrictions, upstream evidence, or hash lineage. | Mutating `classification.operational_scope` after Classification was accepted by Licensing. | Signed, request/state/upstream-bound Classification evidence; exact token semantics; complete hash/audit/replay/parity projection. |
| GAP-CLG-002 | Classification accepted malformed autonomy values and a request-declared ceiling above the locked class-profile ceiling. | A `CLASS_1` declaration could set level/ceiling to `50/100`; very large integers could overflow conversion. | Non-Boolean `0..100` integer contract; effective ceiling cannot exceed the class profile; controlled failure only. |
| GAP-CLG-003 | Licensing silently treated a missing licence as `DECLARED_VALID`, ignored supported spelling aliases/structured declarations, and did not bind the scope/assessment it licensed. | Removing every licence field still returned `ALLOW`; post-Classification and post-Licensing scope substitution remained eligible. | Explicit, non-conflicting licence normalization; conservative scope continuity; signed complete Licensing evidence and token. |
| GAP-CLG-004 | Re-entering a completed governed stage could retain stale ALLOW authority and descendant results/tokens. | Re-running a stage as DENY left its earlier ALLOW token and later-stage authority present. | One traversal per stage/state; invalidate current and descendant eligibility before reevaluation; DENY/ESCALATE leaves no eligibility token. |
| GAP-CLG-005 | Governance had no signed complete outcome/history record and mutable top-level fields could be presented to GRC. | A forged `governance_result=ALLOW` with deleted denial history could be consumed without immutable Governance evidence. | Signed Governance evidence, append-only in-state history binding, exact token semantics for ALLOW, denial/escalation supremacy. |
| GAP-CLG-006 | GRC validated Root/PT only and could PASS without valid Classification, Licensing, or Governance authority. | Deleting the Governance token and calling GRC directly returned `PASS` and issued a GRC token. | GRC must validate every upstream stage/evidence/token required by the actual Governance outcome; normalize invalid handoffs to DENY; bind governed re-entry/history. |
| GAP-CLG-007 | Domain ingress required Governance but not a valid PASS GRC token/evidence state. | Setting `grc_result=DENY`, deleting the GRC token, and invoking Domain directly returned `pass` and issued a Domain token. | Domain admission must require exact Governance ALLOW plus GRC PASS, both signed and state-bound, before any Domain attempt. |
| GAP-CLG-008 | A/B convergence, replay, and audit preserved only partial Pass 5 state. | Classification/Licensing reasons and state, GRC result/re-entry, evidence digests, and governed token digests were absent from comparison/audit projections. | Exact shared Pass 5 parity fields and complete audit/replay lineage; near-match reconciliation remains prohibited. |

## Bounded implementation decisions

- Existing engines, result families, token types, traversal order, and authority
  ownership remain unchanged.
- One shared evidence utility standardises signatures and lineage; it is not a
  new decision engine, authority source, token, or stage.
- Existing `governance_feedback` carries Governance history and GRC response
  evidence; no competing feedback mechanism is introduced.
- Licence validity remains limited to the already-implemented accepted states.
  Unsupported or conflicting declaration shapes fail closed; no external licence
  regime, issuer, expiry, or regulatory rule is invented.
- Licensing cannot infer a scope hierarchy. A requested scope must therefore
  equal the classified operational scope; explicit permitted sets may only
  confirm, not broaden, that scope.
- The Domain change is an ingress validation only. Domain candidates, reasoning,
  fallback behavior, and result semantics remain untouched.

## Closure standard

Each gap is closed only when focused negative tests, affected regressions, the
full Windows suite, replay, A/B parity, release integrity, the 25-year capstone,
and the adversarial harness all pass and the evidence/report artifacts identify
the exact implementation and evidence commits.
