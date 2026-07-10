# Phase 19E Cognitive Pipelines Experimental Scope Lock

Task: PHASE19E-A-COGNITIVE-PIPELINES-EXPERIMENTAL-SCOPE-LOCK-01

Classification:

- CODEX_REPO_WORK
- EXPERIMENTAL_BRANCH
- HUMAN_REVIEW
- NOT CANON
- NOT MAINLINE
- NOT FINAL PILOT PACKAGE

Branch: `phase19e-cognitive-pipelines-experimental`

Base commit: `f79c4bf609c63b0856379925342a03095edca203`

## Purpose

This document locks the safe experimental scope for future cognitive-pipeline
work before any implementation begins.

It does not implement cognitive pipelines, promote canon, modify runtime code,
modify tests, change Desktop V1 traversal, create a pilot package, or construct
the missing SKG/DTN blueprint set.

## Controlling Inputs

The scope lock is informed by:

- `docs/phase19e/SKG_DTN_BLUEPRINT_SOURCE_LINEAGE_CAPTURE.md`
- `reports/PHASE19E_A0_SKG_DTN_BLUEPRINT_SOURCE_LINEAGE_CAPTURE_01_REPORT.md`
- `external_substrates/README.md`
- `external_substrates/EXTERNAL_SUBSTRATE_LOCK.md`
- `external_substrates/BRIDGE_CONTRACT_LOCK.md`
- `docs/EXTERNAL_SKG_DTN_CONSTRUCTION_BASELINE.md`
- `reports/EXTERNAL_SKG_DTN_BASELINE_REPORT.md`
- `docs/canonical_blueprint_series/`
- `docs/blueprint_addenda/`
- `docs/document_control/`
- selected runtime boundary surfaces under `sbp_lex/`

The A0 source-lineage capture remains NOT CANON. It does not authorise Codex to
create the 11 historical SKG/DTN blueprints or infer their content.

## Proposed Experimental File Boundary

Future Phase 19E work may safely live in isolated, branch-only paths:

- `experiments/cognitive_pipelines/`
- `docs/phase19e/`
- `reports/`

If code is later approved, the first implementation namespace should be
`experiments/cognitive_pipelines/`, not `sbp_lex/`, `main.py`, or
`external_substrates/`.

The experimental namespace must remain detached from runtime startup,
traversal, governance, execution, audit mutation, token mutation, replay
mutation, and canonical blueprint authority.

## Forbidden Modification List

Future Phase 19E work must not modify:

- `main.py`
- `sbp_lex/pipeline/`
- `sbp_lex/governance/`
- `sbp_lex/collective/`
- `sbp_lex/execution/`
- `sbp_lex/audit/`
- `sbp_lex/security/`
- `sbp_lex/authority_first/`
- `sbp_lex/shared/`
- `docs/canonical_blueprint_series/`
- existing `docs/document_control/` control outputs
- existing SKG/DTN substrate authority boundaries
- tests outside an explicitly approved Phase 19E test namespace
- `baselines/`
- `runtime_artifacts/`
- final pilot package materials

Phase 19E must not:

- reorder the locked SBP-LEX traversal
- move SKG/DTN inside runtime authority
- allow SKG/DTN to execute
- alter Execution Gate supremacy
- alter Procedural Truth binding
- alter Domain Wrap placement
- mutate audit/replay/token fail-closed controls
- promote research into Desktop V1 canon

## Cognitive Pipeline Non-Authority Rules

Cognitive pipelines must not:

- absorb SKG/DTN
- become SKG/DTN execution authority
- become Governance authority
- bypass Hard Entry
- bypass Procedural Truth
- bypass Domain Wrap
- weaken Execution Gate
- mutate audit/replay/token controls
- become Desktop V1 canon
- infer missing SKG/DTN blueprint content
- claim production readiness

If future cognitive outputs exist, they must be evidence/refinement/context
signals only until an owner-approved boundary defines otherwise.

## Relationship To SKG/DTN Source-Lineage Capture

The Phase 19E-A0 source-lineage capture preserves a historical owner instruction
for SKG/DTN external blueprint construction.

Phase 19E cognitive work may reference that note only to preserve boundaries:

- SKG/DTN remain external.
- SKG/DTN do not execute.
- SKG/DTN are not internal runtime authority.
- Domain determines allowed existence.
- Missing SKG/DTN blueprints must not be fabricated.

Phase 19E cognitive work must not become a substitute for the missing 11
SKG/DTN documents.

## Owner Decisions Required

Before any code implementation, the owner must decide:

1. Whether Phase 19E may create `experiments/cognitive_pipelines/`.
2. Whether the first implementation may be code or documentation/schema only.
3. Whether cognitive outputs are allowed to copy the external-substrate package
   discipline used by SKG/DTN.
4. Whether Pipeline A/B terminology is approved for branch-only experimental use.
5. Whether cognitive pipeline artifacts may include deterministic parity
   fixtures.
6. Whether any Phase 19E tests may be added under a new isolated test namespace.
7. Whether `Reality-Inducement & Reality-Binding` remains excluded from Phase
   19E until separate owner review.
8. Whether this branch should ever be pushed as an experimental branch.

## Safe First Implementation Unit

The minimum safe first implementation unit, if later approved, is:

- an isolated `experiments/cognitive_pipelines/` skeleton
- no imports from `sbp_lex`
- no imports into `sbp_lex`
- no CLI that mutates runtime artifacts
- no runtime startup hook
- no execution decisions
- no governance decisions
- no audit/token/replay mutation
- a boundary README
- a deterministic schema or data model for non-authoritative cognitive
  refinement/evaluation records

The safest first pass is documentation/schema/test-boundary only, not active
pipeline logic.

## Test Plan Outline

If implementation later proceeds, tests should prove:

- no imports from `experiments.cognitive_pipelines` into `main.py` or `sbp_lex/`
- no imports from `sbp_lex` runtime authority modules into the experiment
- cognitive artifacts cannot emit `ALLOW`, `DENY`, `ESCALATE`, `EXECUTE`, or
  `HALT`
- cognitive artifacts cannot emit Governance, Domain, Aurion, or Execution Gate
  results
- cognitive artifacts cannot mutate audit, replay, token, hash-chain, or runtime
  artifact stores
- cognitive artifacts are request-bound, digest-bound, and deterministic if
  external-substrate discipline is approved
- parity mismatch remains a non-execution condition
- degraded mode is observation/diagnostics only
- Desktop V1 traversal order remains unchanged
- SKG/DTN remain external and non-authoritative

## Drift Risk Table

| Risk | Severity | Control |
| --- | --- | --- |
| Cognitive pipeline becomes hidden authority | High | Keep all work under `experiments/cognitive_pipelines/`; reject authority fields and decision values. |
| SKG/DTN absorbed into cognitive work | High | Treat A0 capture as boundary evidence only; do not infer missing SKG/DTN blueprints. |
| Runtime traversal reordered | High | Do not modify `main.py` or `sbp_lex/pipeline/`; test stage order if code is later approved. |
| Domain Wrap drift | High | Preserve Governance -> GRC -> Domain Wrap -> Aurion -> Execution Gate -> Audit. |
| Execution Gate weakened | High | No direct execution output or gate bypass in experiment. |
| Procedural Truth bypass | High | Cognitive records may not influence runtime unless future owner-approved ingress rules exist. |
| Audit/replay/token mutation | High | Experiment must be read-only with respect to runtime evidence stores. |
| Research promoted into canon | Medium | Keep classification as EXPERIMENTAL_BRANCH / NOT CANON. |
| Production-readiness overclaim | Medium | Report prototype/research status only. |
| Terminology drift around Reality-Inducement | Medium | Keep excluded pending owner review. |

## Final Recommendation

PROCEED_TO_19E_B.

Proceed only to a Phase 19E-B owner-decision or pre-implementation planning pass.
Do not implement cognitive pipelines until the owner explicitly approves the
first implementation unit and test boundary.

