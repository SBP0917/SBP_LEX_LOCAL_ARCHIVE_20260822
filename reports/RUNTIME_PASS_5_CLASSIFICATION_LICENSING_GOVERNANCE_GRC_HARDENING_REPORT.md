# Runtime Pass 5 — Classification, Licensing, Governance and GRC Hardening Report

Date: 2026-08-08

## Result

The authorised runtime segment is implemented and passes its technical gates:

`certified PT → Classification → Licensing → Governance → GRC → governed Domain ingress`

Eight observed gaps were closed. Classification, Licensing, Governance and GRC
now emit exact signed stage evidence bound to the request, EIE, traversal,
upstream authority, constraints, decision-stage state and hash-chain position.
Domain ingress admits only Governance `ALLOW` plus GRC `PASS` with the complete
valid chain. No Domain reasoning, Aurion, Execution Gate, Pass 4 Root/PT logic,
owner canon, architecture, token family or traversal order was redesigned.

Technical verification is PASS. The strict final shared-checkout cleanliness
gate remains externally occupied by unrelated concurrent video-generator edits.
Those edits were preserved and excluded from both Pass 5 commits. The exact
implementation commit was therefore verified in a clean attached-`main` clone
with the canonical remote and upstream.

## Commit scope

| Role | Commit |
|---|---|
| Pass 4 / Pass 5 starting point | `2e02b18c7e25f4160f3d2cf3645e3f6cc18fe4e9` |
| Pass 5 implementation and focused tests | `6a8ea7d75096dc90b17c618a73ef090c79c821df` |
| Pass 5 evidence and lineage | The commit containing this report; exact hash emitted in the final handoff |

Branch: `main`

No commit was pushed.

## Classification-first findings and closure

| Gap | Observed baseline behavior | Bounded closure | Result |
|---|---|---|---|
| `GAP-CLG-001` | Classification state/scope could be changed after Classification and still enter Licensing. | Signed exact Classification evidence and token payload; request/EIE/PT/state/hash/constraint binding; stale evidence supersession. | CLOSED |
| `GAP-CLG-002` | Malformed autonomy values and a ceiling above the locked class profile were accepted. | Non-Boolean integer `0..100` checks; ceiling may tighten but cannot exceed the class profile. | CLOSED |
| `GAP-CLG-003` | Missing licence silently became valid and licensed scope was incompletely bound. | Explicit alias-aware licence declaration, conflict rejection, exact scope/environment/autonomy continuity and signed Licensing evidence. | CLOSED |
| `GAP-CLG-004` | Re-entered stages could retain stale ALLOW tokens or descendant authority. | One traversal per completed stage/state, descendant invalidation and latest-finalisation enforcement. | CLOSED |
| `GAP-CLG-005` | Governance result/history were mutable and not signed as one complete outcome. | Signed complete Governance evidence, hash-bound append-only history and ALLOW-only eligibility token. | CLOSED |
| `GAP-CLG-006` | GRC could PASS without valid Classification, Licensing or Governance authority. | Full governed-chain validation; invalid upstream state atomically normalizes to DENY/HALT; DENY/ESCALATE preserved. | CLOSED |
| `GAP-CLG-007` | Domain ingress did not require exact GRC PASS evidence/token state. | Exclusive governed-handoff validator before any Domain attempt; invalid handoff escalates with zero attempts and no Domain token. | CLOSED |
| `GAP-CLG-008` | Replay, A/B convergence and audit omitted material Pass 5 fields. | Exact live-state/evidence/token/history/re-entry/constraint comparison, signed proof verification and complete audit lineage. | CLOSED |

Canonical detail is recorded in:

- `docs/runtime/CLASSIFICATION_LICENSING_GOVERNANCE_GRC_PASS5_GAP_REGISTER.md`
- `docs/runtime/CLASSIFICATION_LICENSING_GOVERNANCE_GRC_RUNTIME_SPECIFICATION.md`

## Runtime hardening delivered

### Classification

- Requires valid canonical Root/PT authority and an intact entry state hash.
- Binds complete Classification result, reason, class/profile, scope,
  environment, restrictions, autonomy, tier and upstream lineage.
- Rejects Boolean, negative, out-of-range and profile-escalating autonomy values.
- Invalidates its own and all descendant authority on re-entry or denial.
- Prevents cross-request, cross-state, stale and superseded Classification reuse.

### Licensing

- Requires an explicit supported licence state; absence is never inferred valid.
- Normalizes existing British/American aliases and rejects conflicting sources.
- Applies an exact conservative scope contract; it does not invent a scope
  hierarchy or external licence regime.
- Preserves classified autonomy/tier/authority/PT constraints and binds the
  complete assessment in signed evidence and the existing Licensing token.

### Governance and denial supremacy

- Preserves the existing `ALLOW`, `DENY`, `ESCALATE` result family.
- Records a deterministic signed decision plus hash-bound Governance history.
- Issues Governance eligibility only for ALLOW.
- Eight downstream inversion vectors—candidate/path data, UI result, urgency,
  severity, adaptive mode, synthetic SKG, synthetic DTN and stale ALLOW—cannot
  turn a Governance DENY into Domain admission.
- ESCALATE cannot become ordinary permission or execution.

### GRC and governed re-entry

- Validates all required Classification, Licensing and Governance evidence and
  tokens in addition to the certified Root/PT chain.
- Binds Governance history, denial fingerprint, material-change declaration,
  retry/fallback inputs, safe-state outcome and governed re-entry response.
- Fingerprint substitution, state substitution, stale authority, history
  deletion, unauthorised retry and uncontrolled fallback all normalize to DENY.
- GRC DENY and ESCALATE records remain auditable with the existing GRC token;
  neither constitutes downstream eligibility.

### Domain ingress boundary

- Requires exact Governance ALLOW and GRC PASS plus live state, hash chain,
  evidence, token, request, EIE, authority, tier, autonomy and scope continuity.
- Direct PT→Domain, Classification→Domain, Licensing→Domain and
  Governance-without-GRC paths are rejected before any Domain candidate runs.
- Forged, stale, cross-request, downgraded, denied and unresolved-escalation
  states receive zero Domain attempts and no Domain token.

## State, token, hash and audit evidence

The valid governed-prefix snapshot records:

| Field | Value |
|---|---|
| Request fingerprint | `cd84a2f696258fe3f24aa6014be5d6b4a7f1805fe593733ecac7b53e428598a8` |
| EIE digest | `6d4c48f5a9c296fb06e81681a148f0f2af57d17a082ae0951e23e2c997aae1f5` |
| Governed state hash | `58d4f64d3a32e05211495360fbf994b9f21df75dd83f690f7283104631d681fa` |
| Hash-chain head | `e4356ae3a02698a0fa72d26652117a4ed52e07091155c770257dc8688c1715df` |
| Live state / hash chain | valid / valid |
| Constraint continuity | valid; zero failures |
| Governance history | valid; digest `3f91c74e92c43c7dab13df90150fb5a286f253b21f4719466374d624f303e638` |
| Domain handoff | valid; zero failures |

Every governed stage has valid evidence, a valid expected token, an exact stage
state digest, a bound entry state hash and a bound hash-chain head. The signed
audit is complete, locked and verified; it records valid evidence/token status
for ALLOW, DENY and ESCALATE paths.

## Replay and deterministic A/B parity

The two replay runs matched with zero mismatches. Replay now requires the exact
canonical Pass 5 comparison-field list and rejects a re-signed record with
missing metadata.

A/B parity is exact for all 35 governed-stage fields, including live stage
projection digests, evidence validity/failure digests, evidence/token digests,
Governance history, governed re-entry and constraint state. Near-match,
weighted and probabilistic reconciliation remain disabled. An actual
dual-runner GRC divergence produced `ESCALATE / HALT` and a divergence record.

## Verification results

| Gate | Exact result |
|---|---|
| `python -m compileall -q .` | PASS, exit 0; only historical inaccessible-cache notices |
| Focused Pass 5 | PASS — 54 passed in 103.07s |
| Focused + Phase 15 | PASS — 79 passed in 110.09s |
| Directly affected regressions | PASS — 336 passed, 1 skipped in 271.95s |
| Provenance/R2/R4 clean-clone gate | PASS — 113 passed, 3 skipped in 537.74s |
| Full approved Windows wrapper | PASS — 2,005 passed, 7 skipped in 975.74s (16:15); wrapper exit 0 |
| Normal runtime | PASS — `ALLOW / EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, token failures empty |
| Replay | PASS — 2 matched, zero mismatches, exact Pass 5 fields |
| A/B parity | EXACT — all 35 governed fields match; near-match false |
| Release integrity | `RELEASE_INTEGRITY_PASS` |
| 25-year capstone | `LOCAL_TRUST_CAPSTONE_PASS` |
| Adversarial harness | `ADVERSARIAL_NEGATIVE_HARNESS_PASS` |
| `git diff --check` before implementation commit | PASS |

Two non-authoritative full-suite attempts were retained as environmental
diagnostics rather than concealed: the primary checkout was rejected because
of unrelated dirty video files, and an initial clean-clone run put temporary
nested Git repositories inside the source tree. The authoritative clean clone
with system temp passed all 2,005 tests.

## Files changed by the implementation commit

Runtime and shared integrity:

- `sbp_lex/api/schema_validation.py`
- `sbp_lex/audit/audit_engine.py`
- `sbp_lex/classification/engine.py`
- `sbp_lex/domains/runner.py` — ingress guard only
- `sbp_lex/governance/engine.py`
- `sbp_lex/governance/grc.py`
- `sbp_lex/licensing/autonomy_ceiling_engine.py`
- `sbp_lex/licensing/engine.py`
- `sbp_lex/licensing/scope_engine.py`
- `sbp_lex/pipeline/dual_runner.py`
- `sbp_lex/pipeline/replay_runner.py`
- `sbp_lex/security/authority_boundary.py`
- `sbp_lex/security/governed_stage_evidence.py`
- `sbp_lex/shared/convergence.py`
- `sbp_lex/shared/hash_chain.py`

Tests and bounded documentation:

- `tests/test_runtime_pass5_classification_licensing_governance_grc_hardening.py`
- `tests/test_phase_15_5a_alignment.py`
- `docs/runtime/CLASSIFICATION_LICENSING_GOVERNANCE_GRC_PASS5_GAP_REGISTER.md`
- `docs/runtime/CLASSIFICATION_LICENSING_GOVERNANCE_GRC_RUNTIME_SPECIFICATION.md`

## Scope declarations

ARCHITECTURE CHANGED: NO

CANON CHANGED: NO

PASS 4 REOPENED OR ALTERED: NO

RUNTIME AUTHORITY OWNERSHIP CHANGED: NO

TRAVERSAL ORDER CHANGED: NO

DOMAIN REASONING HARDENED: NO

AURION HARDENED: NO

EXECUTION GATE HARDENED: NO

LIVE SKG/DTN OR EXTERNAL SERVICE INTRODUCED: NO

NEW TOKEN OR STAGE INTRODUCED: NO

UNRESOLVED CLASSIFICATION GAPS: 0

UNRESOLVED LICENSING GAPS: 0

UNRESOLVED GOVERNANCE GAPS: 0

UNRESOLVED GRC GAPS: 0

TECHNICAL PASS 5 RESULT: PASS

STRICT SHARED-WORKTREE EXIT GATE: PENDING — unrelated concurrent video-generator changes preserved
