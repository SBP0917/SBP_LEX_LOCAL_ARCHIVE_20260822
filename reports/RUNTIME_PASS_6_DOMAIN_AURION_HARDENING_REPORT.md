# Runtime Pass 6 — Domain, Aurion and Controlled Re-entry Hardening Report

Date: 2026-08-08

## Result

Pass 6 is PASS / CLOSED for the authorised Desktop V1 segment:

`valid GRC-governed state → Domain → Aurion constrained pathway resolution → controlled full retraversal → valid Execution Convergence handoff`

Eight evidence-backed gaps were identified and closed. Domain and Aurion now
admit only the exact canonical predecessor state, preserve all upstream
constraints, emit signed state/token/history evidence, and fail closed on
malformed, stale, replayed, substituted or bypassed inputs. The existing
materially changed-request route is the only controlled re-entry mechanism;
its signed denial proof is process-local, bounded, single-use and preserved
through one immutable prepare-once boundary followed by full retraversal.

The resulting Execution Convergence handoff validates with no failures. Its
signed digest is
`c2428319e1637b10438d9bb85ed9112befe4d4243c613ae6694b1b5cc46029c4`.
Execution Convergence and Execution Gate were not modified or hardened; that
work is explicitly deferred to Pass 7.

## Commit scope

| Role | Commit |
|---|---|
| Pass 5 evidence / Pass 6 starting point | `067bf77cac99b6e6aee6167a4f29eb26369b03be` |
| Pass 6 runtime and focused-test implementation | `d9f4a5b2b472035784452f6140e926698d73cfce` |
| Pass 6 evidence and lineage | the Git commit containing this file; supplied in final handoff |

Branch: `main`

No commit was pushed.

## Classification-first findings and closure

| Gap | Observed baseline condition | Bounded closure | Result |
|---|---|---|---|
| `GAP-DA-001` | Domain evidence did not bind its complete attempts, results, reason, effective candidate, constraints and upstream state. | Exact signed Domain evidence/token semantics, latest finalisation, live-state verification and complete history/candidate/result bindings. | CLOSED |
| `GAP-DA-002` | Aurion could accept an incomplete or altered GRC/Domain prefix. | `validate_domain_handoff_to_aurion` now requires the complete valid Root/PT/Classification/Licensing/Governance/GRC/Domain chain and exact live continuity. | CLOSED |
| `GAP-DA-003` | A tighter Domain fallback scope was temporary and could disappear before Aurion. | The selected Domain candidate and effective constraint snapshot are persisted, signed and required unchanged in every Aurion candidate. | CLOSED |
| `GAP-DA-004` | Empty/malformed candidate data and incomplete bindings could participate in Aurion. | Exact candidate/pathway schemas, canonical bindings, monotonic constraints, bounded non-Boolean values and pre/post-rank validation. | CLOSED |
| `GAP-DA-005` | Equal-score order depended on caller order; duplicates and unsigned selected pathways were possible. | Canonical score/ID/digest order, duplicate rejection and signed generated/admissible/ordered/rejected/selected candidate and pathway digests. | CLOSED |
| `GAP-DA-006` | Re-running a completed Domain/Aurion traversal could mint another permission; denial proof use was not single-use. | Completion guards, descendant invalidation, signed prior-denial validation, a capacity-4096 process-local registry and immutable prepare-once full replay. | CLOSED |
| `GAP-DA-007` | Dormant standalone helpers could appear to be alternate Domain/Aurion authority. | Helpers remain integrity-compatible but always return `allowed: false`, `valid: false` and `execution_convergence_eligible: false`. | CLOSED |
| `GAP-DA-008` | Replay, A/B convergence and audit compared only coarse results and omitted material pathway/evidence lineage. | One shared exact 39-field Domain/Aurion projection, signed stage-specific audit-prefix lineage and fail-closed mismatch handling. | CLOSED |

The canonical finding record is
`docs/runtime/DOMAIN_AURION_PASS6_GAP_REGISTER.md`.

## Runtime hardening delivered

### Domain entry and enforcement

- `validate_governed_domain_handoff` requires certified PT, valid
  Classification and Licensing, Governance `ALLOW`, GRC `PASS`, the complete
  expected token/evidence prefix, the correct request/EIE/traversal identity,
  live state/hash continuity and monotonic authority constraints.
- `run_domain_wrap` validates canonical input before an attempt, rejects a
  repeated completed stage, invalidates stale descendants, and records every
  bounded attempt and failure.
- The four canonical Domain implementations are required in their exact type
  and order. Missing, duplicate, reordered, same-name substituted, malformed
  or exceptional rules fail closed.
- Domain fallback may only tighten scope. The accepted effective candidate,
  attempts, results, reason, constraints and upstream digests are signed into
  the existing Domain evidence/token and append-only history.
- A Domain failure produces no Aurion eligibility and neutralises forged
  pre-execution authority.

### Aurion constrained pathway resolution

- `validate_domain_handoff_to_aurion` rejects direct GRC, Governance,
  Licensing, Classification or PT entry, and rejects any missing, invalid,
  wrong-request, stale, replayed or failed Domain state.
- `generate_candidates` emits the canonical bound candidate set;
  `validate_candidate_constraints` enforces the exact schema, upstream
  bindings, authority, licence, tier, autonomy, scope and pathway rules.
- The runtime requires exact equality with the canonical generator output,
  validates candidates before and after ranking, rejects duplicate IDs and
  digests, and rejects ranker content mutation.
- `rank_candidates` uses the deterministic score, candidate ID and canonical
  candidate digest tie-break. The complete ordered set and selected
  candidate/pathway are included in signed evidence.
- Aurion resolves only constrained pathways. It does not issue final execution
  permission.

### Denial and Domain-failure supremacy

Governance `DENY`, unresolved `ESCALATE`, invalid Licensing, failed PT and
Domain failure all dominate Aurion. Candidate preference, ordering, urgency,
severity, fallback, adaptive mode, UI fields and synthetic SKG/DTN fields
cannot reverse an upstream prohibition. A failed Domain or Aurion path clears
downstream tokens and terminal/pre-execution authority fields while retaining
auditable failure history.

### Exclusive mediation

Within the implemented Desktop V1 runtime, an execution-convergence-ready
state requires both canonical Domain and Aurion finalisations. Direct boundary
calls, public noncanonical containers, forged PASS records, replaced
candidates, nested permission fields, terminal control fields and legacy
helpers cannot produce a valid handoff. This is a scoped runtime claim, not a
claim about universal external-effect mediation.

### Controlled re-entry and replay

- Re-entry requires the existing GRC-governed materially changed request and a
  valid signed prior-denial controlled outcome.
- The prior denial, denial fingerprint and Domain/Aurion failure histories are
  preserved; DENY, ESCALATE and failed-pathway lineage cannot be deleted.
- Identical requests, stale or substituted evidence, history deletion,
  Domain-direct, Aurion-direct and execution-direct re-entry all fail closed.
- `_ControlledReentryReplayRegistry` records each accepted proof digest once,
  is private to the process, lock protected and bounded at 4,096 entries.
  Public pipeline APIs cannot inject or replace it.
- `prepare_pipeline_boundary` consumes the proof once and seals one immutable
  prepared boundary. A/B and replay runs receive deterministic clones and must
  traverse every canonical stage again.

### Monotonic constraints and continuity

Signed Domain/Aurion projections preserve request fingerprint, EIE digest,
collective-signal digest, traversal ID, PT, Classification, Licensing,
Governance/GRC, authority scope, consequence tier, autonomy ceiling, effective
Domain scope, stage-entry state hash, token/evidence digests, history and the
hash-chain finalisation position. Authority cannot expand, licence scope cannot
broaden, tier cannot decrease, autonomy cannot increase, and Domain
constraints cannot disappear.

### Execution Convergence handoff

`build_execution_convergence_handoff` signs the immutable state entering the
existing boundary. `validate_execution_convergence_handoff` and
`validate_handoff_evidence` require the exact stage prefix through Aurion, the
Aurion hash-chain tail, Domain/Aurion evidence and token digests, selected
candidate/pathway, ordered set, constraint snapshot, re-entry and histories.
Bypass, invalid pathway, wrong identity/hash, replay, downgrade, escalation,
authority expansion and unauthorised re-entry cannot produce a valid handoff.

## Replay and deterministic A/B parity

The runtime and replay entrypoints both pass. Replay is deterministic and uses
the same canonical Domain/Aurion summary as convergence and audit. Exact A/B
parity passed all 39 comparison fields; near-match reconciliation is false.
Same-result evidence, candidate, pathway, history or handoff mutations are
material mismatches and fail closed.

## Verification results

| Gate | Exact result |
|---|---|
| `python -m compileall -q sbp_lex tests` | PASS |
| Focused Pass 6 and Phase 15.5b integration | PASS — 68 passed in 72.02s |
| Directly affected regressions | PASS — 296 passed in 289.24s |
| Full approved Windows suite | PASS — 2,060 passed, 7 skipped in 2,436.60s |
| Normal runtime | PASS |
| Replay | PASS — deterministic |
| A/B parity | EXACT — 39/39 fields; near-match false |
| Domain bypass protection | PASS |
| Aurion bypass protection | PASS |
| Governance DENY supremacy | PASS |
| Domain failure supremacy | PASS |
| Exclusive mediation | PASS within Desktop V1 scope |
| Controlled re-entry | PASS |
| Tier/autonomy/authority monotonicity | PASS |
| State/token/hash continuity | PASS |
| Execution Convergence handoff | PASS — signed digest `c2428319e1637b10438d9bb85ed9112befe4d4243c613ae6694b1b5cc46029c4` |
| Release integrity | `RELEASE_INTEGRITY_PASS` |
| 25-year capstone | `LOCAL_TRUST_CAPSTONE_PASS` |
| Adversarial harness | `ADVERSARIAL_NEGATIVE_HARNESS_PASS` |

The authoritative full-suite run used the existing Python 3.12.13 validation
environment. A separate CPython 3.14 captured-output attempt encountered
Windows `WinError 6`; this was environment-only and did not represent a source
or test failure.

## Implementation commit contents

Runtime and integrity:

- `sbp_lex/audit/audit_engine.py`
- `sbp_lex/aurion15/candidate/generator.py`
- `sbp_lex/aurion15/candidate/ranker.py`
- `sbp_lex/aurion15/candidate_resolution.py`
- `sbp_lex/aurion15/runtime/constraint_validator.py`
- `sbp_lex/aurion15/runtime/runner.py`
- `sbp_lex/aurion15/runtime_constraint_engine.py`
- `sbp_lex/domains/runner.py`
- `sbp_lex/pipeline/dual_runner.py`
- `sbp_lex/pipeline/replay_runner.py`
- `sbp_lex/pipeline/runner.py`
- `sbp_lex/security/authority_boundary.py`
- `sbp_lex/security/domain_admissibility.py`
- `sbp_lex/security/domain_aurion_evidence.py`
- `sbp_lex/security/governed_stage_evidence.py`
- `sbp_lex/shared/convergence.py`

Tests and bounded documentation:

- `tests/conftest.py`
- `tests/test_phase_15_5a_alignment.py`
- `tests/test_phase_15_5b_integration.py`
- `tests/test_runtime_pass6_domain_aurion_reentry_hardening.py`
- `docs/runtime/DOMAIN_AURION_PASS6_GAP_REGISTER.md`

## Durable evidence set

- `outputs/runtime/domain_aurion_runtime_evidence.json`
- `outputs/runtime/domain_aurion_parity_evidence.json`
- `outputs/runtime/domain_aurion_reentry_evidence.json`
- `reports/RUNTIME_PASS_6_DOMAIN_AURION_HARDENING_REPORT.md`
- `reports/RUNTIME_PASS_6_DOMAIN_AURION_LINEAGE_REPORT.md`

The evidence artifacts contain no signing seed, private key, credential or
external-provider secret.

## Scope declarations and exit gate

ARCHITECTURE CHANGED: NO

CANON CHANGED: NO

PASSES 1–5 REOPENED OR REDESIGNED: NO

RUNTIME AUTHORITY OWNERSHIP CHANGED: NO

TRAVERSAL ORDER CHANGED: NO

DOMAIN EXECUTION AUTHORITY INTRODUCED: NO

AURION EXECUTION AUTHORITY INTRODUCED: NO

EXECUTION CONVERGENCE MODIFIED OR HARDENED: NO — DEFERRED TO PASS 7

EXECUTION GATE MODIFIED OR HARDENED: NO — DEFERRED TO PASS 7

NEW TOKEN, STAGE OR LOOP ARCHITECTURE INTRODUCED: NO

LIVE SKG/DTN OR EXTERNAL SERVICE INTRODUCED: NO

GAPS IDENTIFIED: 8

GAPS CLOSED: 8

UNRESOLVED DOMAIN GAPS: 0

UNRESOLVED AURION GAPS: 0

UNRESOLVED RE-ENTRY GAPS: 0

TECHNICAL PASS 6 RESULT: PASS / CLOSED

READY FOR PASS 7: YES
