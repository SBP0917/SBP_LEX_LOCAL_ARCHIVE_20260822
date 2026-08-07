# Runtime Pass 5 — Classification, Licensing, Governance and GRC Lineage Report
primary checkout: unrelated video-generator edits remain unstaged. Pass 5 paths
are committed, and the implementation commit was independently verified from a
clean canonical clone. The unrelated files were neither staged nor modified by
Pass 5.
Date: 2026-08-08

## Commit lineage

```text
Pass 4 evidence / Pass 5 baseline
2e02b18c7e25f4160f3d2cf3645e3f6cc18fe4e9
    ↓
Pass 5 runtime and focused-test implementation
6a8ea7d75096dc90b17c618a73ef090c79c821df
    ↓
Pass 5 evidence-only recording commit
the commit containing this report; exact hash emitted in the final handoff
```

Branch: `main`

The implementation commit was tested from a clean local clone attached to
`main`, tracking `origin/main`, with the canonical remote
`https://github.com/SBP0917/SBP_LEX_DUAL_V6.git`. No commit was pushed.

## Requirement-to-runtime-to-evidence lineage

| Requirement | Runtime implementation | Function/schema | Focused proof | Durable evidence | Result |
|---|---|---|---|---|---|
| Certified PT prerequisite | Every Pass 5 stage calls the canonical upstream validator before granting eligibility. | `security/authority_boundary.py`; `validate_canonical_upstream` | valid handoff; incomplete-prefix Domain matrix | stage `upstream_token_digests` and `upstream_evidence_digests` | CLOSED |
| Classification determinism | Complete result/reason/state projection is signed and hash-finalized. | `classification/engine.py`; `desktop-v1.governed-stage-evidence.v1` | `test_valid_governed_handoff_has_exact_signed_stage_lineage` | Classification stage/evidence/token digests | CLOSED |
| Classification substitution resistance | Evidence and token bind request, EIE, traversal, entry state and exact live projection; latest same-stage finalization wins. | `governed_stage_evidence.py`; `validate_stage_evidence` | cross-request, scope substitution, historical ALLOW supersession | evidence validity/failure digest and chain index | CLOSED |
| Autonomy ceiling law | Values are non-Boolean integers in `0..100`; ceiling cannot exceed the AP/ACF profile. | `classification/engine.py`; `autonomy_ceiling_engine.py` | bounded schema matrix; profile self-escalation | constraint snapshot | CLOSED |
| Explicit licence | Missing, conflicting or unsupported declarations fail; supported aliases normalize deterministically. | `api/schema_validation.py`; `licensing/engine.py` | missing, alias, structured and conflict cases | Licensing reason/state/evidence | CLOSED |
| Scope non-broadening | Classified, context, requested and permitted scopes must agree exactly. | `licensing/scope_engine.py`; `validate_scope` | explicit scope contract; Classification/Licensing substitution | Classification/Licensing constraint snapshots | CLOSED |
| Licensing cannot bypass Governance | Licensing evidence/token is required and descendant authority is purged on denial/re-entry. | `licensing/engine.py`; `invalidate_from_stage` | stale ALLOW token purge; Licensing substitution | token expected/present/valid audit fields | CLOSED |
| Governance result contract | Existing ALLOW/DENY/ESCALATE semantics and deterministic reasons are retained. | `governance/engine.py`; `run_governance` | valid, DENY and ESCALATE pipeline cases | Governance result/reason/evidence | CLOSED |
| Governance history | Each outcome appends a digest-linked request/EIE/traversal-bound history record. | `governed_stage_evidence.py`; `append_governance_history`, `validate_governance_history` | deletion/inversion and malformed-history attacks | history digest and validation result | CLOSED |
| DENY supremacy | Governance DENY cannot be replaced by mutable downstream fields, stale ALLOW or direct Domain invocation. | Governance/GRC evidence validation plus Domain ingress guard | eight inversion vectors; stale governed ALLOW | negative-test list and audit lineage | CLOSED |
| ESCALATE protection | Governance/GRC ESCALATE never creates Governance or Domain eligibility and halts ordinary execution. | `governance/grc.py`; `domains/runner.py` | ESCALATE→permission and ESCALATE→ALLOW mutation | replay/audit ESCALATE outcomes | CLOSED |
| Full GRC mediation | GRC validates every required governed predecessor and normalizes invalid handoff to DENY/HALT. | `governance/grc.py`; `validate_governed_stage_token` | direct GRC, missing Governance token, incomplete chain | GRC evidence/token/failure lineage | CLOSED |
| Governed re-entry | Denial fingerprint, prior denial, material change, fallback and escalation inputs are signed. | `governance/grc.py`; GRC `reentry_input_snapshot` | fingerprint/retry/fallback/feedback matrix | governed re-entry and input snapshot | CLOSED |
| No stale stage authority | Re-evaluation invalidates current/descendant evidence and tokens; old finalization is superseded. | `governed_stage_evidence.py`; `stage_already_completed`, `invalidate_from_stage` | Classification and governed historical ALLOW tests | latest-finalisation validation failure | CLOSED |
| Monotonic constraints | Tier, autonomy, authority, scope and PT state remain exact through GRC. | `validate_constraint_continuity`; stage `constraint_snapshot` | late tier/autonomy downgrade; scope attacks | `constraint_continuity_valid=true` | CLOSED |
| State/hash continuity | Stage-entry state hash, decision state, chain head and finalization entry are bound; malformed chains deny without throwing. | `shared/hash_chain.py`; `live_state_hash_valid`, `append_stage_finalisation` | rebuilt token state; malformed chain cases | state hashes, chain heads and logical indexes | CLOSED |
| Token continuity | Existing tokens bind exact evidence digest, stage state, result and constraints. | `stage_token_payload`; `validate_governed_stage_token` | deleted/forged/stale/cross-request token cases | per-stage token digest/validity | CLOSED |
| Exact replay | Canonical comparison metadata includes all Pass 5 result/reason/live/evidence/token/history/re-entry fields. | `pipeline/replay_runner.py`; `REPLAY_COMPARISON_FIELDS`, `verify_replay_result` | valid, DENY, ESCALATE and re-signed metadata cases | 2 matched, zero mismatches | CLOSED |
| Exact A/B parity | Convergence recomputes live state, enforces canonical fields and rejects inconsistent signed semantics. | `shared/convergence.py`; `build_pipeline_convergence_proof`, `verify_convergence_proof` | live mutation, GRC divergence and actual dual-runner fail-close | all 35 fields exact; near-match false | CLOSED |
| Complete audit | Audit records evidence/token validity, state/chain bindings, constraints, history, re-entry and Domain eligibility. | `audit/audit_engine.py`; `desktop-v1.pass5-governed-lineage.v1` | ALLOW, DENY and ESCALATE audit tests | signed audit hash and lineage stage map | CLOSED |
| Domain ingress exclusivity | No Domain engine runs without exact Governance ALLOW plus GRC PASS and complete valid lineage. | `security/authority_boundary.py`; `validate_governed_domain_handoff`; `domains/runner.py` | incomplete prefixes; missing/DENY/hash/cross-request GRC | valid handoff snapshot; zero-attempt negative evidence | CLOSED |

## Gap-to-file-to-test closure matrix

| Gap | Principal files | Principal regression proof | Closure evidence |
|---|---|---|---|
| `GAP-CLG-001` | `classification/engine.py`, `security/governed_stage_evidence.py`, `security/authority_boundary.py` | scope mutation, cross-request evidence, historical ALLOW | Classification stage/evidence/token digests and valid live projection |
| `GAP-CLG-002` | `api/schema_validation.py`, `classification/engine.py`, `licensing/autonomy_ceiling_engine.py` | bounded/non-Boolean matrix, class-profile ceiling | autonomy `50/75`, tier `MEDIUM`, constraint continuity valid |
| `GAP-CLG-003` | `licensing/engine.py`, `licensing/scope_engine.py` | missing/alias/structured/conflict licence and scope substitution | Licensing result/reason/state/evidence/token |
| `GAP-CLG-004` | `security/governed_stage_evidence.py`, all four stage engines | denial re-entry and stale finalization cases | supersession/invalidation failures; no stale eligibility |
| `GAP-CLG-005` | `governance/engine.py`, `security/governed_stage_evidence.py` | history deletion and eight denial-inversion vectors | valid history digest and Governance evidence |
| `GAP-CLG-006` | `governance/grc.py`, `security/authority_boundary.py` | direct GRC, missing Governance token, retry/fallback/feedback attacks | GRC exact evidence/token and governed re-entry |
| `GAP-CLG-007` | `domains/runner.py`, `security/authority_boundary.py` | incomplete prefixes and four GRC handoff attacks | valid positive handoff; invalid paths have zero attempts |
| `GAP-CLG-008` | `pipeline/dual_runner.py`, `pipeline/replay_runner.py`, `shared/convergence.py`, `audit/audit_engine.py` | exact replay, live parity mutation, actual dual divergence, audit matrices | parity JSON, replay hash, signed audit lineage |

## Exact governed-stage lineage

| Stage | Result | Stage-state digest | Evidence digest | Token digest | Chain index |
|---|---|---|---|---|---:|
| Classification | ALLOW | `677a1b9e733efc1184ff518d9b7baca0dc1413b6980ee496839d4070cb0923f7` | `40eca99738bc6e060a305105263092b0d345da52d445b1c3283e60a5f8ae24e7` | `f5bc2e105e7b51960522822a0e75229bbc755d2c080b34aa81f5e3f707a79b70` | 18 |
| Licensing | ALLOW | `eb7537ce243ddaa8becd4af52ad37f29c55d6cd6c1c1267251bf488415cdbeb7` | `a858f2b303873a14017959dd555c725f3361c3ca5432f76416c8beaf169d0839` | `92117ebcb7cb4a9b08a844c2740d67bb0d60906fc61075baa347252b596c9c94` | 19 |
| Governance | ALLOW | `b7fa69602450bbce977f75ca02b26c8338319a485bc5486ef693649d29076f45` | `1fe597cfb34e36fdc9368ff5108a311cdaab357b60243a6f1c332ad311269a28` | `584c91ee69318380931738d76bedc21c04c6bf771f5f60b35c8dd320133f5d5a` | 21 |
| GRC | PASS | `9bd414f955bc1dbab1f3f87116aab99b3f90900681dae4d4c14bb8c40a175f3c` | `9717a8377863bc60cb0082be4b632ee9153affe6fc7bec3f8f9f62ad8d80e634` | `b98b626638c720f6bf503644c42a57fe840a69398affdade7270f5c8107ff3ce` | 22 |

All evidence and tokens validate. Constraint continuity, Governance history,
the governed-prefix live state hash, the hash chain and Domain handoff all
validate with empty failure lists.

## Replay and parity lineage

| Evidence | Result |
|---|---|
| Initial A/B input parity | exact; near-match false |
| Root/PT parity | Root, PT, tier and corroboration exact |
| Pass 5 governed parity | all 35 canonical fields exact |
| Convergence | matched; no mismatches; hash `6fdeeecaaa34390b87afaea226f5e11b8ad510af917e2bb826e2e4892f970f30` |
| Replay | 2 matched; no mismatches; hash `0d69a686a5017d8ceee25f800ab84ff935a93d0ad16284989c75f663ec2fee2f` |
| Divergent actual dual run | exact mismatch; `ESCALATE / HALT`; divergence record present |
| Re-signed inconsistent proof | rejected |
| Re-signed replay metadata mismatch | rejected |

## Verification lineage

| Gate | Result |
|---|---|
| Compile | PASS, exit 0 |
| Focused Pass 5 | 54 passed |
| Focused + Phase 15 | 79 passed |
| Directly affected | 336 passed, 1 skipped |
| Provenance/R2/R4 clean gate | 113 passed, 3 skipped |
| Full approved Windows wrapper | 2,005 passed, 7 skipped; wrapper PASS |
| Normal runtime | ALLOW / EXECUTE; convergence matched; no token failures |
| Replay | 2 matched; zero mismatches |
| Release integrity | RELEASE_INTEGRITY_PASS |
| 25-year capstone | LOCAL_TRUST_CAPSTONE_PASS |
| Adversarial harness | ADVERSARIAL_NEGATIVE_HARNESS_PASS |

## Durable artifact lineage

- `outputs/runtime/classification_licensing_governance_grc_evidence.json`
- `outputs/runtime/classification_licensing_governance_grc_parity_evidence.json`
- `reports/RUNTIME_PASS_5_CLASSIFICATION_LICENSING_GOVERNANCE_GRC_HARDENING_REPORT.md`
- `reports/RUNTIME_PASS_5_CLASSIFICATION_LICENSING_GOVERNANCE_GRC_LINEAGE_REPORT.md`

The JSON artifacts contain no signing seed, private key, signature blob,
credential or external-provider secret.

## Boundary and unresolved findings

GAPS IDENTIFIED: 8

GAPS CLOSED: 8

UNRESOLVED CLASSIFICATION GAPS: 0

UNRESOLVED LICENSING GAPS: 0

UNRESOLVED GOVERNANCE GAPS: 0

UNRESOLVED GRC GAPS: 0

DOMAIN HARDENING BEYOND INGRESS: NOT STARTED

AURION HARDENING: NOT STARTED

EXECUTION CONVERGENCE / EXECUTION GATE HARDENING: NOT STARTED

The only unclosed exit condition is procedural workspace hygiene in the shared
primary checkout: unrelated video-generator edits remain unstaged. Pass 5 paths
are committed, and the implementation commit was independently verified from a
clean canonical clone. The unrelated files were neither staged nor modified by
Pass 5.
