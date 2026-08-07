# Runtime Pass 4 — Root/PT Lineage Report

Date: 2026-08-07

## Commit lineage

```text
Pass 3 final verification / Pass 4 baseline
7cf107245ec561e927bfa178f35a7d49a4da129b
    ↓
Pass 4 Root/PT implementation under test
e53bf8f560b3ad62a7d4a9104ba53153860e3729
    ↓
Pass 4 evidence-only recording commit
the commit containing this report; exact hash emitted in final handoff
```

Branch: `main`

The baseline and implementation commit were clean. The final handoff verifies
the evidence-only recording commit and a clean worktree. The containing commit
cannot be embedded in this file without changing that same commit hash.

## Requirement-to-runtime lineage

| Requirement | Runtime finding | File/function or schema | Focused proof | Durable evidence | Result |
|---|---|---|---|---|---|
| Exact Root order | Seven stages execute in the locked order and short-circuit on first failure. | `root_of_trust_runner.py`; `ROOT_OF_TRUST_ORDER`, `run_root_of_trust` | valid chain and 14 isolated failure cases | Root `stage_results`, result/reason/digest | CLOSED |
| Root input continuity | Request, EIE, Root-entry state, collective package, attachment and admitted authority material are exact. | `control_chain_validation.py`; `validate_root_input_bindings` | seven mutation cases plus request/EIE tests | `root_context_digest`, entry state and collective digests | CLOSED |
| Authority legitimacy | Authority/jurisdiction must match the signed admitted SKG basis. | `context_interface.py`; `anchor_validation_engine.py` | invalid/substituted/unresolved authority | authority and validation-basis binding | CLOSED |
| Attestation | Signature, identity, subject, authority, bindings, freshness, expiry and revocation are validated. | `context_interface.py`; `attestation_engine.py` | malformed, substituted, expired and revoked cases | attestation identities and stage digest | CLOSED |
| Exact consensus | All applicable admitted attestations must agree exactly; no score/tolerance. | `attestation_consensus_engine.py` | inconsistent consensus case | exact identity/statement vector | CLOSED |
| Truth anchor/continuity | Bound signed anchor is produced after prerequisites; predecessor and control-chain references must match. | `truth_anchor_engine.py`; `truth_continuity_engine.py` | anchor/continuity tamper cases | truth-anchor and continuity digests | CLOSED |
| Expiry/revocation | Authority, attestation and truth intervals/statuses are enforced. | `truth_expiry_engine.py`; `truth_revocation_engine.py` | expired/future/revoked matrix | deterministic stage/reason evidence | CLOSED |
| Aggregate Root evidence | Final stage vector, bindings, result/reason and signature are validated as one record. | `root_of_trust_runner.py`; `desktop-v1.root-evidence.v1` | valid/tamper/cross-request tests | `root_evidence_digest` | CLOSED |
| Root failure law | PT and downstream eligibility/tokens are removed; full corrected retraversal is required. | `_fail_root`; `_clear_root_and_downstream_eligibility` | each-stage failure followed by PT | persistent-inoperability record | CLOSED |
| One PT source assessment | One deterministic assessment feeds evidence, corroboration, sufficiency and PT. | `procedural_truth_envelope.py`; `assess_source_records` | evidence-dimension and binding matrices | `source_assessment_digest` | CLOSED |
| Source identity/independence | Unique qualifying provenance/source identity is counted once; duplicate aliases are excluded. | `desktop-v1.pt-source-assessment.v1`; `qualified_sources` | duplicate/alias TOP test | identity summary and duplicate count | CLOSED |
| Source qualification | Verification, attestation, freshness, provenance, consistency, independence, relevance and bindings are mandatory. | `source_is_qualified`; `validate_pt_evidence_envelope` | seven invalid dimensions and four binding mismatches | per-dimension aggregate results | CLOSED |
| Malformed source control | Empty/malformed IDs, URIs, types and claims fail at Hard Entry. | `schema_validation.py`; `validate_runtime_request_schema` | malformed source/identity cases | deterministic ingress denial | CLOSED |
| Evidentiary sufficiency | Count is necessary but not sufficient; completeness and every qualification dimension are distinct and digested. | `evidence_engine.py`; `desktop-v1.evidentiary-sufficiency.v1` | count-sufficient/incomplete case | sufficiency result/reason/digest | CLOSED |
| Locked 2/3/5 floors | LOW=2, MEDIUM=3, TOP=5 unique qualifying sources. | `thresholds.py`; `corroboration_engine.py` | six locked tier/count outcomes | required/observed and PT outcome | CLOSED |
| Factor/financial law | Strict 0..3 factors; locked AUD bands; maximum consequence factor wins. | `schema_validation.py`; `thresholds.py` | malformed/huge and band-boundary tests | four factors and computed tier | CLOSED |
| Dynamic escalation | LOW→MEDIUM, LOW→TOP and MEDIUM→TOP are allowed and recorded. | `apply_thresholds`; `run_threshold_conditioning` | three escalation cases | previous/current/high-water tier | CLOSED |
| No downgrade | MEDIUM→LOW, TOP→MEDIUM and TOP→LOW retain the high-water tier and fail deterministically. | `desktop-v1.threshold-conditioning.v1` | three downgrade cases and mutation tests | monotonic flag and state digest | CLOSED |
| PT evidence/token | Signed final PT evidence precedes PASS-only PT and threshold-token issuance with complete bindings. | `finalize_procedural_truth`; `validate_procedural_truth_evidence`; `verify_threshold_bundle` | token completeness/tamper/failure cases | PT evidence/token and threshold digests | CLOSED |
| PT continuity/graft resistance | Root, request, EIE, collective, source assessment, state and chain-head bindings prevent reuse. | PT/Root validators and finalization hash binding | post-Root substitution and same-request cross-state graft tests | Root/PT evidence digests and failure reasons | CLOSED |
| Classification boundary | Root/PT-invalid state cannot become Classification `ALLOW`. | `authority_boundary.py`; `validate_root_pt_eligibility` | downstream matrix and genuine PT escalation | classification guard result | CLOSED |
| Licensing boundary | Licence validity cannot override PT invalidity. | canonical-upstream eligibility guard | downstream matrix | licensing guard result | CLOSED |
| Governance boundary | Governance `ALLOW` is ineffective without valid Root/PT/corroboration. | canonical-upstream eligibility guard | downstream matrix | governance guard result | CLOSED |
| GRC boundary | GRC cannot restore execution permission; existing controlled re-entry remains. | `grc.py`; `run_grc` | downstream matrix and persistent-inoperability test | GRC deny/re-entry evidence | CLOSED |
| Domain/Aurion boundaries | Domain pass or pathway resolution cannot restore invalid PT. | existing runners via shared guard | downstream matrix | deterministic fail/escalate/HALT | CLOSED |
| Execution Gate boundary | PT, corroboration, tier, token, request, EIE and state semantics must all remain valid. | `authority_boundary.py`; `threshold_tokens.py` | eight execution-gate mutation cases | strict-security failure list | CLOSED |
| Exact A/B parity | Root/PT basis and all acceptance fields are compared exactly. | `dual_runner.py`; `convergence.py` | repeated/parity and mismatch tests | `root_pt_parity` artifact | CLOSED |
| Replay | Successful and failed Root/PT results/reasons/digests are comparison fields. | `replay_runner.py`; `REPLAY_COMPARISON_FIELDS` | successful and failed replay tests | matched/no mismatches | CLOSED |
| Hash/audit lineage | Root/PT aggregate entries retain prior hash and the bounded verification basis. | `audit_engine.py`; hash-chain appenders | complete lineage test | signed audit hash and Root/PT lineage | CLOSED |
| Desktop externality | Synthetic local SKG/DTN remain context providers; no live authority/service was activated. | runtime boundary/specification | static/runtime mode checks | `provider_mode=synthetic_local` | CLOSED / N/A LIVE |

## Runtime evidence lineage

The secret-free normal snapshot records:

| Field | Value |
|---|---|
| Request fingerprint | `cd84a2f696258fe3f24aa6014be5d6b4a7f1805fe593733ecac7b53e428598a8` |
| EIE digest | `6d4c48f5a9c296fb06e81681a148f0f2af57d17a082ae0951e23e2c997aae1f5` |
| Root-entry state hash | `2841221de4175426c693ec51ee051afadfb4b428cce86e23b26e790b6eef2507` |
| Collective signal digest | `f3d4917dd0050a58b7d52d09a749ed7c0ad8dc926b2a44cf1bf491b9b1d421e1` |
| Root result/reason | `PASS / root_of_trust_chain_complete` |
| Root evidence digest | `8eb173496557da6574e26007be643683394cdfe12161e2bd0569cd9820cc0940` |
| Source total/qualifying | `3 / 3` |
| Sufficiency | `SUFFICIENT` |
| Factors | `HS=2, IR=1, CI=1, FO=2` |
| Tier / corroboration | `MEDIUM / 3 required / 3 observed` |
| PT result/reason | `PASS / procedural_truth_certified` |
| PT evidence digest | `d8881488c40e547f722709dbef0798e53c040f204539ed250f0b5b90b57619a4` |
| A/B Root parity | `true` |
| A/B PT parity | `true` |
| Tier/corroboration parity | `true / true` |
| Near-match reconciliation | `false` |

Source files:

- `outputs/runtime/root_pt_runtime_evidence.json`
- `outputs/runtime/root_pt_parity_evidence.json`

Neither artifact contains a signing secret, signature blob, public key, private
token, credential or external-provider material.

## Verification lineage

| Gate | Result |
|---|---|
| Compile | Exit 0 |
| Focused | 77 passed in 21.02s |
| Directly affected | 167 passed in 101.07s |
| Full approved Windows suite | 1,951 passed, 7 skipped in 2,126.93s |
| Normal runtime | ALLOW / EXECUTE; convergence matched; token failures empty |
| Replay | 2 matched; zero mismatches |
| A/B parity | Initial/Root/PT/tier/corroboration exact; near-match false |
| Current test-local trust | Release integrity, capstone and adversarial harness PASS |
| Diff/metadata | `git diff --check` PASS; `main`; final clean status verified after commit |

The historical persisted Phase 18.7 generated bundle remains bound to its
original `f5ba5b2...` provenance and was not regenerated. Its direct stale
diagnostic is expected after later source commits. Current code was validated
with the repository-approved ephemeral trust-root bootstrap used by the full
suite and normal runtime.

## Closure and handoff

All entries in `docs/runtime/ROOT_PT_PASS4_GAP_CLOSURE_REGISTER.md` are closed.
There are zero unresolved Root gaps, zero unresolved PT gaps and zero owner
decisions in the authorised scope.

ARCHITECTURE CHANGED: NO

CANON CHANGED: NO

RUNTIME AUTHORITY OWNERSHIP CHANGED: NO

TRAVERSAL ORDER CHANGED: NO

SKG/DTN REMAIN EXTERNAL: YES

LIVE LINKAGE INTRODUCED: NO

CLOUD/NODES/MESH/QUORUM/DISTRIBUTED RUNTIME INTRODUCED: NO

NEAR-MATCH RECONCILIATION INTRODUCED: NO

PASS 4 STATUS: PASS / CLOSED

UNRESOLVED ROOT OF TRUST GAPS: 0

UNRESOLVED PROCEDURAL TRUTH GAPS: 0

READY FOR PASS 5: YES

The exact handoff is the certified PT state entering Classification. Pass 5
implementation was not started.
