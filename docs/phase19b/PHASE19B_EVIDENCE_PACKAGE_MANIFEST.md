# PHASE19B Evidence Package Manifest

Draft status: local/private Phase 19B evidence package map.

This manifest organises existing evidence only. It does not create a final pilot
package, activate runtime traversal, promote canon, or grant authority to
support layers.

## Included Evidence Artifacts

| Path | Artifact type | Source phase | Evidence role | Validation relevance | Pilot-package relevance | Status | Notes |
|---|---|---|---|---|---|---|---|
| `reports/PHASE19A_OWNER_CLOSURE_01_REPORT.md` | Closure report | Phase 19A | Phase closure proof | High | High | INCLUDED | Records Phase 19A closed under bounded Desktop V1 scope. |
| `reports/PHASE19A_POSTBASELINE_REVIEW_01_REPORT.md` | Review report | Phase 19A | Closure readiness proof | High | High | INCLUDED | Confirms no technical Implementation 03 gap. |
| `reports/PHASE19A_IMPLEMENTATION_01_REPORT.md` | Implementation report | Phase 19A | Initial translator/fixture proof | High | High | INCLUDED | Records 10 Phase 19A tests, full validation, and raw package boundary. |
| `reports/PHASE19A_IMPLEMENTATION_02_REPORT.md` | Implementation report | Phase 19A | Expanded failure-mode proof | High | High | INCLUDED | Records 17 Phase 19A tests and detached evidence summary support. |
| `reports/PHASE19A_OPEN_01_PREFLIGHT_REPORT.md` | Preflight report | Phase 19A | Pre-implementation gap map | Medium | Medium | INCLUDED | Useful for showing why Phase 19A was bounded. |
| `reports/PHASE19B_OPEN_01_PREFLIGHT_REPORT.md` | Preflight report | Phase 19B | Phase 19B opening proof | High | High | INCLUDED | Shows owner-definition need and safe scope candidate. |
| `reports/PHASE19B_SCOPE_LOCK_01_REPORT.md` | Scope-lock report | Phase 19B | Phase 19B scope proof | High | High | INCLUDED | Locks evidence/pilot-package preparation only. |
| `docs/phase19b/PHASE19B_SCOPE_LOCK.md` | Scope document | Phase 19B | Scope boundary | High | High | INCLUDED | Defines Phase 19B as non-runtime expansion. |
| `docs/phase19b/PHASE19B_ELIGIBLE_ARTIFACTS_REGISTER.md` | Artifact register | Phase 19B | Eligibility control | High | High | INCLUDED | Establishes YES/NO/HUMAN_REVIEW artifact status. |
| `docs/phase19b/PHASE19B_PROHIBITED_EXPANSION_LIST.md` | Prohibition register | Phase 19B | Drift prevention | High | High | INCLUDED | Blocks runtime, topology, support-authority, and canon drift. |
| `docs/phase19b/PHASE19B_OWNER_DECISION_REGISTER.md` | Decision register | Phase 19B | Owner-control queue | High | High | INCLUDED | Keeps remaining owner decisions visible. |
| `fixtures/phase19a/README.md` | Fixture guide | Phase 19A | Fixture orientation | Medium | High | INCLUDED | Explains fixture package use. |
| `fixtures/phase19a/failure_mode_cases.json` | Failure-mode register | Phase 19A | Failure coverage list | High | High | INCLUDED | Enumerates covered failure cases. |
| `fixtures/phase19a/schemas/eie.schema.json` | Schema | Phase 19A | EIE fixture proof | High | Medium | INCLUDED | Demonstrates EIE fixture shape. |
| `fixtures/phase19a/schemas/skg_readiness.schema.json` | Schema | Phase 19A | SKG readiness proof | High | Medium | INCLUDED | Non-authoritative readiness evidence only. |
| `fixtures/phase19a/schemas/dtn_readiness.schema.json` | Schema | Phase 19A | DTN readiness proof | High | Medium | INCLUDED | Non-authoritative contextual evidence only. |
| `fixtures/phase19a/schemas/external_pre_context_package.schema.json` | Schema | Phase 19A | External package boundary | High | Medium | INCLUDED | Shows external package shape without self-traversal. |
| `fixtures/phase19a/schemas/runtime_pre_context_signals.schema.json` | Schema | Phase 19A | Runtime-local signal shape | High | Medium | INCLUDED | Supports Hard Entry signal validation explanation. |
| `fixtures/phase19a/examples/eie_valid.json` | Example fixture | Phase 19A | Valid EIE example | Medium | Medium | INCLUDED | Reviewer-friendly sample evidence. |
| `fixtures/phase19a/examples/eie_malformed.json` | Example fixture | Phase 19A | Negative EIE example | Medium | Medium | INCLUDED | Demonstrates malformed EIE case. |
| `fixtures/phase19a/examples/eie_stale.json` | Example fixture | Phase 19A | Negative EIE example | Medium | Medium | INCLUDED | Demonstrates stale EIE case. |
| `fixtures/phase19a/examples/eie_unbound.json` | Example fixture | Phase 19A | Negative EIE example | Medium | Medium | INCLUDED | Demonstrates unbound EIE case. |
| `fixtures/phase19a/examples/detached_evidence_summary_shape.json` | Example fixture | Phase 19A | Detached summary shape | High | High | INCLUDED | ODA/PVPL/SIM-readable support evidence shape. |
| `tests/test_phase19a_bounded_translator.py` | Test file | Phase 19A | Executable evidence | High | High | INCLUDED | Proves translator boundary, failure modes, support-only boundaries, and Domain Wrap order. |
| `sbp_lex/phase19a/pre_context_translator.py` | Support code | Phase 19A | Read-only implementation evidence | High | Medium | HUMAN_REVIEW | Include as read-only evidence reference; do not modify in Phase 19B. |
| `sbp_lex/phase19a/fixtures.py` | Support code | Phase 19A | Read-only fixture helper evidence | High | Medium | HUMAN_REVIEW | Include as read-only evidence reference; do not modify in Phase 19B. |
| `sbp_lex/phase19a/evidence_summary.py` | Support code | Phase 19A | Detached summary helper evidence | High | High | HUMAN_REVIEW | Read-only; generating new summaries requires owner permission. |
| `reports/ODA_02_EVIDENCE_GRADE_ONSITE_DEPLOYMENT_ASSISTANT_REPORT.md` | ODA report | ODA-02 | Support-only proof | Medium | High | INCLUDED | ODA is local support only with `runtime_authority: NONE`. |
| `reports/PVPL_02_EVIDENCE_GRADE_LOCAL_PROOF_LAYER_REPORT.md` | PVPL report | PVPL-02 | Local proof-layer proof | High | High | INCLUDED | PVPL is local/private and publication-inactive. |
| `reports/SIM_01_CONTROLLED_SIMULATION_HARNESS_REPORT.md` | SIM report | SIM-01 | Simulation harness evidence | Medium | Medium | INCLUDED | Support-only simulation evidence. |
| `reports/SIM_02_CONTROLLED_SCENARIO_LIBRARY_REPORT.md` | SIM report | SIM-02 | Scenario library evidence | Medium | Medium | INCLUDED | Local scenario evidence only. |
| `reports/SIM_03_FAILURE_TAMPER_REPLAY_PARITY_MATRIX_REPORT.md` | SIM report | SIM-03 | Failure/tamper/replay matrix evidence | High | High | INCLUDED | Artifact-level evidence; runtime-level claims remain limited. |
| `reports/BASELINE_01_EVIDENCE_SPINE_PRE_PHASE19A_REPORT.md` | Baseline report | Baseline-01 | Evidence spine | High | High | INCLUDED | Ties ODA/PVPL/SIM/PQC evidence before Phase 19A. |
| `reports/PHASE_IMPLEMENTATION_RECONCILIATION_AUDIT.md` | Reconciliation report | Audit | Phase trace | Medium | High | INCLUDED | Useful for phase-to-artifact mapping. |
| `reports/PHASE_18_5_PRE_ACTIVATION_AUTHORITY_BOUNDARY_AUDIT.md` | Authority report | Phase 18.5 | Boundary evidence | High | Medium | INCLUDED | Supports no runtime-authority expansion claims. |
| `reports/PHASE_18_6_HISTORICAL_AUDIT_MUTATION_ATTACK_REPORT.md` | Audit security report | Phase 18.6 | Audit mutation evidence | Medium | Medium | INCLUDED | Audit/replay proof support. |
| `reports/PHASE_18_7D_LOCAL_EVIDENCE_CHAIN_REPORT.md` | Local evidence report | Phase 18.7D | Evidence chain support | Medium | Medium | INCLUDED | Local/private evidence only. |
| `reports/PHASE_18_7F_RELEASE_INTEGRITY_PACKAGE_REPORT.md` | Release integrity report | Phase 18.7F | Integrity support | Medium | Medium | INCLUDED | Local release integrity evidence. |
| `reports/PHASE_18_8_UNIVERSITY_VALIDATION_DOSSIER_REPORT.md` | Dossier report | Phase 18.8 | Handoff evidence | Medium | High | INCLUDED | Existing dossier evidence; do not rewrite in this pass. |
| `sbp_lex/audit/audit_engine.py` | Runtime audit file | Existing runtime | Read-only audit proof reference | Medium | Medium | HUMAN_REVIEW | Inspect only; no modification allowed. |
| `sbp_lex/pipeline/replay_runner.py` | Runtime replay file | Existing runtime | Read-only replay proof reference | Medium | Medium | HUMAN_REVIEW | Inspect only; no modification allowed. |
| `sbp_pvpl/` | Support package | PVPL-02 | Local proof support | Medium | High | HUMAN_REVIEW | CLI generation requires owner permission; remains detached. |
| `sbp_oda/` | Support package | ODA-02 | Local support explanation | Medium | High | HUMAN_REVIEW | CLI generation requires owner permission; remains detached. |
| `sbp_simulation/` | Support package | SIM-01/02/03 | Local simulation evidence | Medium | Medium | HUMAN_REVIEW | CLI generation requires owner permission; remains detached. |

## Excluded / Restricted Evidence

| Path or category | Artifact type | Source phase | Evidence role | Validation relevance | Pilot-package relevance | Status | Notes |
|---|---|---|---|---|---|---|---|
| `baselines/` | Archive/source-lineage tree | Historical | Archive only | Low | Low | EXCLUDED | Untracked; do not include as active evidence. |
| Missing originals | Missing source material | Historical | None | Unknown | Unknown | EXCLUDED | Must not be reconstructed or used as authority. |
| `docs/canonical_blueprint_series/` | Canon candidate docs | Blueprint control | Reference only | Medium | Medium | EXCLUDED | Not owner-promoted; do not modify or promote. |
| `runtime_artifacts/` | Generated artifacts | Tests/runs | Generated local outputs | Variable | Variable | EXCLUDED | Do not include unless owner explicitly approves a generated-output baseline. |
| Production/public deployment claims | Claim category | Future | Out of scope | None | None | EXCLUDED | Phase 19B is not deployment readiness. |
| Future-node/distributed material | Future topology | Future | Out of scope | None | None | EXCLUDED | No nodes, quorum, distributed governance, or cloud runtime. |
