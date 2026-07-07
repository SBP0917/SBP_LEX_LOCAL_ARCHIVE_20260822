# PHASE19B Eligible Artifacts Register

Draft status: Phase 19B scope-lock register.

Phase 19B may use artifacts only for local/private validation, evidence
packaging, pilot-package preparation, and proof/report organisation. Eligibility
does not grant runtime authority.

| Path | Type | Status | Eligible for Phase 19B | Pilot-package relevance | Evidence-package relevance | Notes |
|---|---|---|---|---|---|---|
| `reports/PHASE19B_OPEN_01_PREFLIGHT_REPORT.md` | Phase 19B preflight report | Present | YES | High | High | Establishes preflight finding and owner-definition need. |
| `reports/PHASE19A_OWNER_CLOSURE_01_REPORT.md` | Phase 19A closure report | Present | YES | High | High | Records Phase 19A closed state and Phase 19B opening condition. |
| `reports/PHASE19A_POSTBASELINE_REVIEW_01_REPORT.md` | Phase 19A post-baseline review | Present | YES | High | High | Confirms no technical Implementation 03 gap. |
| `reports/PHASE19A_IMPLEMENTATION_01_REPORT.md` | Phase 19A implementation report | Present | YES | High | High | Records translator, fixtures, and initial tests. |
| `reports/PHASE19A_IMPLEMENTATION_02_REPORT.md` | Phase 19A implementation report | Present | YES | High | High | Records expanded failure coverage and detached summary. |
| `reports/PHASE19A_OPEN_01_PREFLIGHT_REPORT.md` | Phase 19A preflight report | Present | YES | Medium | High | Useful for source-to-implementation trace. |
| `fixtures/phase19a/README.md` | Fixture guide | Present | YES | High | High | Phase 19A fixture entry point. |
| `fixtures/phase19a/failure_mode_cases.json` | Failure-mode fixture register | Present | YES | High | High | Evidence of bounded failure-mode library. |
| `fixtures/phase19a/schemas/eie.schema.json` | EIE fixture schema | Present | YES | Medium | High | Evidence package schema only. |
| `fixtures/phase19a/schemas/skg_readiness.schema.json` | SKG readiness schema | Present | YES | Medium | High | Non-authoritative readiness schema. |
| `fixtures/phase19a/schemas/dtn_readiness.schema.json` | DTN readiness schema | Present | YES | Medium | High | Non-authoritative contextual schema. |
| `fixtures/phase19a/schemas/external_pre_context_package.schema.json` | External package schema | Present | YES | Medium | High | Used to explain external package boundary. |
| `fixtures/phase19a/schemas/runtime_pre_context_signals.schema.json` | Runtime-local signal schema | Present | YES | Medium | High | Used to explain validated local signal shape. |
| `fixtures/phase19a/examples/eie_valid.json` | EIE example | Present | YES | Medium | High | Valid EIE fixture. |
| `fixtures/phase19a/examples/eie_malformed.json` | EIE failure example | Present | YES | Medium | High | Failure evidence. |
| `fixtures/phase19a/examples/eie_stale.json` | EIE failure example | Present | YES | Medium | High | Failure evidence. |
| `fixtures/phase19a/examples/eie_unbound.json` | EIE failure example | Present | YES | Medium | High | Failure evidence. |
| `fixtures/phase19a/examples/detached_evidence_summary_shape.json` | Detached summary example | Present | YES | High | High | ODA/PVPL/SIM-readable support shape. |
| `tests/test_phase19a_bounded_translator.py` | Phase 19A regression tests | Present | YES | Medium | High | May be cited or rerun; do not modify unless a later task permits tests. |
| `sbp_lex/phase19a/pre_context_translator.py` | Phase 19A support code | Present | HUMAN_REVIEW | Medium | High | Read-only evidence source for Phase 19B unless owner allows code changes. |
| `sbp_lex/phase19a/fixtures.py` | Phase 19A support code | Present | HUMAN_REVIEW | Medium | High | Read-only evidence source for Phase 19B unless owner allows code changes. |
| `sbp_lex/phase19a/evidence_summary.py` | Detached evidence helper | Present | HUMAN_REVIEW | High | High | May inform summaries; direct new execution or output generation needs owner scope. |
| `reports/ODA_02_EVIDENCE_GRADE_ONSITE_DEPLOYMENT_ASSISTANT_REPORT.md` | ODA report | Present | YES | High | Medium | Support-only; no runtime authority. |
| `sbp_oda/` | ODA support package | Present | HUMAN_REVIEW | High | Medium | CLI use or generated outputs require explicit owner scope. |
| `reports/PVPL_02_EVIDENCE_GRADE_LOCAL_PROOF_LAYER_REPORT.md` | PVPL report | Present | YES | High | High | Local/private proof only; publication inactive. |
| `sbp_pvpl/` | PVPL support package | Present | HUMAN_REVIEW | High | High | CLI use or generated outputs require explicit owner scope. |
| `reports/SIM_01_CONTROLLED_SIMULATION_HARNESS_REPORT.md` | SIM report | Present | YES | Medium | High | Support/evidence-only simulation material. |
| `reports/SIM_02_CONTROLLED_SCENARIO_LIBRARY_REPORT.md` | SIM report | Present | YES | Medium | High | Scenario evidence source. |
| `reports/SIM_03_FAILURE_TAMPER_REPLAY_PARITY_MATRIX_REPORT.md` | SIM report | Present | YES | Medium | High | Failure/tamper/replay evidence source. |
| `sbp_simulation/` | Simulation support package | Present | HUMAN_REVIEW | Medium | High | CLI use or generated outputs require explicit owner scope. |
| `reports/BASELINE_01_EVIDENCE_SPINE_PRE_PHASE19A_REPORT.md` | Evidence spine report | Present | YES | High | High | Useful evidence spine input. |
| `reports/PHASE_IMPLEMENTATION_RECONCILIATION_AUDIT.md` | Reconciliation audit | Present | YES | High | High | Phase-to-artifact trace input. |
| `outputs/university_validation_dossier/` | University handoff outputs | Present | HUMAN_REVIEW | High | High | Existing handoff evidence; updating dossier needs later explicit task. |
| `outputs/release_integrity_bundle/` | Release integrity bundle | Present | HUMAN_REVIEW | Medium | High | Existing output evidence; do not regenerate or commit changes without owner scope. |
| `outputs/local_evidence_chain.json` | Local evidence chain | Present | HUMAN_REVIEW | Medium | High | Existing output evidence; verify before packaging if used. |
| `outputs/local_trust_root_manifest.json` | Local trust manifest | Present | HUMAN_REVIEW | Medium | High | Existing output evidence; verify before packaging if used. |
| `runtime_artifacts/` | Generated test/runtime artifacts | Present | HUMAN_REVIEW | Low | Medium | Generated artifacts are not commit candidates unless explicitly selected. |
| `baselines/` | Baseline archive material | Untracked/present | NO | Low | Low | Do not use as active authority or commit without owner instruction. |
| `docs/canonical_blueprint_series/` | Canon candidate documents | Present | NO | Medium | Medium | Do not modify or promote during Phase 19B scope lock. |
| `main.py` | Runtime entry point | Present | NO | None | Low | Runtime code is prohibited from Phase 19B scope-lock modification. |
| `sbp_lex/pipeline/runner.py` | Runtime traversal runner | Present | NO | None | Low | Runtime traversal is prohibited from Phase 19B scope-lock modification. |

## Register Notes

- `YES` means the artifact may be referenced, indexed, summarised, or packaged
  as existing evidence under Phase 19B.
- `HUMAN_REVIEW` means the artifact may be relevant, but direct use,
  regeneration, command execution, or inclusion in a pilot package needs owner
  confirmation.
- `NO` means the artifact must not be modified, activated, promoted, or used as
  active authority in Phase 19B.
