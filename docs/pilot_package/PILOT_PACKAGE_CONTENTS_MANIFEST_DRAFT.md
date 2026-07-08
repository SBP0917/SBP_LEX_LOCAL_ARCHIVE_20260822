# Pilot Package Contents Manifest Draft

Draft status: proposed contents only.

| Path | Artifact type | Reason for inclusion | Evidence role | External review suitability | Sensitivity level | Owner review required | Notes |
|---|---|---|---|---|---|---|---|
| `docs/phase19b/PHASE19B_SCOPE_LOCK.md` | Scope document | Defines Phase 19B boundary | Scope proof | YES | LOW | NO | Include early in package. |
| `docs/phase19b/PHASE19B_EVIDENCE_PACKAGE_MANIFEST.md` | Manifest | Evidence map | Evidence index | YES | LOW | NO | Central evidence map. |
| `docs/phase19b/PHASE19B_VALIDATION_EVIDENCE_INDEX.md` | Claims index | Claim-to-evidence map | Validation proof | YES | LOW | NO | Reviewer guide to claims. |
| `docs/phase19b/PHASE19B_EVIDENCE_EXCLUSION_REGISTER.md` | Exclusion register | Prevents drift | Exclusion proof | YES | LOW | NO | Include to show what is not claimed. |
| `docs/phase19b/PHASE19B_OWNER_REVIEW_RESOLUTION_LOG.md` | Owner record | Shows owner approvals | Approval proof | YES | LOW | NO | Confirms preparation may proceed. |
| `reports/PHASE19B_OWNER_REVIEW_01_REPORT.md` | Report | Owner review summary | Approval proof | YES | LOW | NO | Include with Phase 19B report set. |
| `reports/PHASE19B_EVIDENCE_PACKAGE_01_REPORT.md` | Report | Evidence package summary | Evidence proof | YES | LOW | NO | Include. |
| `reports/PHASE19B_SCOPE_LOCK_01_REPORT.md` | Report | Scope lock summary | Boundary proof | YES | LOW | NO | Include. |
| `reports/PHASE19A_OWNER_CLOSURE_01_REPORT.md` | Report | Phase 19A closure | Closure proof | YES | LOW | NO | Include. |
| `reports/PHASE19A_IMPLEMENTATION_01_REPORT.md` | Report | Initial Phase 19A implementation | Implementation proof | YES | LOW | NO | Include. |
| `reports/PHASE19A_IMPLEMENTATION_02_REPORT.md` | Report | Expanded failure coverage | Implementation proof | YES | LOW | NO | Include. |
| `reports/PHASE19A_POSTBASELINE_REVIEW_01_REPORT.md` | Report | Closure readiness | Review proof | YES | LOW | NO | Include. |
| `fixtures/phase19a/README.md` | Fixture guide | Explains fixtures | Fixture context | YES | LOW | NO | Include. |
| `fixtures/phase19a/failure_mode_cases.json` | Fixture register | Failure-mode evidence | Failure proof | YES | LOW | NO | Include. |
| `fixtures/phase19a/schemas/` | Schema set | Fixture validation shape | Schema proof | YES | LOW | NO | Include. |
| `fixtures/phase19a/examples/` | Examples | Positive/negative examples | Fixture proof | YES | LOW | NO | Include. |
| `tests/test_phase19a_bounded_translator.py` | Test source | Executable evidence reference | Test proof | REDACT | MEDIUM | YES | Summary recommended unless owner approves raw source. |
| `sbp_lex/phase19a/` | Support implementation | Translator/evidence helper reference | Implementation proof | SUMMARY_ONLY | HIGH | YES | Summarise; raw inclusion requires owner approval. |
| `reports/ODA_02_EVIDENCE_GRADE_ONSITE_DEPLOYMENT_ASSISTANT_REPORT.md` | Report | ODA support boundary | Support proof | YES | LOW | NO | Include as detached support evidence. |
| `reports/PVPL_02_EVIDENCE_GRADE_LOCAL_PROOF_LAYER_REPORT.md` | Report | PVPL proof boundary | Proof support | YES | LOW | NO | Include as detached proof evidence. |
| `reports/SIM_03_FAILURE_TAMPER_REPLAY_PARITY_MATRIX_REPORT.md` | Report | Failure/tamper/replay evidence | Simulation evidence | YES | LOW | NO | Include with limitation notes. |
| `reports/BASELINE_01_EVIDENCE_SPINE_PRE_PHASE19A_REPORT.md` | Report | Evidence spine baseline | Baseline proof | YES | LOW | NO | Include. |
| `outputs/university_validation_dossier/` | Existing dossier outputs | Reviewer handoff context | Handoff support | HUMAN_REVIEW | MEDIUM | YES | Review before inclusion; do not regenerate here. |
| `outputs/release_integrity_bundle/` | Existing output bundle | Integrity context | Integrity support | HUMAN_REVIEW | MEDIUM | YES | Review before inclusion; do not regenerate here. |
| `docs/pilot_package/` | Preparation docs | Pilot package planning | Assembly planning | YES | LOW | NO | Include after owner approval. |
| `baselines/` | Archive tree | None for active package | Excluded | NO | HIGH | YES | Exclude. |
| `runtime_artifacts/` | Generated artifacts | None unless selected later | Generated evidence | NO | HUMAN_REVIEW | YES | Exclude unless separately approved. |
