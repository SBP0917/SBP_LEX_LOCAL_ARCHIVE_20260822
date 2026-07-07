# PHASE19B Pilot Package Preparation Register

Draft status: preparation register only.

This register identifies material that could belong in a later local/private
pilot-package assembly task. It does not create the final pilot package and does
not imply deployment activation.

| Artifact | Why it belongs in pilot package | Safe for external review | Contains implementation-sensitive material | Redact or summarise | Owner review required | Notes |
|---|---|---|---|---|---|---|
| `reports/PHASE19A_OWNER_CLOSURE_01_REPORT.md` | Establishes Phase 19A closed scope | YES | NO | NO | NO | Strong handoff anchor. |
| `reports/PHASE19A_POSTBASELINE_REVIEW_01_REPORT.md` | Explains closure readiness and no Implementation 03 need | YES | NO | NO | NO | Useful reviewer context. |
| `reports/PHASE19A_IMPLEMENTATION_01_REPORT.md` | Explains first translator/fixture implementation | YES | LOW | NO | NO | Contains command/test history. |
| `reports/PHASE19A_IMPLEMENTATION_02_REPORT.md` | Explains expanded failure coverage | YES | LOW | NO | NO | Contains command/test history. |
| `reports/PHASE19B_OPEN_01_PREFLIGHT_REPORT.md` | Shows Phase 19B was opened cautiously | YES | NO | NO | NO | Good drift-control evidence. |
| `reports/PHASE19B_SCOPE_LOCK_01_REPORT.md` | Shows evidence-only scope lock | YES | NO | NO | NO | Good boundary evidence. |
| `docs/phase19b/PHASE19B_SCOPE_LOCK.md` | Defines pilot/evidence-only scope | YES | NO | NO | NO | Include in preparation bundle. |
| `docs/phase19b/PHASE19B_EVIDENCE_PACKAGE_MANIFEST.md` | Central evidence map | YES | NO | NO | YES | Owner should approve before final package assembly. |
| `docs/phase19b/PHASE19B_VALIDATION_EVIDENCE_INDEX.md` | Claim-to-evidence map | YES | NO | NO | YES | Owner should approve before final package assembly. |
| `fixtures/phase19a/README.md` | Fixture orientation | YES | NO | NO | NO | Reviewer-friendly. |
| `fixtures/phase19a/failure_mode_cases.json` | Failure-mode list | YES | NO | NO | NO | Include as evidence index, not runtime input. |
| `fixtures/phase19a/schemas/` | Fixture schema set | YES | LOW | NO | NO | Implementation-alignment schemas only. |
| `fixtures/phase19a/examples/` | Example fixtures | YES | LOW | NO | NO | Safe if presented as examples only. |
| `tests/test_phase19a_bounded_translator.py` | Executable validation evidence | YES | MEDIUM | SUMMARISE OPTIONAL | YES | Include as source evidence only if owner approves code exposure. |
| `sbp_lex/phase19a/` | Phase 19A support implementation | HUMAN_REVIEW | MEDIUM | SUMMARISE RECOMMENDED | YES | Do not package source externally unless owner approves. |
| `reports/ODA_02_EVIDENCE_GRADE_ONSITE_DEPLOYMENT_ASSISTANT_REPORT.md` | Shows local support assistant boundary | YES | LOW | NO | NO | Include as report evidence. |
| `sbp_oda/` | ODA support implementation | HUMAN_REVIEW | MEDIUM | SUMMARISE RECOMMENDED | YES | Source inclusion needs owner approval. |
| `reports/PVPL_02_EVIDENCE_GRADE_LOCAL_PROOF_LAYER_REPORT.md` | Shows local proof layer boundary | YES | LOW | NO | NO | Include as report evidence. |
| `sbp_pvpl/` | PVPL support implementation | HUMAN_REVIEW | MEDIUM | SUMMARISE RECOMMENDED | YES | Source inclusion or generated bundles need owner approval. |
| `reports/SIM_03_FAILURE_TAMPER_REPLAY_PARITY_MATRIX_REPORT.md` | Shows failure/tamper/replay evidence boundary | YES | LOW | NO | NO | Include as report evidence. |
| `sbp_simulation/` | SIM support implementation | HUMAN_REVIEW | MEDIUM | SUMMARISE RECOMMENDED | YES | Source inclusion needs owner approval. |
| `reports/BASELINE_01_EVIDENCE_SPINE_PRE_PHASE19A_REPORT.md` | Evidence spine across ODA/PVPL/SIM/PQC | YES | LOW | NO | NO | Include as context. |
| `outputs/university_validation_dossier/` | Existing reviewer dossier outputs | HUMAN_REVIEW | LOW | REVIEW FIRST | YES | Do not update or final-package yet. |
| `outputs/release_integrity_bundle/` | Existing release integrity outputs | HUMAN_REVIEW | LOW | REVIEW FIRST | YES | Do not regenerate in this pass. |
| `runtime_artifacts/` | Generated local outputs | NO | VARIABLE | EXCLUDE | YES | Exclude unless owner explicitly selects artifacts. |
| `baselines/` | Archive/source-lineage tree | NO | VARIABLE | EXCLUDE | YES | Not active evidence and untracked. |

## Preparation Status

Pilot-package preparation status: PREPARATION_REGISTER_CREATED.

Final pilot-package assembly status: NOT_STARTED.

Final pilot-package assembly may begin only after owner approval of this
register and the evidence package manifest.
