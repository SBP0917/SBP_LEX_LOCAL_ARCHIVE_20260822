# Pilot Package Redaction And Sensitivity Register

Draft status: sensitivity planning register.

| Path or category | Sensitivity reason | Recommended handling | Risk if mishandled | Owner review required |
|---|---|---|---|---|
| `sbp_lex/phase19a/` | Implementation-sensitive translator/support code. | SUMMARY_ONLY unless raw source is approved. | Could expose implementation details outside intended review scope. | YES |
| `tests/test_phase19a_bounded_translator.py` | Test source shows implementation behavior and fixtures. | REDACT or include with owner approval. | Could reveal internal failure-mode construction. | YES |
| `sbp_lex/audit/` | Runtime audit implementation. | SUMMARY_ONLY. | Could imply runtime files are part of pilot content or invite edits. | YES |
| `sbp_lex/pipeline/replay_runner.py` | Runtime replay implementation. | SUMMARY_ONLY. | Could imply runtime traversal change authority. | YES |
| `sbp_oda/` | Support implementation; contains local support tooling. | SUMMARY_ONLY unless owner approves raw source. | Could be mistaken for runtime deployment assistant authority. | YES |
| `sbp_pvpl/` | Proof support implementation. | SUMMARY_ONLY unless owner approves raw source. | Could be mistaken for public publication activation. | YES |
| `sbp_simulation/` | Simulation implementation. | SUMMARY_ONLY unless owner approves raw source. | Could be mistaken for runtime decision authority. | YES |
| `docs/canonical_blueprint_series/` | Canon-candidate only, not owner-promoted final canon. | EXCLUDE or summary as candidate status only. | Could imply canon promotion. | YES |
| Patent-sensitive architecture descriptions | May contain protectable architecture framing. | HUMAN_REVIEW before external distribution. | Could disclose sensitive design before owner approval. | YES |
| Internal-only reports | May contain unresolved gaps or internal procedure notes. | HUMAN_REVIEW. | Could confuse reviewer with non-final internal material. | YES |
| Phase 19A and Phase 19B reports | Reviewer evidence. | INCLUDE. | Low if scope/exclusion docs accompany them. | NO |
| Fixture schemas and examples | Reviewer evidence. | INCLUDE. | Low if marked as implementation-alignment fixtures, not canon. | NO |
| `outputs/university_validation_dossier/` | Existing handoff outputs may need freshness review. | HUMAN_REVIEW. | Could include stale or incomplete handoff content. | YES |
| `outputs/release_integrity_bundle/` | Existing generated output bundle. | HUMAN_REVIEW. | Could imply current final release package. | YES |
| `runtime_artifacts/` | Generated local test/runtime outputs. | EXCLUDE. | Could include transient environment-specific data. | YES |
| `baselines/` | Historical archive/source-lineage material. | EXCLUDE. | Could reintroduce old or stale material as active evidence. | YES |
| Missing originals | Not present in repo. | EXCLUDE. | Could create unsupported authority claims. | YES |
| Cache, bytecode, `.pytest_cache/`, `__pycache__/`, `*.pyc` | Generated noise. | EXCLUDE. | Repository/package pollution. | NO |

## Handling Summary

Safe for review: Phase reports, Phase 19B scope/evidence docs, fixture schemas,
fixture examples, and boundary/exclusion registers.

Summary instead of raw inclusion: implementation code, runtime audit/replay
files, ODA/PVPL/SIM source packages, and sensitive architecture descriptions.

Excluded entirely: baselines, missing originals as authority, generated runtime
artifacts, caches, bytecode, and production/public deployment claims.
