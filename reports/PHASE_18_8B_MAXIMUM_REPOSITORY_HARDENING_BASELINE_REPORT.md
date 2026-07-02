# Phase 18.8B Maximum Repository Hardening Baseline Report

## Baseline Identity

- Phase identifier: 18.8B
- Repository: `SBP0917/SBP_LEX_DUAL_V6`
- Branch: `main`
- Remote: `https://github.com/SBP0917/SBP_LEX_DUAL_V6.git`
- Commit base before work: `67ee3176ad068558567b54dd029ee3d4df70a7ff`
- Recommended commit message: `Phase 18.8B repository hardening blueprint and dossier update`

## Files Changed

- Runtime/control-chain hardening files under `sbp_lex/`.
- Focused negative tests under `tests/test_phase_18_8b_repository_hardening.py`.
- Canonical blueprint series under `docs/canonical_blueprint_series/`.
- Blueprint addenda status wording under `docs/blueprint_addenda/`.
- University dossier generator and generated dossier outputs.
- Reports under `reports/`.

## Hardening Implemented

- Shared EIE/SKG/DTN/Root control-chain validator.
- Explicit canonical EIE digest semantics.
- Root-bound state hash preservation.
- Root pre-anchor validation.
- Canonical upstream EIE/SKG/DTN/Root validation.
- Execution Gate independent control-chain validation.
- Expanded audit/replay metadata.
- Dossier positive overclaim detection.
- 13-document blueprint series.

## Tests Added / Updated

- Added `tests/test_phase_18_8b_repository_hardening.py`.
- Updated dossier tests through generator changes.
- Existing EIE/PT and Execution Gate tests remain active.

## Validation Results

Final validation results:

- Compile result: PASS, `python -m compileall .`, exit code 0.
- Full-suite result: PASS, `605 passed in 206.11s (0:03:26)`.
- `git diff --check` result: PASS, exit code 0; only Windows LF-to-CRLF working-copy notices were emitted.

## Remaining Repository Limitations

- Local deterministic signatures are not hardware-backed.
- Local SKG/DTN metadata is non-authoritative.
- Local audit/replay does not provide external custody.
- Adapter coverage remains repository-local.

## External-Production Readiness Requirements

See `reports/PHASE_18_8B_EXTERNAL_PRODUCTION_READINESS_GAP_REPORT.md`.

## University Handover Impact

The repository is stronger for university technical review because 18.8B adds fail-closed local negative tests, explicit blueprint alignment, and clearer separation between local hardening and external production requirements.

## Canonical Blueprint Status

- All 13 canonical blueprint documents exist: yes.
- Index current: yes.
- Source/supersession map current: yes.
- Blueprint documents created: all 13 plus index and map.
- Blueprint documents updated: older addenda marked as repository-side implementation alignment material pending owner canonisation.
- University dossier references the 13-document series: yes, via generator and artifact index.
- Dossier regenerated after hardening: yes, `VALIDATION_DOSSIER_READY`.
- Dossier includes Phase 18.8B hardening evidence: yes.
- Dossier includes external-production gap requirements: yes.
- Final validation after documentation/dossier update: PASS.

## Commit Decision

Local baseline should be committed only after final validation passes.
