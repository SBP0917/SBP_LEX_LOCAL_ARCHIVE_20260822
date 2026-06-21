# Phase 18 Procedural Truth Binding Report

## Scope completed

Phase 18 adds deterministic Procedural Truth evidence binding during canonical state construction. The implementation records admitted pre-context evidence, anchors it through Root of Trust, evaluates it under the existing locked thresholds, exposes PT-only outcomes, and preserves replay and audit evidence.

## Files changed

- `sbp_lex/governance/procedural_truth_envelope.py` — PT envelope construction, qualification, digest, and integrity validation.
- `sbp_lex/shared/state_builder.py` — records the PT envelope and digest without deciding PT outcome.
- `sbp_lex/pipeline/runner.py` — passes already-admitted pre-context metadata to State Builder and records the envelope digest in state-construction evidence.
- `sbp_lex/authority_first/root_of_trust_runner.py` — creates the canonical Root of Trust evidence anchor.
- `sbp_lex/authority_first/truth_anchor_engine.py` — includes admitted package and PT envelope digests in truth anchorage.
- `sbp_lex/governance/evidence_engine.py` — consumes and validates envelope source records.
- `sbp_lex/governance/threshold_conditioning_engine.py` — detects tier substitution and threshold relaxation.
- `sbp_lex/governance/corroboration_engine.py` — counts only qualifying envelope sources.
- `sbp_lex/governance/procedural_truth_engine.py` — emits deterministic PT-only outcomes and failure reasons.
- `sbp_lex/governance/procedural_truth_runner.py` — locks PT failure to non-executable controlled re-entry requirements.
- `sbp_lex/audit/audit_engine.py` — records PT binding and provenance evidence.
- `sbp_lex/pipeline/replay_runner.py` — compares PT outcome and envelope digest during replay.
- `tests/test_phase_18_procedural_truth_binding.py` — 20 focused Phase 18 tests.
- `docs/PROCEDURAL_TRUTH_BINDING_DURING_STATE_CONSTRUCTION.md` — architecture and behaviour documentation.
- `reports/PHASE_18_PROCEDURAL_TRUTH_BINDING_REPORT.md` — this report.

## Implemented behaviour

The envelope records all required request, substrate, pre-context, provenance, validation-status, threshold, qualifying-count, and deterministic-failure fields. Root of Trust signs their canonical digest chain from inside SBP-LEX. Procedural Truth recomputes locked TOP/MEDIUM/LOW requirements and emits `PT_PASS`, `PT_REFINE`, `PT_ESCALATE`, or `PT_FAIL` while retaining legacy PASS/FAIL compatibility for existing downstream gates.

PT failure halts execution and records that corrected evidence, corrected source package, corrected validation state, and full retraversal are mandatory. No automatic re-entry is available.

## Tests added

Twenty focused tests cover all three passing thresholds, insufficient-source outcomes, exclusion of stale/unattested/inconsistent/unverified sources, downgrade protection, digest preservation, Root of Trust anchorage, deterministic replay, non-executable failure, controlled re-entry requirements, external SKG/DTN boundaries, and absence of external Governance or execution permission output.

## Verification results

- `python -m compileall -q .` — PASS using Python 3.12.13. The interpreter reported that the access-restricted `.pytest_cache` directory could not be listed; source compilation completed with exit code 0.
- `python -m pytest -q` — PASS, 128 tests. One environmental warning reported that pytest could not write its cache under the access-restricted working copy.
- `scripts\run_tests.bat` — PASS, 128 tests.
- `python main.py` — PASS: `ALLOW`, `EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, no token failures.
- `python main.py replay` — PASS: two runs matched with identical `PT_PASS` outcome and PT envelope digest; no mismatches.
- `git diff --check` — PASS; only Git's informational LF-to-CRLF working-copy warnings were emitted.
- `git diff --stat` — 11 tracked files changed, 114 insertions and 20 deletions; four new files are also present and listed above.
- `git status --short` — expected Phase 18 modifications only; no UI or external-substrate source changes.
- prohibited-topology search — no matches in active `sbp_lex` or `external_substrates` Python source (test-only locked-term assertions remain).
- external import search — no `sbp_lex` imports in `external_substrates`.

## Authority boundary confirmation

No external-substrate file was changed. No `sbp_lex` import was introduced into `external_substrates`. SKG, DTN, and the bridge remain external and non-authoritative. External packages do not emit Governance results or execution permission. Hard Entry Gate is not bypassed, direct runtime injection was not added, and canonical SBP-LEX Root of Trust remains authoritative.

Desktop V1 remains local/private, the Dual Adaptive Deterministic Pipelines remain preserved, and no UI work was started. No cloud, APK, node, quorum, mesh, multi-node, or distributed-runtime capability was introduced.
