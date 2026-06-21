# Phase 18.5 Pre-Activation Authority Boundary Audit

## Scope

This pass audits and hardens the Phase 18 authority boundary before any later runtime-activation phase. It adds no automatic submission, traversal trigger, external authority path, UI work, or Phase 19 capability.

## Files inspected

- Hard Entry and canonical pipeline: `sbp_lex/pipeline/hard_ingress.py`, `runner.py`, `replay_runner.py`, and `dual_runner.py`.
- Canonical state and PT binding: `sbp_lex/shared/state_builder.py`, `sbp_lex/governance/procedural_truth_envelope.py`, PT engines, threshold conditioning, corroboration, and consistency processing.
- Authority: Root of Trust runner and anchor, attestation, continuity, expiry, and revocation engines.
- Downstream authority order: Governance runner, GRC, Domain runner, Aurion runtime runner, and Execution Gate.
- Audit and controlled outcomes: audit engine/finalisation, hash chain, token stack, convergence, and controlled outcome processing.
- External boundary: bridge validators, external validation, hard-entry preview, SKG/DTN builders, demo packages, and existing boundary tests.
- Desktop locality and topology checks: API access control/server, runtime, desktop labels, and active Python source.

## Phase 18.5 files changed

- `sbp_lex/pipeline/hard_ingress.py` — rejects embedded external authority keys and terminal authority values before admission.
- `external_substrates/shared/validation.py` — rejects `ALLOW`, `DENY`, and `ESCALATE` values in external packages in addition to prohibited authority keys.
- `sbp_lex/authority_first/root_of_trust_runner.py` — requires accepted Hard Entry identity, a valid PT envelope digest, and all five anchored digests before Root of Trust can pass.
- `sbp_lex/pipeline/runner.py` — classification progression requires both legacy PT `PASS` and PT-only `PT_PASS`.
- `sbp_lex/execution/execution_gate.py` — fails closed on PT result/outcome mismatch.
- `sbp_lex/pipeline/replay_runner.py` — preserves and compares request, SKG, DTN, pre-context, and PT-envelope digest lineage.
- `tests/test_phase_18_5_authority_boundary.py` — 14 focused pre-activation hardening tests.
- `reports/PHASE_18_5_PRE_ACTIVATION_AUTHORITY_BOUNDARY_AUDIT.md` — this audit report.

The earlier uncommitted Phase 18 files remain part of the working tree and were not reverted or redesigned.

## Tests added

The focused suite verifies that an external package cannot self-traverse, bypass Hard Entry, overwrite request identity, overwrite Governance, or overwrite execution state. It verifies missing/tampered PT envelopes, missing Root of Trust digests, PT result/outcome mismatch, deterministic replay of bound metadata, complete audit lineage, the external import boundary, rejection of external authority outcomes, and absence of prohibited topology in active source.

## Authority boundary findings

- Pre-context metadata is passed to State Builder only on the accepted Hard Entry branch. Rejected packages construct no admitted PT binding and cannot reach Root of Trust.
- State Builder derives request identity with the canonical digest helper; package-supplied identity cannot replace it.
- Root of Trust now fails closed unless it can anchor request fingerprint, SKG digest, DTN digest, pre-context digest, and PT envelope digest against an accepted Hard Entry identity.
- PT cannot be skipped: classification requires `PASS` plus `PT_PASS`; Execution Gate independently checks the same invariant and the PT token stack.
- External packages cannot carry execution permission, Governance result, execution result, or terminal `ALLOW`/`DENY`/`ESCALATE` authority values.
- SKG and DTN remain external context substrates. They do not import canonical runtime code, govern, execute, mutate runtime state, or bypass Hard Entry.
- Governance remains the admissibility authority. Domain is called only after Governance `ALLOW` plus GRC `PASS`; Domain itself rejects non-allowed Governance. Aurion is called only after Domain pass and independently rejects other Domain states. Execution Gate remains the final execution boundary.
- Audit records the complete request/SKG/DTN/pre-context/PT-envelope lineage and the canonical Root of Trust anchor.
- Replay compares the PT outcome, envelope digest, and the full PT-bound digest lineage.

## Verification results

- `python -m compileall -q .` — PASS using Python 3.12.13. The access-restricted `.pytest_cache` directory could not be listed; source compilation completed with exit code 0.
- `python -m pytest -q` — PASS, 142 tests. One environmental warning reported that pytest could not write its cache under the access-restricted working copy.
- `scripts\run_tests.bat` — PASS, 142 tests.
- `python main.py` — PASS: `ALLOW`, `EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, and no token failures.
- `python main.py replay` — PASS: two runs matched with identical PT result, PT outcome, envelope digest, and full PT-bound request/SKG/DTN/pre-context lineage; no mismatches.
- `git diff --check` — PASS; only informational LF-to-CRLF working-copy warnings were emitted.
- `git diff --stat` — cumulative uncommitted Phase 18/18.5 tracked diff: 14 files, 191 insertions, 23 deletions. Six expected new Phase 18/18.5 files are untracked and listed by status.
- `git status --short` — expected Phase 18/18.5 files only; no Desktop/UI, APK, cloud, or unrelated files changed.
- external import search — no `sbp_lex` imports in `external_substrates`.
- active-source topology search — no prohibited topology terms.
- locality/dual-pipeline search — loopback-only defaults and Dual Adaptive Deterministic Pipelines remain present and unchanged.

## Boundary confirmation

Phase 19 was not started. Runtime activation and automatic external-package traversal were not added. Hard Entry, Root of Trust, Procedural Truth, Governance, Domain, Aurion, Execution Gate, and Audit retain their canonical order and authority. SKG, DTN, and the bridge remain external. Desktop V1 remains local/private, and the Dual Adaptive Deterministic Pipelines remain preserved.
