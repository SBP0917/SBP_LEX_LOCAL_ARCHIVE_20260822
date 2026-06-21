# Phase RED-20B Attack Report

## Scope

RED-20B executed only the five attack classes specified for this block:

- Confused-deputy authority attack.
- TOCTOU state substitution.
- Protocol and security downgrade attack.
- Signature wrapping and signed-field substitution.
- Canonicalization ambiguity and digest-confusion attack.

Phase 19 and RED-20C were not started. No runtime activation path, UI work, APK work, node, quorum, mesh, distributed runtime, cloud, or V2/V3 capability was added.

## Attacks executed

1. Presented an external pre-context package directly to Governance. Governance denied it and issued no Governance token.
2. Presented the external package directly to Governance, Domain, Aurion, and Execution Gate. Every component failed closed without canonical upstream state.
3. Swapped a validated request action before use. Immutable request-snapshot validation detected the TOCTOU mismatch.
4. Swapped the PT envelope after validation and recomputed its public digest. The signed PT token no longer matched active state.
5. Substituted validated Classification, Licensing, and Governance results. Each active result diverged from its signed stage token.
6. Swapped a token bundle from a different request before gate use. Request binding and token verification rejected it; Execution Gate halted.
7. Re-signed SKG, DTN, and pre-context packages with downgraded package versions. Exact version enforcement rejected them.
8. Replaced canonical signature algorithm and signing-marker metadata with weaker markers. Signature verification rejected both.
9. Downgraded PT threshold tier/requirement and submitted a stale external package. PT token binding and bridge freshness checks rejected them.
10. Wrapped a valid signed token with an unsigned active-authority field. Strict token schema rejected the wrapper.
11. Substituted a signed token digest. Token verification failed.
12. Re-signed an authority token containing a different evidence-anchor context. Cryptographic verification succeeded, but semantic authority binding rejected the token.
13. Submitted duplicate JSON fields and alternate mapping order. Duplicate fields failed; order normalized deterministically.
14. Submitted composed/decomposed Unicode variants and a normalization key collision. Values normalized identically; ambiguous normalized keys failed.
15. Substituted numeric strings for numeric values. Digests remained type-distinct and request schema validation rejected coercion.

## Gaps found

- Downstream components trusted upstream result strings without independently requiring and semantically binding canonical stage tokens.
- Canonical state retained only a request fingerprint, not an immutable request snapshot for active-field TOCTOU comparison.
- Signature envelope metadata (`issuer`, algorithm, deterministic signing marker) was not strictly enforced.
- Tokens allowed extra unsigned wrapper fields and did not strictly enforce canonical version, issuer, field set, name, or verified marker.
- External SKG, DTN, pre-context, and bridge validators did not all enforce exact package version `1.0`.
- Internal canonical JSON used permissive string fallback and lacked explicit Unicode normalization/key-collision rejection.

## Fixes applied

- Added `sbp_lex/security/authority_boundary.py` for request-snapshot validation, canonical stage-token validation, and semantic active-state/token comparison.
- State Builder now preserves an immutable request identity snapshot and digest.
- Classification, Licensing, Governance, Domain, Aurion, and Execution Gate independently validate their required upstream authority tokens before acting.
- Canonical signatures now require exact internal issuer, algorithm, deterministic marker, and signature-envelope field set.
- Token verification now rejects extra wrapper fields, version/issuer/name substitution, and non-canonical token shapes.
- Canonical hashing now rejects unsupported values/non-string keys/non-finite numbers, normalizes Unicode to NFC, rejects normalization key collisions, preserves numeric/string distinctions, and remains order-independent.
- Exact external package-version checks were added to SKG, DTN, pre-context, and bridge validation.
- Two legacy Domain unit fixtures were upgraded to include a legitimate signed canonical Governance prerequisite; production behavior was not weakened.

## Files added or changed for RED-20B

- `sbp_lex/security/authority_boundary.py`
- `sbp_lex/security/pqc.py`
- `sbp_lex/security/token_stack.py`
- `sbp_lex/shared/state_builder.py`
- `sbp_lex/classification/engine.py`
- `sbp_lex/licensing/engine.py`
- `sbp_lex/governance/engine.py`
- `sbp_lex/domains/runner.py`
- `sbp_lex/aurion15/runtime/runner.py`
- `sbp_lex/execution/execution_gate.py`
- `external_substrates/skg/signal_builder.py`
- `external_substrates/dtn/signal_builder.py`
- `external_substrates/shared/pre_context_package.py`
- `external_substrates/shared/bridge_validator.py`
- `tests/test_phase_15_5a_alignment.py`
- `tests/test_red_20b_attack_classes_15_11.py`
- `reports/PHASE_RED_20B_ATTACK_REPORT.md`

The verified but uncommitted RED-20A files remain in the same working tree and were preserved.

## Tests added

Fifteen required attack scenarios are represented by 17 focused test executions because Classification, Licensing, and Governance substitution are independently parameterized. Interim full-suite result: 185 tests passed.

## Mandatory verification

- `python -m compileall -q .` — PASS using Python 3.12.13. The access-restricted `.pytest_cache` directory could not be listed; source compilation completed with exit code 0.
- `python -m pytest -q` — PASS, 185 tests. One environmental warning reported that pytest could not write its cache under the access-restricted working copy.
- `scripts\run_tests.bat` — PASS, 185 tests.
- `python main.py` — PASS: `ALLOW`, `EXECUTE`, `MODE_2_SPLIT_VALIDATOR`, convergence matched, and no token failures.
- `python main.py replay` — PASS: two deterministic runs matched with identical PT-bound lineage and no mismatches.
- `git diff --check` — PASS; only informational LF-to-CRLF working-copy warnings were emitted.
- `git diff --stat` — cumulative uncommitted RED-20A/20B tracked diff: 22 files changed with 423 insertions and 94 deletions; five intended new RED-20A/20B files are untracked.
- `git status --short` — exactly the intended RED-20A/20B files; no UI or unrelated file changes.
- external import search — no `sbp_lex` imports in `external_substrates`.
- active-source topology search — no prohibited topology terms.
- locality and pipeline search — loopback-only defaults and Dual Adaptive Deterministic Pipelines remain present.

## Boundary determination

No altered artifact validated silently. No trusted internal component acted as authority for an external package. SKG and DTN remain external, canonical SBP-LEX remains the sole runtime authority, and Desktop V1 remains local/private.
