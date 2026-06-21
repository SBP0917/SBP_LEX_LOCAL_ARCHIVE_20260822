# Phase RED-20D Attack Report

## Scope and outcome

RED-20D executed D1-D25 only. All 25 focused attacks failed closed or exposed a documented cryptographic trust limit. Phase 19 was not started, runtime activation was not introduced, and RED-20D made no UI or external-substrate authority changes.

## Attacks executed

- D1-D5: forged audit, replay, Procedural Truth, Governance, and Root of Trust signatures/artifacts under signing-secret-compromise simulation.
- D6-D10: Hard Entry, Root of Trust, Procedural Truth, Governance, and Execution Gate bypass attempts.
- D11-D15: dependency, fixture, build artifact, release package, and validation-tool substitution.
- D16-D20: false authority token, lineage, jurisdiction, licensing, and Governance authority.
- D21-D25: combined token theft/replay, token theft/PT manipulation, rollback/authority substitution, persistence poisoning/authority capture, and coordinated full-boundary collapse.

## Proven gaps and fixes

The canonical authority validator previously checked token signatures, payload semantics, request binding, and issuance lineage, but did not independently require the canonical stage sequence. A shared stage-lineage verifier now requires accepted Hard Entry and the unique ordered upstream stages appropriate to each authority token. Strict execution verification additionally requires the Execution Gate stage.

Trusted delivery artifacts previously had no focused pinned-manifest control. A deterministic supply-chain manifest now binds the manifest type, pinned validator identity, artifact names and SHA-256 digests, manifest digest, and signature. Validation requires an independently supplied trusted manifest digest; re-signing a substituted manifest does not replace that pin.

Two pre-existing domain unit fixtures manufactured a post-Governance state directly. They were corrected to begin from a fully traversed canonical state; the production guard was not weakened.

## Signing-secret compromise assessment

The Desktop V1 signature helper is explicitly a non-production, single local HMAC placeholder. Possession of its secret defeats signature-origin authenticity for every artifact sharing that secret.

What fails:

- An attacker with the secret can create signatures that pass the placeholder signature verifier.
- Cryptographic separation between audit, replay, PT, Governance, Root of Trust, persistence, and release roles does not exist in this prototype.
- If an attacker can also rewrite every mutually checked state, lineage, head, checkpoint, and trusted pin, software-only verification inside the same trust domain cannot distinguish the forgery. Total key plus storage/control-plane capture remains a terminal trust assumption, not a solved condition.

What remains protected against single-artifact forgery:

- Request fingerprint and active-state semantic binding.
- Exact token stage/name/payload and issuance-trace lineage.
- Root of Trust-to-PT-envelope and external-digest equality.
- Audit, execution attestation, controlled outcome, hash-chain, chronology, persistence checkpoint, and replay-head cross-checks.
- Trusted replay/head comparison and independently supplied supply-chain manifest pins.
- Canonical stage-order enforcement and final Execution Gate checks.

Current isolation assumptions:

- The local signing secret, code, trusted checkpoint/head, trusted manifest pin, and runtime storage are not all controlled by one attacker.
- External SKG/DTN packages never receive the internal secret and remain untrusted until Hard Entry.
- Desktop V1 remains local/private and the placeholder signing claim remains non-production.

Production controls required:

- Separate asymmetric keys by role and environment, backed by HSM/KMS or equivalent hardware custody.
- Offline Root of Trust, least-privilege signing services, threshold authorization, rotation, revocation, and rapid compromise response.
- Independently anchored append-only transparency/log heads and externally witnessed checkpoints.
- Reproducible/hermetic builds, signed provenance and SBOMs, dependency locking, protected release pipelines, and independent release verification.
- Immutable/WORM audit retention, segregated backup recovery, dual control, monitoring, and key-use anomaly detection.

## Authority-capture assessment

False authority did not become accepted authority. Token signature, request, semantic, stage, lineage, and state-snapshot checks rejected D16-D20. Authority remains canonical and internal; SKG/DTN remain external signals rather than Governance or execution authorities.

## Supply-chain assessment

All five substitutions produced `supply_chain_compromise_detected:*`. The manifest pin is deliberately external input to validation, preventing a substituted artifact plus re-signed manifest from silently redefining the trusted baseline. This control is readiness hardening, not a claim of a production release system.

## Total-boundary-collapse assessment

D21-D25 could not obtain execution eligibility. Combined mutations were rejected through request binding, semantic token checks, issuance lineage, stage ordering, rollback/checkpoint comparison, persistence integrity, PT/root lineage, and strict execution verification. A total compromise of the shared placeholder signing secret plus all trusted storage, code, heads, and pins remains outside the protection possible within one local trust domain and requires the production controls above.

## Files added or changed for RED-20D

- `sbp_lex/security/authority_boundary.py`
- `sbp_lex/security/supply_chain.py`
- `sbp_lex/execution/execution_gate.py`
- `tests/test_phase_15_5a_alignment.py`
- `tests/test_red_20d_attack_classes_5_1.py`
- `reports/PHASE_RED_20D_ATTACK_REPORT.md`

The verified, uncommitted RED-20A/20B/20C working-tree changes were preserved.

## Tests and verification

- Focused RED-20D matrix: PASS, 25 tests.
- Full pytest suite: PASS, 231 tests; one non-fatal Windows `.pytest_cache` permission warning.
- `python -m compileall -q .`: PASS; the inaccessible `.pytest_cache` directory produced a non-fatal listing notice.
- `scripts\run_tests.bat`: PASS, 231 tests; the same non-fatal cache warning was reported.
- `python main.py`: PASS with an isolated RED-20D integrity store; `ALLOW`, `EXECUTE`, convergence matched, and no token failures.
- `python main.py replay`: PASS with an isolated RED-20D integrity store; two deterministic runs matched with no mismatches.
- `git diff --check`: PASS; Git reported line-ending conversion notices only.
- `git diff --stat`: PASS. The tracked cumulative RED-20A-D diff contains 24 files, 685 insertions, and 107 deletions; untracked reports, security modules, and focused tests are listed by status.
- `git status --short`: reviewed; only the intended cumulative uncommitted RED-20A-D work is present.
- Boundary searches: no `sbp_lex` imports in `external_substrates`, and no prohibited topology terms in active Python source.

## Mandatory conclusions

- Phase 19 was not started.
- Runtime activation was not introduced.
- SKG and DTN remain external.
- Desktop V1 remains local/private.
- No nodes, quorum, mesh, distributed runtime, cloud, APK, or V2/V3 work was introduced.
