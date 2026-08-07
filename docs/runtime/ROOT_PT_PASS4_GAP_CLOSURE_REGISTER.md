# Runtime Pass 4 Root/PT Gap Closure Register

Baseline commit: `7cf107245ec561e927bfa178f35a7d49a4da129b`

Branch: `main`

Scope: Root of Trust, Procedural Truth, evidence sufficiency, tier and
corroboration conditioning, and the immediate downstream invariants needed to
prove that Root/PT ineligibility cannot be bypassed.

## Method

The baseline was inspected before implementation against the native Root and
PT blueprints and addenda. Each item was classified using the Pass 4
vocabulary. Corrections were limited to the existing Root chain, the one PT
path, the existing threshold/token contracts, exact dual-pipeline/replay
comparison, bounded audit lineage, and downstream entry invariants. No STOP
condition was encountered.

All result entries below were closed only after the focused, affected,
full-suite, runtime, replay, exact-parity, and current-state trust checks
completed.

## Root of Trust gaps

| Requirement | Baseline classification and observation | Gap | Correction / file and function | Focused proof | Deterministic evidence | Result |
|---|---|---|---|---|---|---|
| Exact seven-stage order | `IMPLEMENTED_NOT_TESTED`: order constant existed, but exact one-call/short-circuit behaviour was not proven. | No complete order or failure-isolation proof. | `authority_first/root_of_trust_runner.py`: retain `ROOT_OF_TRUST_ORDER`; aggregate ordered results and stop on first failure. | Root order and short-circuit matrix. | Root stage-result vector and reason. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Root entry/state integrity | `PARTIAL`: Hard Entry/EIE/substrate checks existed; current state hash, attachment signature, collective package and freshness were not verified together. | Mutated or substituted attachment/collective material could enter Root. | `shared/control_chain_validation.py`: Root input, attachment and collective-binding validators; `root_of_trust_runner.py`: mandatory preflight. | request/EIE/state/collective/attachment mutation matrix. | `state_hash_entering_root`, collective/attachment digests, failure reasons. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Authority legitimacy | `DOCUMENTED_NOT_IMPLEMENTED`: non-empty request authority was accepted. | Root did not consume the validated SKG legitimacy basis. | `collective/context_interface.py`: closed signed `root_trust_material.validation_basis`; `anchor_validation_engine.py`: exact authority/jurisdiction/legitimacy validation. | invalid/substituted/unresolved authority tests. | authority identity, jurisdiction, validation-basis digests. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Attestation validity | `IMPLEMENTED_WITH_BLUEPRINT_CONFLICT`: only presence of collective digest/signature was checked. | No signature, subject, identity, authority, request/EIE, freshness, nonce, expiry or revocation check. | `context_interface.py`: admitted attestation projection; `attestation_engine.py`: deterministic full validation. | malformed/substituted/expired/revoked attestation tests. | attestation identity/digest/result/reasons. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Attestation consensus | `IMPLEMENTED_WITH_BLUEPRINT_CONFLICT`: prior PASS became a synthetic score of 1.0. | No attestations were compared; probabilistic-style score was not exact consensus. | `attestation_consensus_engine.py`: exact identity and statement-digest agreement; no score/tolerance. | singleton-valid and inconsistent/broken consensus tests. | consensus identities/digest/result. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Truth anchor | `DOCUMENTED_NOT_IMPLEMENTED`: stage always passed and the old anchor was signed before Root stages. | No validation of prior Root results or bound truth statement. | `truth_anchor_engine.py` and Root aggregate finalizer: construct/verify signed truth anchor after prerequisite stages. | truth-anchor tamper/status tests. | truth-anchor digest/signature/result. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Truth continuity | `PARTIAL`: only hash-chain link structure was checked. | No predecessor, authority, attestation, request/EIE, collective or state continuity. | `truth_continuity_engine.py`: exact truth and chain-head continuity validation. | continuity-reference and chain-break tests. | continuity references/result/reason. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Truth expiry | `IMPLEMENTED_WITH_BLUEPRINT_CONFLICT`: only canonical timestamp/nonce shape was checked. | Authority, attestation and truth validity intervals were ignored. | `truth_expiry_engine.py`: admitted logical-time and closed interval validation. | expired/future authority, attestation and truth tests. | issued/valid-until basis and expiry result. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Truth revocation | `DOCUMENTED_NOT_IMPLEMENTED`: mutable empty module sets were the authority. | No signed/admitted authority, attestation or truth revocation decision. | `truth_revocation_engine.py`: admitted revocation-status validation; globals removed from the decision path. | authority/attestation/truth revocation tests. | revocation result and exact reason. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Aggregate Root evidence | `PARTIAL`: pre-stage compatibility anchor omitted final stage vector/reason and several bindings. | Replay/audit could not prove the completed chain. | `root_of_trust_runner.py`: signed `root_of_trust_evidence`; `control_chain_validation.py`: full verifier. | aggregate evidence signature/digest/binding tests. | `root_evidence_digest`, stage vector, Root result/reason. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Root token eligibility | `PARTIAL`: authority token bound only old anchor/result. | Mutated/stale/cross-request Root token semantics were not checked. | `root_of_trust_runner.py`: enrich authority token; `security/authority_boundary.py`: semantic comparison. | token tamper/cross-request reuse tests. | authority-token digest and Root evidence binding. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Root failure law | `PARTIAL`: runner stopped, but old anchor could remain valid and direct PT trusted it. | Failure could leave misleading eligibility state. | Root fail-closed finalizer: invalidate anchor, remove Root/PT tokens, clear PT PASS, mark persistent inoperability/full retraversal. | each Root-stage failure followed by PT/downstream direct calls. | deterministic failed Root record; no PT token/classification. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |

## Procedural Truth and threshold gaps

| Requirement | Baseline classification and observation | Gap | Correction / file and function | Focused proof | Deterministic evidence | Result |
|---|---|---|---|---|---|---|
| PT-after-Root precondition | `DOCUMENTED_NOT_IMPLEMENTED`: direct PT trusted old anchor flags. | PT could run locally before full Root verification. | `governance/procedural_truth_engine.py`: Root evidence/token preflight through `validate_root_of_trust_evidence`. | missing/failed/tampered/cross-request Root followed by direct PT. | PT failure reason; no PT/threshold token. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| One source assessment | `PARTIAL`: several engines recomputed weak, differing aggregates. | No single authoritative qualification basis. | `procedural_truth_envelope.py`: deterministic per-source assessment consumed by evidence, corroboration and final certification. | valid and invalid dimension matrix. | assessment-set digest, identity summary, rejection reasons. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Explicit/derived trust properties | `IMPLEMENTED_WITH_BLUEPRINT_CONFLICT`: missing provenance/integrity/authority/etc. defaulted true. | Missing trust was silently inferred valid. | Envelope builder records explicit values or the exact admitted-boundary derivation basis; conflicting/missing-unestablished values fail. | missing/false/malformed trust-property tests. | per-dimension result and qualification basis. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Request/EIE/collective/relevance binding | `DOCUMENTED_NOT_IMPLEMENTED`: only envelope-level request binding existed. | Other-request/EIE evidence and irrelevant evidence could count. | Per-source canonical binding/relevance fields and validation; Root revalidation prevents post-Root substitution. | request-mismatch, EIE-mismatch, collective mismatch and irrelevant-source tests. | source assessment binding fields and reasons. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Source independence | `PARTIAL`: count used entries; duplicate check used one fallback identifier and did not affect count. | Exact duplicates and aliases could inflate 2/3/5. | Stable provenance URI, otherwise source ID/name; unique qualifying identities only; duplicate/alias exclusions recorded. | five duplicates and shared-URI aliases at TOP. | total/qualifying/unique/duplicate counts and identity summary. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Freshness, attestation, verification, consistency | `PARTIAL`: booleans existed, with no unified deterministic assessment. | Invalid entries were inconsistently reported and counted. | Unified source assessment plus aggregate dimension results. | stale/unattested/unverified/inconsistent fifth-source matrix. | dimension results and unique observed count. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Evidentiary sufficiency | `PARTIAL`: count and several flags existed, but no distinct complete result/digest/relevance test. | Count alone could appear sufficient; completeness was absent. | `evidence_engine.py` / `procedural_truth_engine.py`: distinct signed/digested sufficiency record covering all dimensions and active tier. | sufficient count with incomplete/irrelevant/contradictory evidence. | sufficiency result/reason/digest. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Controlled PT outcome | `VERIFIED_IMPLEMENTED` for vocabulary; `IMPLEMENTED_NOT_EVIDENCED` for full determinism. | Complete reason/evidence equality was not replayed. | Preserve `PT_PASS`, `PT_REFINE`, `PT_ESCALATE`, `PT_FAIL`; bind deterministic final reason/evidence. | LOW/MEDIUM/TOP pass and shortfall cases; repeated/replay equality. | PT result/outcome/reason/digest. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Factor range | `IMPLEMENTED_WITH_BLUEPRINT_CONFLICT`: API accepted 0..5 and threshold helper silently coerced malformed values. | Values above 3 and booleans/malformed values could alter or lower tier. | `api/schema_validation.py`, `config/thresholds.py`: strict non-boolean integer 0..3 factors. | factor boundaries and malformed-input Hard Entry denial. | denial reasons and factor snapshot. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Financial banding | `PARTIAL`: AUD bands correct; malformed/negative/non-finite values silently became LOW. | Invalid financial data could lower burden. | Preserve 499.99/49,999.99/50,000 bands; validate finite, non-negative numeric input; record missing-value policy. | band boundaries, malformed/negative/non-finite and max-factor tests. | financial input status/factor/tier. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Locked 2/3/5 floors | `VERIFIED_IMPLEMENTED`: constants and basic tests existed. | Needed proof using unique, fully qualifying sources. | Preserve constants; corroboration consumes unique qualifying assessment only. | LOW 2/1, MEDIUM 3/2, TOP 5/4. | required/observed and PT outcome. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| No downgrade / escalation | `PARTIAL`: a current tier was locally preserved, but no durable transition/high-water evidence existed. | Mutable factors/tier/tokens could create TOP/MEDIUM downgrades. | `config/thresholds.py`, `threshold_conditioning_engine.py`: sealed conditioning record with previous/current/high-water tier and monotonic result. | all three upward and all three prohibited downward transitions; direct field mutation. | threshold-conditioning digest/transition/result. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| PT evidence/token issuance | `PARTIAL`: PT token was issued before final certification and omitted key bindings/nonce. | A pre-certification token trace and weak semantics existed. | Finalize certification and signed `procedural_truth_evidence` first; issue PT token only on certified PASS with all required bindings/timestamp/nonce. | insufficient evidence has no token; token-field tamper matrix. | PT evidence/token digest/signature/fields. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Threshold-token semantics | `PARTIAL`: signatures and internal bundle hashes were checked, not values against state. | Same-request stale semantic tokens survived tier mutation. | `security/threshold_tokens.py`: compare component values, tier, requirement, stage and bundle root with sealed live state. | component/bundle tamper and stale-token reuse. | semantic verification failure reasons. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |

## Continuity, downstream, parity and lineage gaps

| Requirement | Baseline classification and observation | Gap | Correction / file and function | Focused proof | Deterministic evidence | Result |
|---|---|---|---|---|---|---|
| Complete EIE/Root/PT continuity | `PARTIAL`: validators existed separately; PT did not revalidate Root-bound envelope. | Post-Root evidence substitution could reach local PT calculation. | Shared full Root validator plus signed PT evidence continuity validator. | envelope/source replacement with recomputed local digest; cross-request/EIE reuse. | Root/PT evidence digests and binding failures. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Classification invariant | `VERIFIED_IMPLEMENTED` in normal runner; full mutation matrix untested. | Manual PT/Root/token mutation required explicit proof. | `security/authority_boundary.py`: reusable Root/PT eligibility at Classification entry. | PT FAIL/ESCALATE and Root failure cannot produce Classification ALLOW. | classification DENY/UNSET and guard reasons. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Licensing invariant | `PARTIAL`: direct Licensing required only Classification token. | A valid Classification/licence could restore PT-invalid state. | Same Root/PT eligibility check now applies to Licensing entry. | valid licence/classification plus PT failure. | Licensing DENY and no licence override. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Governance invariant | `PARTIAL`: normal order guarded, direct mutation matrix absent. | Governance ALLOW semantics could be presented with invalid PT. | Same eligibility check at Governance entry; no governance authority change. | PT/corroboration invalid plus direct Governance. | Governance ineffective/DENY. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| GRC invariant | `PARTIAL`: GRC had no canonical upstream guard. | Direct GRC could produce PASS after PT failure. | `governance/grc.py`: Root/PT entry guard; existing re-entry law retained. | direct GRC and identical failed re-entry. | GRC DENY/controlled re-entry. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Domain and Aurion invariants | `PARTIAL`: their existing guards did not prove PT semantics. | Direct PASS/pathway resolution could appear to restore PT. | Reusable eligibility check in existing canonical-upstream calls. | direct Domain/Aurion on PT-invalid states. | Domain/Aurion fail/escalate and HALT. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Execution Gate invariant | `PARTIAL`: many PT checks existed; tier/token semantic equality was incomplete. | Direct tier/threshold mutation could retain execution validity. | Existing gate calls full eligibility and semantic threshold verifier; gate ownership unchanged. | PT/corroboration/tier/token/request/EIE/state mutation matrix. | strict-security failure list and HALT. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Exact A/B Root/PT parity | `DOCUMENTED_NOT_IMPLEMENTED` for result fields. | Convergence ignored Root/PT results, counts, sufficiency, tier and digests. | `pipeline/dual_runner.py`, `shared/convergence.py`: exact basis/result fields and fail-closed mismatch; near-match false. | normal dual run and injected mismatch proof. | `root_pt_parity` and A/B digest fields. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Replay equality | `PARTIAL`: replay omitted Root reason/digest and complete PT result basis. | Some Root/PT divergence was invisible. | `pipeline/replay_runner.py`: exact Root/PT fields in signed replay comparison. | repeated run/replay and tamper verification. | replay matched/no mismatches and compared fields. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| Hash-chain/audit lineage | `PARTIAL`: substages existed; aggregate definitive Root/PT records were absent. | Pass 7 could not verify the complete Pass 4 basis. | Root/PT aggregate hash entries; `audit/audit_engine.py` bounded signed lineage projections. | hash-chain and audit-record field tests. | Root/PT lineage records and audit hash. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |
| External Desktop boundary | `NOT_APPLICABLE_DESKTOP_V1` for live trust services. | None: live linkage is prohibited, not missing Pass 4 work. | Preserve synthetic local validated SKG/DTN and context-only authority role. | import/static scope checks and runtime provider mode. | provider mode `synthetic_local`; network/live flags false. | CLOSED — focused proof passed; included in 77 focused / 167 affected / 1,951 full-suite passes |

## Owner decisions and STOP conditions

No owner decision is required for the bounded corrections above. No correction
requires a stage reorder, authority transfer, canonical-doctrine change,
weakened corroboration, approximate truth scoring, token-stack redesign, live
SKG/DTN service, external credential, or distributed runtime.

Final closure counts are recorded here after verification:

- unresolved Root of Trust implementation gaps: 0
- unresolved Procedural Truth implementation gaps: 0
- unresolved owner decisions: 0

## Final verification basis

- focused Pass 4 suite: 77 passed in 21.02s
- directly affected regression batch: 167 passed in 101.07s
- approved Windows suite: 1,951 passed, 7 skipped in 2,126.93s
- normal runtime: `ALLOW / EXECUTE`, convergence matched, no token failures
- replay: two runs matched, zero mismatches
- deterministic A/B parity: initial, Root, PT, tier, and corroboration parity
  exact; near-match reconciliation false
- current test-local trust root: release integrity, local-trust capstone, and
  adversarial negative harness all passed
- implementation commit under test:
  `e53bf8f560b3ad62a7d4a9104ba53153860e3729`

The historical persisted Phase 18.7 generated bundle remains anchored to its
original commit and was not rewritten by this bounded runtime pass. Current
code integrity was verified through the repository-approved ephemeral
test-local trust-root bootstrap used by the full suite and runtime checks.
