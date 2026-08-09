# Runtime Engineering Pass 7 — Execution Convergence Report

## 1. Result

Pass 7 is **COMPLETE** for the bounded Desktop V1 runtime-engineering scope.

The final clean Windows suite passed at `ac5ac74ea5af09e99cd1852711f156b9cf954d3b`: **2,175 passed, 7 skipped** in **4,680.99 seconds**, with exit code 0.

## 2. Baseline and repository state

- Branch: `main`
- Starting commit: `85ea181ecabecb93d6f424581104a1a3b89a80e8`
- Primary implementation commit: `83de406902970150ec3a879dbd7db1d352774cec`
- Final code/test-isolation commit: `ac5ac74ea5af09e99cd1852711f156b9cf954d3b`
- Initial working tree: clean
- Working tree for the final full-suite run: clean
- Existing unrelated stashes were preserved and were not restored or dropped.

## 3. Inspection and initial findings

The canonical runtime, hard ingress, state construction, token stack, threshold tokens, Execution Gate, capability/authority reference, measured startup, hash chain, audit engine/finalisation, replay ledger/runner, persistence integrity store, dual runner and formal verifier were inspected together with their existing tests.

Initial findings were classified as follows:

| Finding | Classification | Resolution |
|---|---|---|
| Gate accepted several success-shaped values without exact terminal vocabulary and binding | PARTIAL | Exact gate/token/stage/result semantics implemented |
| Traversal authority was not bound to one measured operational attempt | MISSING | Signed measured traversal receipt and atomic claim implemented |
| Capability lifecycle did not close every replay/cross-state/ambiguous-effect path | PARTIAL | Exact bindings, single use, cancellation/revocation/expiry and acknowledgement checks completed |
| Terminal whole-state digest and custody were not cross-bound across all terminal stores | PARTIAL | Preseal verification and durable terminal custody implemented |
| Hard-entry rejection lacked a distinct terminal custody form | IMPLEMENTED_NOT_EVIDENCED | Signed rejection custody added and tested |
| Dual divergence retained success-shaped surfaces in some paths | PARTIAL | Success surfaces removed; controlled persistent inoperability and signed audit added |
| Replay non-authority was architectural but not explicit in all terminal material | IMPLEMENTED_NOT_TESTED | `NOT_AUTHORISED` replay semantics and non-effect tests added |
| Live services, distributed runtime and external certification | NOT_APPLICABLE_DESKTOP_V1 | Remained outside scope |

## 4. Implementation

The primary implementation changed 32 files (5,109 insertions, 354 deletions). A final targeted legacy test-boundary fixture added seven lines without altering production runtime behaviour.

Major corrections:

- Strict terminal Gate conditions, exact stage/token sets, threshold applicability, temporal and trace-order validation.
- Signed traversal receipt bound to measured startup, request fingerprint and traversal-start event.
- Atomic, process-local, single-use operational receipt and capability claims; replay/validation receipts are non-operational.
- Whole-terminal-state preseal and durable custody across replay ledger, integrity store, completed event and authority material.
- Distinct signed hard-entry rejection custody.
- Denial conservation across upstream failures, retry/fallback/replay/direct-gate and reconstructed-state attacks.
- Full-dual divergence strips success surfaces, records signed convergence failure and enters persistent inoperability.
- Exact target/operation adapter acknowledgement; ambiguous effects never become confirmed success.
- Formal verification bound to the verified terminal preseal digest.
- Terminal-aware canonical hash profile.
- Narrow test isolation after CLI subprocesses invalidate the parent measured-startup cache.

New production modules:

- `sbp_lex/execution/terminal_assurance.py`
- `sbp_lex/runtime/terminal_custody.py`
- `sbp_lex/runtime/traversal_receipt.py`

New focused tests:

- `tests/test_runtime_pass7_execution_convergence_hardening.py`
- `tests/test_runtime_pass7_terminal_custody.py`

## 5. Tests and verification

### Focused and affected suites

- Pass 7 consolidated new/affected suite: **114 passed** in 354.55 seconds.
- Strict Execution Gate selection: **8 passed**.
- Terminal custody selection: **5 passed**.
- H8 plus Pass 4/5/6 regression selection: **240 passed**.
- Legacy red-team boundary after the final isolation correction: **28 passed** in 27.68 seconds.
- Representative H7 measurement/capability plus Pass 7 custody selection: **21 passed** in 132.99 seconds.
- R2 supply-chain relevant suite: **47 passed, 3 skipped**. This was regression verification only; no provenance package was created or promoted.
- Windows/R4 relevant suite: **44 passed**. This was regression verification only; no package was created or promoted.
- Local-trust focused suite: **24 passed**.

All required Pass 7 test classes A through V are represented in the focused tests, including positive convergence, token/signature/digest/binding failures, denial conservation, hash mutation, receipt/capability replay, audit readiness, replay non-effect, measured-runtime invalidity, ambiguous effect, duplication/races and terminal exceptions.

### Full suite

Final command:

```text
scripts\run_tests.bat -q -p no:cacheprovider
```

Final result:

```text
2175 passed, 7 skipped in 4680.99s (1:18:00)
[PASS] Requested test run passed.
```

During closure, an earlier clean monolithic run found one legacy test whose parent measured-startup cache had been invalidated by an earlier CLI subprocess: 2,174 passed, 7 skipped, 1 failed. A broad fixture was rejected after it caused measurement-sequence rebinding. The final correction was narrowed to the legacy module boundary, the affected sequences passed, and the clean monolithic suite then passed in full.

### Compile and repository checks

- `python -m compileall -q .`: exit 0. Inaccessible ignored historical pytest temporary directories produced `Can't list` notices; source/test-specific compile checks passed.
- `git diff --check`: pass.
- Final clean status will be recorded after the evidence commit.

## 6. Runtime assurance results

| Area | Result |
|---|---|
| Denial conservation | PASS — upstream invalidity cannot be restored downstream |
| Required and threshold token convergence | PASS — exact set, semantics, signatures, digests and bindings enforced |
| Cross-request/state/EIE binding | PASS — transplant and stale material rejected |
| Capability lifecycle | PASS — issued only after convergence, atomically single-use, non-transferable and auditable |
| Measured startup | PASS — bound through receipt, capability and terminal custody; changed identity blocks execution |
| Hash chain | PASS — removal/reorder/duplication/mutation/truncation/fake success/cross-request copying block execution |
| Audit and terminal custody | PASS — attributable, presealed and durably cross-bound; audit has no authority |
| Replay | PASS — exact deterministic verification, `NOT_AUTHORISED`, no fresh effect or operational capability |
| Ambiguous effect | PASS — authorisation to attempt is distinct from confirmed success |
| Race/concurrency | PASS — duplicate claims/consumption and tested overlaps are atomically rejected or safely serialized |
| Dual divergence | PASS — no success surface, signed convergence failure and persistent inoperability |

## 7. Normal runtime and replay attempts

Both required CLI commands were attempted in the operator shell:

```text
python main.py
python main.py replay
```

Both exited 1 and failed closed because the shell does not contain an authorised `SBP_LEX_SIGNING_SECRET` of exactly 64 lowercase hexadecimal characters. No test seed was injected into a durable runtime and no trust artifact was rewritten. Valid operational traversal and deterministic replay/non-effect behaviour passed under the repository's ephemeral isolated test trust root.

## 8. Local trust and provenance boundary

The existing stored release-integrity and local-trust capstone artifacts refer to an older commit and currently report stale-artifact failure. A refresh attempt stopped before writing because the authorised signing secret was absent. This is recorded as a later owner-authorised trust/provenance milestone, not hidden or relabelled.

Pass 7 did **not** create, rebuild or promote a provenance package. R2 and R4 commands above were existing regression tests only. Pass 7 also did not create clean clones. The owner has deferred whether ten clean clones will derive from baseline 10 or baseline 12.

## 9. Minimal traceability

| Requirement / criterion | Runtime correction | Principal files | Evidence |
|---|---|---|---|
| V4 non-bypass / final convergence | Exact Gate, receipt and preseal | `execution_gate.py`, `traversal_receipt.py`, `terminal_assurance.py` | Pass 7 A–V suite; full suite |
| V5 denial conservation | Terminal invalidity and divergence closure | `execution_gate.py`, `dual_runner.py`, `hard_ingress.py` | Denial, fallback, replay and divergence tests |
| V6 capability integrity | Exact binding and atomic lifecycle | `capability.py`, `execution_attestation.py` | reuse, transplant, race, cancellation and acknowledgement tests |
| V7 measured startup | Receipt-to-terminal runtime binding | `traversal_receipt.py`, `capability.py`, `execution_gate.py` | drift, stale identity and subprocess-isolation tests |
| V8 cryptographic assurance | Exact signed-token/receipt/custody verification | `token_stack.py`, `threshold_tokens.py`, `terminal_custody.py` | digest/signature/resigning negative tests |
| V10 operational assurance | Fail-closed terminal exceptions and durable custody | `audit_finalisation.py`, `integrity_store.py`, `pipeline_replay_ledger.py` | write-failure, interruption and custody tests |
| V12 evidence custody | Whole-state preseal and cross-store binding | `terminal_custody.py`, `audit_engine.py`, `formal/verifier.py` | custody downgrade/partial/mutation tests |

## 10. Remaining gaps

1. An authorised operator signing secret is required for direct normal/replay CLI operation.
2. Durable release-integrity and local-trust evidence must be refreshed at the later authorised trust/provenance milestone.
3. The owner must choose baseline 10 or baseline 12 before creating ten clean clones.
4. Live external-provider assurance, production operations, external certification, independent IV&V and complete formal proof remain outside this pass.

These gaps do not leave a known Pass 7 terminal-control test failing. They bound environment activation and later assurance work.

## 11. Boundary confirmation

- No architecture redesign.
- No authority ownership change.
- No traversal reorder.
- No live SKG/DTN or other external service linkage.
- No cloud, nodes, quorum, mesh or distributed runtime.
- No production credential introduced.
- No provenance package or clone set created.
- No production-readiness, certification, independent-IV&V or complete-formal-proof claim.
