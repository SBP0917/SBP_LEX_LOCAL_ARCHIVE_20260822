# Runtime Engineering Pass 8 — Operational Resilience Report

## 1. Result

Pass 8 status: **COMPLETE** for the bounded Desktop V1 scope.

The implementation hardens process ownership, lifecycle supervision, shutdown,
restart/recovery classification, resource controls, test-only fault injection,
soak measurement, structured event vocabulary, backup/restore evidence, and PQC
migration readiness without changing canonical authority or traversal order.

## 2. Baseline and repository state

- Branch: `main`
- Starting commit: `45bfad36d89569a0cdc7e8206c8c7a2d09869093`
- Starting working tree: clean
- Pass 7 prerequisite: COMPLETE; clean suite 2,175 passed, 7 skipped
- Pass 8 implementation commit: `717c9c8e09983e646d70852dad20e0731f06f564`
- Ending verified implementation commit: `717c9c8e09983e646d70852dad20e0731f06f564`
- Final working tree: `clean after the report/evidence commit`
- Existing unrelated stashes were preserved and were not restored or dropped.

## 3. Inspection and findings before modification

Inspected areas included the canonical runtime and CLI/API entry points, measured
startup, chronology/event bus, request/schema/admission bounds, hard ingress,
state construction, Pass 4–7 control path, Domain/Aurion candidate loop,
Execution Gate/capability/attestation, audit/replay/terminal custody, persistence
integrity store, recovery inventory/backup/restore, local trust/evidence chain,
release integrity, ML-DSA provider/policy, external source signing, synthetic
fixture signing, and the relevant test suites.

| Finding | Classification | Resolution |
|---|---|---|
| No explicit operational lifecycle, drain, crash-loop, or restart supervisor | MISSING | Non-authoritative lifecycle controller and canonical-runtime wrapper implemented |
| No exclusive validated local runtime owner record | MISSING | Digest-bound exclusive owner lock with validated stale-lock preservation implemented |
| Restart points lacked one conservative classification matrix | PARTIAL | Stage/decision/effect-bound recovery record and fail-closed action matrix implemented |
| Persistence quarantine and backup/restore were strong but not collected into Pass 8 evidence | IMPLEMENTED_NOT_EVIDENCED | Existing controls reused, extended tests and operator matrix/runbook added |
| Runtime bounds existed across modules but lacked one evidence view | PARTIAL | 27-metric resource policy/snapshot and atomic local capacity implemented |
| No central deterministic fault injector | MISSING | Explicitly enabled, test-only injector for 32 seams and 22 fault classes implemented |
| No required deterministic long-run harness | MISSING | balanced local soak with bounded telemetry and 30m/2h/4h/8h modes implemented |
| ML-DSA provider seam was strict; migration inventory/profile lifecycle was incomplete | PARTIAL | 22-boundary inventory, signed profile contract, downgrade tests and performance baseline added; no migration performed |
| Four required scenarios were not packaged as a Pass 8 canonical fixture set | MISSING | digest-bound derived-outcome fixture/evaluator package added |

## 4. Files changed

Production/runtime and fixture implementation:

- `sbp_lex/runtime/operational_resilience.py`
- `sbp_lex/runtime/resource_budgets.py`
- `sbp_lex/runtime/fault_injection.py`
- `sbp_lex/runtime/resilience_soak.py`
- `sbp_lex/runtime/event_bus.py`
- `sbp_lex/security/crypto_agility.py`
- `external_substrates/demo/pass8_resilience_scenarios.py`

Focused tests:

- `tests/test_runtime_pass8_operational_resilience.py`
- `tests/test_runtime_pass8_resource_fault_soak.py`
- `tests/test_runtime_pass8_pqc_scenarios.py`

Specifications, operations, reports, outputs, and fixtures:

- `docs/runtime/PASS_08_OPERATIONAL_RESILIENCE_SPECIFICATION.md`
- `docs/operations/RECOVERY_RESTART_BACKUP_RESTORE_INCIDENT_RUNBOOK.md`
- `docs/security/PQC_MIGRATION_READINESS_SPECIFICATION.md`
- `reports/PASS_08_FAULT_INJECTION_MATRIX.md`
- `reports/PASS_08_RECOVERY_RESTART_MATRIX.md`
- `reports/RUNTIME_ENGINEERING_PASS_08_OPERATIONAL_RESILIENCE_REPORT.md`
- `outputs/runtime/pass_08_operational_resilience_evidence.json`
- `outputs/runtime/pass_08_soak_metrics.json`
- `outputs/runtime/pass_08_resource_budget_snapshot.json`
- `outputs/security/pqc_migration_readiness_inventory.json`
- `outputs/security/pqc_performance_baseline.json`
- `fixtures/pass8/pass_08_resilience_scenarios.json`

## 5. Operational results

| Area | Result |
|---|---|
| Process supervision | PASS — exclusive live-owner rejection; validated stale preservation; corrupt lock rejection; crash loop bounded |
| Measured startup | PASS under isolated test trust — invalid/mismatched runtime identity fails closed before admission/recovery |
| Shutdown | PASS — idle, repeated, drain, invalidation, mid-stage, audit-finalisation and no-capability-during-drain cases |
| Restart | PASS — no automatic resume; attempt bounds and measured identity enforced |
| Recovery | PASS — pre-state, control-stage, DENY/ESCALATE, Domain/Aurion, Gate, ambiguous effect, audit and terminal cases classified conservatively |
| PT and DENY conservation | PASS — PT DENY and Governance DENY require full re-entry; neither is restored to success |
| Capability after restart | PASS — pending pre-crash capability is cleared and cannot be consumed |
| Persistence | PASS in focused/established tests — partial, truncation, chain, checkpoint, rollback and cross-request faults reject |
| Quarantine | PASS — corrupt recovery/persistence evidence is preserved and grants no authority |
| Backup | PASS — manifest, identity, commit, inventory, digest, completion and atomic publication validate |
| Restore | PASS — missing/mutated/unexpected/wrong-commit/wrong-runtime/traversal candidates reject; separate restore validates |
| Resource limits | PASS — 27 classes reject above bound; duplicate/concurrent saturation is atomic |
| Fault injection | PASS — 32 seams and 22 classes halt safely; no injected fault grants authority |
| Structured events | PASS — lifecycle events use the existing bounded signed chronology/event bus; observability is non-authoritative |

## 6. Soak result

- Required final duration: **1,800.0 seconds** (30 minutes; 60-second warm-up,
  1,740-second steady state)
- Workload count: **35,151**
- Workload mix: valid 7,031; denied 7,030; escalated 7,030; malformed
  7,030; replay 7,030
- Pass status: **PASS — all 14 assertions true**
- Resource summary: working set 26,906,624-byte baseline, 27,078,656-byte
  warm-up end, 29,368,320-byte peak/end; traced Python peak 981,924 bytes,
  steady median 637,859 bytes and end 867,431 bytes; one thread; 178 Windows
  handles at baseline/peak/end; 359 bounded telemetry samples. Open-file count
  was unavailable because the optional process-inspection package is not part of
  the assurance environment; handle count and temporary-file count were captured.
- Case-latency summary: minimum 0.1873 ms, median 0.57355 ms, p95 0.9178 ms,
  p99 1.2433 ms, maximum 3.5468 ms across the bounded 4,096-sample window
- Audit, integrity-ledger, replay and token-validation counts: **35,151 each**;
  capability issuance/consumption: **7,031 / 7,031**

The final soak uses only local synthetic projections and no live effect. It
records warm-up separately from steady state, uses bounded telemetry,
recent-capability, and latency windows, and applies no invented universal memory
threshold. All mandatory assertions must be true in the final artifact.

Two pre-final runs were rejected during conformance review. The first was stopped
because several required measurements were not yet explicit; its orphan workers
were then identified and terminated. The next completed 30 minutes and passed
its control assertions, but exposed a 64-bit Windows pseudo-handle adapter defect
that marked handle/working-set measurements unavailable. That artifact was moved
intact to the ignored `runtime_artifacts/pass8_adverse/` evidence area. The
adapter was corrected and verified with live values before the acceptance clock
was restarted. Neither pre-final run is represented as the accepted output.

## 7. PQC migration readiness

- Inventory: `outputs/security/pqc_migration_readiness_inventory.json`
- Boundaries found: **22**
- Inventory validation: PASS; no referenced repository file missing
- Active provider: `cryptography.mldsa`, provider version 49.0.0
- Algorithm identifier: `ML-DSA`
- Provider abstraction: existing strict provider seam retained; versioned profile
  and requirement layer added without rerouting active signing
- Metadata: provider/algorithm/signature/hybrid/key/lifecycle/migration/legacy/
  deprecation fields explicit in the readiness profile
- Downgrade rejection: PASS for missing/substituted provider, algorithm, mode,
  key identity, fingerprint, revocation, expiry, legacy, hybrid and cross-version
  cases
- Provider loss: mandatory verification fails closed; no fallback is selected
- Current provider replacement: **false**
- Migration completed: **false**
- Quantum-safe claim: **false**
- Detached clone status: no PQC-named branch or registered worktree was located;
  no detached worktree was attached, modified, merged, or promoted

Performance evidence uses five warm-up and 25 measured ML-DSA samples on Python
3.12.13 / Windows 11. Median sign/verify/failure-path measurements were
2.0170 ms / 0.4388 ms / 0.4285 ms; signature size was 3,309 bytes and public key
size 1,952 bytes. This is an engineering baseline, not certification.

## 8. Synthetic scenarios

The four fixtures are one canonical digest-bound set. Their evaluator derives
outcomes from conditions, delegation records, plan constraints, and mandatory
crypto/resource failures, then compares the derived outcome with the fixture's
expected result.

| Scenario | Result |
|---|---|
| A — multi-jurisdiction emergency | deterministic ESCALATE/HALT; missing corroboration and authority conflict conserved |
| B — impersonation/delegation | deterministic DENY/HALT; forged, revoked and over-scoped delegation rejected |
| C — constrained resource optimisation | cheapest violating plan rejected; bounded admissible synthetic plan selected; no-plan case ESCALATE/HALT |
| D — coordinated AI/crypto pressure | deterministic DENY/HALT; provider loss/downgrade/resource pressure creates no authority or duplicate effect |

No real identity, targeting, infrastructure-control, external-service, or live
effect data is present. The later professor/university validation package may
reference this same fixture set without creating a divergent copy.

## 9. Tests and verification

- Final Pass 8 focused/boundary suite: **168 passed** in 3.41 seconds
  (166 focused Pass 8 checks plus two external-substrate boundary checks)
- Adjacent Pass 6/7, recovery, PQC, admission, persistence and measured-startup
  selection: **388 passed, 2 skipped** in 971.41 seconds
- Final established suite: `2341 passed, 7 skipped in 3150.49s (0:52:30)`
- `python -m compileall -q .`: exit 0; inaccessible ignored historical pytest
  temporary directories emitted `Can't list` notices, while focused module and
  test compilation passed
- `git diff --check`: PASS

The first full-suite attempt reported 2,338 passed, 7 skipped, and 3 failed.
Two failures correctly exposed an external-substrate import-boundary violation and
were fixed in `717c9c8`; the third was an over-deep in-repository temporary-path
artifact and passed when isolated with the normal system temporary directory.
A subsequent corrected run reached its two-hour runner limit without a pytest
summary; its verified orphan test processes were terminated, so it is not
represented as a pass or fail. The clean final run above used the established
runner, the normal system temporary directory, and completed without failures.

The established batch command invokes `python -m pytest` with isolated user site
and disabled plugin autoload. The final suite result is recorded at the clean
implementation commit before this report/evidence-only commit.

## 10. Runtime, replay, measured startup, and trust status

Required operator-shell commands `python main.py` and `python main.py replay`
were attempted and each exited 1, failing closed because no authorised
`SBP_LEX_SIGNING_SECRET` of exactly 64 lowercase hexadecimal characters exists
in the shell. No test seed was injected into a durable runtime.

Normal traversal, exact deterministic replay/non-effect, measured startup,
integrity ledger, lifecycle supervision, and Pass 7 invariants pass under the
repository's isolated ephemeral test trust root.

Stored operator-shell evidence remains stale/invalid from the pre-existing
baseline state:

- measured-startup `show`: exit 1 (`baseline_store_integrity_invalid`);
- evidence-chain `show`: `EVIDENCE_CHAIN_INVALID`;
- local-trust capstone `show`: `LOCAL_TRUST_CAPSTONE_FAIL`;
- release-integrity `show`: `RELEASE_INTEGRITY_FAIL`;
- stored integrity ledger verification without the authorised verification
  environment: signature failures and fail-closed poisoning marker.

No owner baseline, local-trust, release, or ledger artifact was overwritten,
deleted, promoted, or relabelled. This is the same owner-activation/trust refresh
boundary recorded after Pass 7, not a hidden Pass 8 runtime-control failure.

## 11. Exact command record

Principal commands executed with
`C:\Users\LeighMC\Documents\Codex\V\VENV_SBP_V1_3ef5992_20260716T152709+1000\Scripts\python.exe`
(Python 3.12.13) were:

```text
python -m py_compile <Pass 8 modules and tests>
python -m compileall -q .
python -m pytest -p no:cacheprovider -q tests/test_runtime_pass8_operational_resilience.py tests/test_runtime_pass8_resource_fault_soak.py tests/test_runtime_pass8_pqc_scenarios.py
python -m pytest -p no:cacheprovider -q tests/test_runtime_pass7_execution_convergence_hardening.py tests/test_runtime_pass7_terminal_custody.py tests/test_runtime_pass6_domain_aurion_reentry_hardening.py tests/test_r1_canonical_backup_recovery.py tests/test_pqc_01_provider_contract.py tests/test_h2d_admission_control.py tests/test_h4a_security_state_persistence.py tests/test_h8_measured_startup_runtime_identity.py
python -m sbp_lex.runtime.resilience_soak --mode required_30m --output outputs/runtime/pass_08_soak_metrics.json
python -m sbp_lex.runtime.resource_budgets --output outputs/runtime/pass_08_resource_budget_snapshot.json
python -m sbp_lex.security.crypto_agility inventory --root . --output outputs/security/pqc_migration_readiness_inventory.json
python -m sbp_lex.security.crypto_agility performance --samples 25 --warmup 5 --output outputs/security/pqc_performance_baseline.json
python -m external_substrates.demo.pass8_resilience_scenarios --output fixtures/pass8/pass_08_resilience_scenarios.json
scripts\run_tests.bat -q -p no:cacheprovider
python main.py
python main.py replay
python -m sbp_lex.runtime.measured_startup show
python -m sbp_lex.local_trust.evidence_chain show
python -m sbp_lex.local_trust.local_trust_capstone show
python -m sbp_lex.local_trust.release_integrity show
IntegrityStore().verify()
git diff --check
git status --short
```

## 12. Minimal change lineage

| Source requirement | Finding | File/function | Test | Evidence | Result |
|---|---|---|---|---|---|
| Supervision/duplicate owner | central owner/lifecycle absent | `RuntimeOwnershipManager`, `RuntimeLifecycleController` | operational tests | recovery matrix/evidence | PASS |
| Shutdown/restart | no drain/recovery classifier | lifecycle and `assess_recovery_record` | stage/restart tests | runbook/recovery matrix | PASS |
| Persistence/quarantine | strong existing controls needed Pass 8 coverage | integrity store plus recovery record quarantine | H4A and Pass 8 tests | operational evidence | PASS |
| Backup/restore | strong existing implementation needed mutation/substitution proof | `sbp_lex/recovery` reused | R1 and Pass 8 restore tests | recovery matrix | PASS |
| Soak/resources | harness and central evidence absent | `resilience_soak.py`, `resource_budgets.py` | resource/soak tests plus final run | soak/snapshot | PASS |
| Fault injection | central safe seam absent | `fault_injection.py` | 32 seam / 22 class parameters | fault matrix | PASS |
| PQC readiness | inventory/lifecycle metadata incomplete | `crypto_agility.py` | PQC negative/performance tests | inventory/baseline | PASS readiness only |
| Scenarios A–D | no canonical Pass 8 package | scenario builder/evaluator | deterministic/tamper/no-plan tests | fixture package | PASS |

## 13. Remaining gaps

1. An authorised operator signing secret is required for direct normal/replay CLI
   activation; none was persisted or substituted by Pass 8.
2. Stored measured-startup, evidence-chain, local-trust, release-integrity, and
   integrity-ledger evidence requires a later owner-authorised refresh/verification
   environment. Pass 8 does not overwrite it.
3. No PQC-named detached clone was discoverable in registered branches/worktrees;
   any separately held clone remains outside this workspace and untouched.
4. Per-boundary runtime integration of the new migration profile, provider
   selection, key custody/rotation/revocation/expiry, hybrid policy, archive
   treatment, and specialist approval remain deferred to Pass 9 or later.
5. Extended 2h/4h/8h soak modes are available but were not run automatically.
6. APP implementation, live external-provider assurance, production operations,
   external certification, and final native-Windows IVVF remain outside Pass 8.

These gaps do not leave a known Pass 8 focused or established-suite control test
failing. They bound operator activation and explicitly deferred later work.

## 14. Boundary confirmation

- No architecture redesign.
- No authority reassignment.
- No traversal reorder.
- No automatic denial restoration.
- No emergency authority override.
- No live SKG/DTN or other external service.
- No external credential introduced.
- No cloud, nodes, quorum, mesh, or distributed runtime.
- No real-world weapon, targeting, or infrastructure integration.
- No PQC provider replacement or migration-completion claim.
- No quantum-safe claim.
- No APP implementation.
- No final Windows IVVF completion claim.
- No production-readiness or certification claim.
