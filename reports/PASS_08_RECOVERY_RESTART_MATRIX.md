# Pass 8 Recovery and Restart Matrix

Status: implemented and focused-test verified

Recovery record: `PASS8_DESKTOP_V1_RECOVERY_RECORD_V1`

Every recovery record is schema- and digest-bound to the request fingerprint,
runtime identity, repository commit, last stage, decision, execution result,
effect status, state hash, and `resume_authority=false`. A recovery assessment
also declares no automatic effect retry and no authority grant.

| Interruption/terminal point | Conserved fact | Required recovery action | Quarantine | Automatic resume/effect retry |
|---|---|---|---:|---:|
| Adapter | no governed state | full ingress | No | No |
| EIE | no governed state | full ingress | No | No |
| SKG/DTN | no governed state | full ingress | No | No |
| Bridge | no governed state | full ingress | No | No |
| Hard entry pending | no governed state | full ingress | No | No |
| State construction | state not current | full-path revalidation | No | No |
| Collective attachment | state not current | full-path revalidation | No | No |
| Root of Trust | state not current | full-path revalidation | No | No |
| Procedural Truth | state not current | full-path revalidation; PT failure cannot be bypassed | No | No |
| Classification | state not current | full-path revalidation | No | No |
| Licensing | state not current | full-path revalidation | No | No |
| Governance pending | state not current | full-path revalidation | No | No |
| Governance DENY | terminal decision | full re-entry; prior DENY preserved | No | No |
| ESCALATE | terminal decision | full re-entry; prior ESCALATE preserved | No | No |
| Domain failure | candidate rejection | bounded new-candidate re-entry | No | No |
| Aurion failure | candidate rejection | bounded new-candidate re-entry | No | No |
| Execution Gate converged, effect not attempted | capability uncertain | invalidate capability and revalidate | No | No |
| Synthetic effect attempt; unknown/ambiguous/partial | effect status uncertain | reconciliation required | No | No |
| Audit finalisation | terminal evidence incomplete | non-executing evidence repair | No | No |
| Terminal complete | terminal history | read-only; new requests use full path | No | No |
| Runtime identity mismatch | runtime substitution/change | measured-startup revalidation; controller fails closed | No | No |
| Unknown stage | unclassifiable evidence | quarantine | Yes | No |
| Malformed/schema-invalid record | untrusted evidence | quarantine | Yes | No |
| Digest-invalid record | tampered evidence | quarantine | Yes | No |
| `resume_authority=true` | forbidden authority claim | quarantine | Yes | No |

## Shutdown matrix

| Condition | Behavior | Result |
|---|---|---|
| Idle READY | stop admission, drain/stop, release ownership after validation | deterministic STOPPED |
| Active PROCESSING | block admission/capabilities; drain active work | STOPPED after terminal result |
| Active invalidation selected | record every invalidated request/stage; clear pending capabilities | STOPPED, no resume |
| Shutdown during every critical stage | lifecycle blocks new authority; recovery classification applies | safe HALT/re-entry |
| Audit finalisation interrupted | preserve terminal state; evidence repair only | no effect replay |
| Repeated shutdown | record already complete | idempotent STOPPED |
| Shutdown after failure | enter recovery-required | no restart authority |

## Process/restart bounds

- Exclusive create prevents two live local owners.
- A live lock returns `duplicate_runtime_ownership`.
- A stale lock must validate before it is preserved and replaced.
- A corrupt lock fails closed and is not silently removed.
- Crash and recovery attempts are independently bounded at three.
- The fourth crash/recovery attempt quarantines rather than loops.
- Pending capabilities are cleared on shutdown and unexpected termination.
- A restarted process must present a valid measured-startup identity.

## Persistence, backup, and restore matrix

| Fault | Enforcement | Expected result |
|---|---|---|
| Partial/truncated persistence write | strict parse, chain, checkpoint, atomic publication | fail closed/quarantine |
| Corrupted ledger record | digest/signature/chain validation | fail closed/quarantine |
| Rollback snapshot | generation/checkpoint continuity | reject |
| Cross-request snapshot | request binding | reject |
| Valid backup | staged copy, stable-source check, manifest and completion validation | valid package |
| Missing backup artifact | complete inventory validation | reject |
| Mutated artifact | size/digest validation | reject |
| Unexpected artifact | exact member-set validation | reject |
| Wrong repository commit | restore preflight binding | reject |
| Wrong runtime identity | restore preflight binding | reject |
| Path traversal/symlink | approved-root containment | reject |
| Valid separate restore | preflight, staged generation, fresh-process checks, atomic pointer | authoritative restore valid |

## Evidence linkage

- Implementation: `sbp_lex/runtime/operational_resilience.py`
- Existing recovery: `sbp_lex/recovery/`
- Focused tests: `tests/test_runtime_pass8_operational_resilience.py`
- Existing recovery tests: `tests/test_r1_canonical_backup_recovery.py`
- Operational evidence: `outputs/runtime/pass_08_operational_resilience_evidence.json`
- Runbook: `docs/operations/RECOVERY_RESTART_BACKUP_RESTORE_INCIDENT_RUNBOOK.md`

Nothing in this matrix authorizes automatic denial restoration, emergency
override, identical failed-candidate retry, capability reuse, or effect retry.
