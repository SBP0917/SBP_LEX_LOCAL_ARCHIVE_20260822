# Recovery, Restart, Backup, Restore, and Incident Runbook

Scope: SBP-LEX Dual V6 Desktop V1 local single-host runtime

Audience: authorized local operator and verifier

Principle: stop, preserve, verify, then recover; never manufacture authority

## Non-negotiable rules

- Do not automatically resume an interrupted request.
- Do not restore DENY or ESCALATE into ALLOW.
- Do not retry an unknown, ambiguous, partial, or unacknowledged effect.
- Do not bypass measured startup, full-path revalidation, Governance, the
  Execution Gate, capability verification, audit, replay, or integrity checks.
- Do not delete adverse, corrupt, partial, or quarantined evidence.
- Do not rebuild or approve the measured baseline without owner authorization.
- Do not weaken `security.integrity_ledger` because a recovery is urgent.
- Do not use this runbook to introduce live services, external ingestion,
  distributed coordination, real infrastructure control, or emergency authority.

## Immediate incident response

1. Stop admission of new work.
2. Block new capability issuance and clear unconsumed capability references.
3. Record the lifecycle state, runtime identity, repository commit, request
   fingerprint, last completed stage, decision/result, effect status, state hash,
   integrity checkpoint, and relevant paths.
4. Preserve active lock, recovery, audit, replay, integrity, and process evidence.
5. If effect status is not conclusively `NOT_ATTEMPTED` or a confirmed terminal
   status, classify it as reconciliation-required and do not retry.
6. Request orderly drain only when active work can finish without weakening a
   control. Otherwise invalidate incomplete work and enter recovery-required.
7. Do not restart until process ownership and measured startup can be validated.

## Clean shutdown

For an idle runtime, request shutdown and confirm the sequence
`DRAINING -> STOPPING -> STOPPED`. For active work, confirm new admissions and
capability issuance are blocked. Allow the current traversal to reach a safe
terminal record, or explicitly invalidate it. Verify pending capability count and
active traversal count are zero. A repeated shutdown at `STOPPED` is safe and
must not create a new state transition with authority.

If shutdown interrupts audit finalisation, preserve the terminal state and allow
only non-executing evidence repair. Never replay the effect to reconstruct audit.

## Unexpected termination and crash loops

Unexpected termination clears active and pending state, records
`FAILED_CLOSED`, and enters `RECOVERY_REQUIRED`. A restart is not a continuation.
It is a new measured process evaluating preserved evidence.

At most three restart/recovery attempts are permitted. Exceeding the bound moves
the runtime to `QUARANTINED`. Do not repeatedly launch a failing runtime. Diagnose
the first stable failure evidence before another controlled attempt.

## Runtime ownership

Before start, validate the ownership record schema and digest.

- If the recorded process is live, stop: duplicate runtime ownership is denied.
- If the process is absent and the record validates, preserve it under its
  digest-bound stale name, then claim a new exclusive owner record.
- If the lock is corrupt, substituted, or already has conflicting stale evidence,
  stop and quarantine/investigate. Do not delete it to force startup.
- On normal shutdown, release only the lock whose owner token matches the current
  process.

## Restart classification

| Last known condition | Required action | Automatic resume/effect retry |
|---|---|---|
| Adapter/EIE/SKG-DTN/bridge/pre-state | Full ingress from original evidence | No |
| State through Governance pending | Full canonical-path revalidation | No |
| Terminal DENY or ESCALATE | Full re-entry; preserve prior terminal record | No |
| Domain or Aurion candidate failure | Bounded new-candidate re-entry; no identical failed retry | No |
| Execution Gate converged, effect not attempted | Invalidate capability and fully revalidate | No |
| Synthetic effect unknown/ambiguous/partial | Reconciliation required | No |
| Audit finalisation incomplete | Non-executing evidence repair only | No |
| Terminal complete | Read-only history | No |
| Runtime identity mismatch | New measured-startup validation | No |
| Unknown/malformed/digest-invalid record | Quarantine | No |

## Persistence corruption and quarantine

Validate the integrity ledger from its first record through the checkpoint. A
partial write, truncation, digest/signature failure, predecessor break, rollback,
cross-request substitution, or checkpoint mismatch fails closed.

Preserve the exact bytes and calculate their digest before moving the record into
the approved quarantine directory. Record source digest, size, and quarantine
path. Never edit quarantined evidence in place. Recover only from a separately
validated authoritative source and then repeat measured startup and full
canonical-path verification.

## Backup creation

1. Select only inventoried authoritative artifacts.
2. Confirm the approved backup root is separate from the active recovery target.
3. Record repository commit, measured baseline identifier, runtime identity,
   generation, predecessor identifier where applicable, and timestamp.
4. Create the staged package. The implementation verifies source stability before
   and after copy, secret scanning, artifact sizes/digests, the sealed manifest,
   and completion marker before atomic publication.
5. Independently run package validation after publication.
6. Preserve the returned backup identifier and aggregate digest.

Do not accept a package with a missing, mutated, extra, symlinked, or unexpected
member, a mismatched completion marker, a changed source during copy, or detected
secret material.

## Restore

Restore only into an approved separate destination. Before writing, validate:

- package and completion integrity;
- full artifact inventory and domain/sensitivity placement;
- expected repository commit;
- expected measured baseline identifier;
- expected runtime identity;
- generation and predecessor continuity;
- destination containment and absence of traversal/symlink substitution.

The restore is not authoritative until the fresh-process validation commands
succeed and the authoritative pointer is atomically published. If any step fails,
retain the failure evidence, leave the previous authoritative generation intact,
and do not start runtime processing from the candidate restore.

## Cryptographic-provider incident

If the mandatory provider is missing, times out, reports another provider or
algorithm, supplies malformed/wrong/revoked/expired key metadata, or presents a
cross-version/legacy downgrade, reject verification and fail closed. Do not fall
back silently. Pass 9 retains the selected local `cryptography.mldsa` provider
and enforces its signed profile; it does not authorize an alternative provider
or production deployment. Restore only the exact approved provider and profile,
then repeat activation, measured-startup, recovery, and trust checks.

## Resource incident

On request, queue, concurrency, candidate, token, replay, audit, output, temporary
artifact, restart, or recovery saturation, reject further work safely. Do not
raise bounds during the incident. Preserve the measured metric, configured limit,
request fingerprint, lifecycle state, and terminal result. The test-only injector
may reproduce the failure only in an explicitly enabled test environment.

## Exit criteria

Recovery is complete only when process ownership is unique, measured startup is
approved, runtime identity matches, the recovery record is valid and conservative,
integrity/audit/replay evidence validates, pending authority is empty, the runtime
is `READY`, and a new request must traverse the full canonical path. A successful
recovery record grants no authority by itself.

## Incident closure matrix

| Incident | Detection evidence | Immediate safe action | Prohibited action | Preserve | Recovery / validation | Escalate when | Closure evidence |
|---|---|---|---|---|---|---|---|
| Runtime will not start | startup rejection and operator-shell error | keep admission closed | bypass startup | baseline, identity, commit, error | restore required environment; repeat measured startup | trust material or code change is required | approved startup record |
| Measured-startup failure | measurement/baseline/attestation mismatch | fail closed | approve or rewrite baseline ad hoc | measurement and baseline bytes | owner-authorized baseline process, then remeasure | expected identity cannot be established | matching signed attestation |
| Duplicate runtime | live validated ownership lock | do not launch second process | delete live lock | lock and process identity | stop intended owner normally or retain it | ownership is ambiguous | unique validated owner |
| Repeated crash | bounded crash count and recovery events | stop restart loop | increase bound during incident | crash/recovery records and dumps | diagnose, repair, fresh measured start | third controlled attempt fails | stable start plus recovery validation |
| Ledger corruption | parse/digest/signature/link/checkpoint failure | quarantine and stop dependent work | edit/delete adverse record | exact bytes, digest, checkpoint | recover separately from authoritative evidence | authoritative source unavailable | clean full-chain verification |
| Evidence write failure | atomic write/audit/replay failure | halt result finalisation | claim success without evidence | partial/staged files and terminal state | non-executing evidence repair | terminal facts cannot be reconstructed | cross-bound audit/replay validation |
| Capability uncertainty | missing/duplicate/unconsumed capability state | invalidate capability | consume or reissue by assumption | capability reference and traversal receipt | full canonical revalidation | effect may already have occurred | new bound single-use capability or DENY |
| Ambiguous synthetic effect | unknown/partial/missing acknowledgement | reconcile; no retry | treat attempt as success or repeat effect | adapter request/acknowledgement and audit | determine terminal status independently | ambiguity cannot be resolved | confirmed status or preserved HALT |
| Replay mismatch | replay digest/state/result divergence | deny replay result | execute from replay | original and replay evidence | investigate immutable inputs and runtime identity | decision-relevant divergence remains | exact deterministic non-authoritative replay |
| Resource saturation | controlled limit reason and measurement | reject new work, preserve bound | raise limit or skip controls under pressure | metric, limit, request, lifecycle record | drain safely; diagnose workload | bounded drain/recovery fails | normal bounded measurements |
| Audit growth | bounded-record/size warning | stop admission before limit | truncate unsealed history | head/checkpoint/count and storage evidence | archive/rotate only under approved custody | continuity cannot be maintained | verified continuity and bounded active store |
| Backup failure | staging/member/manifest/publication error | retain current authority; abandon candidate | publish partial backup | stage metadata and failure reason | rebuild from stable source into new destination | authoritative source changed or secret detected | independently valid package |
| Restore failure | preflight/generation/fresh-process failure | retain prior authoritative generation | repoint to failed restore | package, failure record, prior pointer | correct cause and use new separate target | commit/identity/baseline continuity unresolved | valid restore and fresh-process checks |
| Provider failure/downgrade | unavailable/timeout/substitution/profile error | reject protected object | silent fallback or runtime legacy acceptance | profile, provider metadata, bounded error | restore exact approved provider/profile; repeat activation and reverify | replacement, production custody, or specialist decision is required | exact-provider V3 verification plus refreshed trust evidence |
| Local trust stale/dirty/invalid | capstone/evidence/release status failure | keep activation closed | regenerate without owner authority | current trust artifacts, commit, status | owner-authorized trust-evidence regeneration | authorised secret/approval is absent | valid commit-bound trust chain |

## Escalation conditions

Stop and obtain owner direction if recovery would require an authority change,
traversal reorder, denial restoration, emergency override, identical failed
candidate retry, result-semantic change, live service, PQC clone merge/provider
selection, APP implementation, destructive resource exhaustion, adverse-evidence
deletion, security-ledger weakening, production claim, quantum-safe claim,
certification claim, or final Windows IVVF claim.
