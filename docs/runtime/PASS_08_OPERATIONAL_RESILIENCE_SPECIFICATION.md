# Runtime Pass 8 Operational Resilience Specification

Status: implemented and verification-bound

Scope: SBP-LEX Dual V6 Desktop V1, single-host local runtime

Version: `PASS8_DESKTOP_V1_OPERATIONAL_LIFECYCLE_V1`

## Purpose and boundary

Pass 8 adds operational supervision, deterministic shutdown, restart/recovery
classification, bounded resources, test-only fault injection, a deterministic
soak harness, and evidence capture around the existing canonical runtime.
It does not become an authority source. Governance, Procedural Truth, Domain,
Aurion, the Execution Gate, capability issuance, effect acknowledgement,
audit, and replay retain their Pass 7 meanings and order.

This pass is explicitly local and single-host. It introduces no live SKG/DTN,
external service, external credential, cloud/node/quorum/mesh/distributed
runtime, real infrastructure control, weapon data, emergency authority
override, APP implementation, production-readiness claim, certification claim,
PQC migration-completion claim, quantum-safe claim, or final Windows IVVF claim.

## Lifecycle model

The operational lifecycle states are:

`NOT_STARTED -> STARTING -> STARTUP_VALIDATION -> READY -> PROCESSING`

Orderly termination uses:

`READY|PROCESSING -> DRAINING -> STOPPING -> STOPPED`

Unexpected termination uses:

`READY|PROCESSING -> FAILED_CLOSED -> RECOVERY_REQUIRED -> RECOVERY_VALIDATION`

Recovery can return to `READY` only after a valid measured-startup record and a
valid recovery assessment. Invalid evidence reaches `FAILED_CLOSED` or
`QUARANTINED`. Restart and recovery attempts are bounded at three.

Every lifecycle event is sequence-numbered and digest-bound. Operational
records always carry `authority_granted=false` and `resume_authority=false`.
They cannot mint a control token, change a decision, or authorize an effect.

## Measured startup and process ownership

Startup requires an approved measured-startup result with a 64-hex runtime
identity, an approved baseline identifier, measurement and attestation digests,
and a positive startup sequence. Invalid measurement fails closed before work
is accepted.

`RuntimeOwnershipManager` publishes an exclusive JSON ownership record using
create-exclusive filesystem semantics. A live owner blocks a duplicate runtime.
A stale owner is first schema/digest validated, then preserved as evidence,
before a new owner may be claimed. Corrupt or substituted locks fail closed.

## Shutdown contract

Shutdown immediately stops new admissions and capability issuance, clears
unconsumed capability references, and records the operator request. Active work
is either drained to a terminal result or explicitly invalidated. A drain never
creates execution authority. Repeated shutdown after `STOPPED` is idempotent.

An exception in the wrapped canonical traversal is treated as unexpected
termination. The request is not resumed. Pending authority is cleared and
recovery is required.

## Restart and recovery contract

Recovery records bind request fingerprint, runtime identity, repository commit,
last stage, decision, execution result, effect status, state hash, and an
explicit false resume-authority marker.

Recovery actions are deliberately conservative:

- pre-state interruption requires full ingress;
- state/control interruption requires full-path revalidation;
- DENY or ESCALATE requires full re-entry and preserves the terminal decision;
- Domain/Aurion candidate failure permits only bounded new-candidate re-entry;
- an unconsumed/uncertain capability is invalidated before revalidation;
- unknown, ambiguous, or partial effect status requires reconciliation with no
  automatic retry;
- incomplete audit permits only non-executing evidence repair;
- terminal history is read-only and never automatically resumed;
- unknown, malformed, digest-invalid, or resume-authorizing records quarantine;
- runtime-identity mismatch requires measured-startup revalidation and fails
  closed in the active recovery controller.

## Persistence, quarantine, backup, and restore

Pass 8 reuses the existing integrity store and recovery implementation. Atomic
writes, hash-chain verification, checkpoint verification, rollback detection,
cross-request binding, and quarantine remain authoritative. Corrupt evidence is
preserved; it is not repaired into acceptance.

Backup publication remains staged and atomic. Its manifest binds repository
commit, measured baseline, runtime identity, generation, inventory, domain
manifests, and artifact digests. Restore validates the complete package before
writing into a separate approved destination. Missing, mutated, unexpected,
wrong-commit, wrong-runtime, symlink, traversal, partial, and substituted
packages are rejected.

## Resource policy

`ResourceBudgetPolicy` centralizes evidence for 27 resource classes: request
bytes, EIE bytes, JSON depth/keys, strings, lists, evidence, collective signals,
tokens, duplicate token names, candidate and fallback attempts, replay loading,
audit payloads, queue/concurrency, traversal time, evidence output, temporary
artifacts, recovery/restart attempts, and bounded failure records.

Measurements above a limit fail closed. Unknown, negative, non-integer, or
boolean measurements are invalid. `BoundedLocalCapacity` atomically blocks
duplicate request identifiers and saturation. Existing schema, admission,
candidate, event, and token controls remain the enforcement points; the Pass 8
snapshot is an evidence view and does not replace them.

## Fault injection

Fault injection is unavailable unless both the constructor opt-in and
`SBP_LEX_TEST_FAULT_INJECTION=1` are present. Thirty-two critical seams and 22
fault classes are declared. Injected records are deterministic, digest-bound,
test-only, halt execution, and grant no authority. Normal runtime code does not
enable or silently activate the injector.

## Soak protocol

The required local soak is 30 minutes with a bounded, balanced mix of valid,
denied, escalated, malformed, and replay cases. Every case produces a
deterministic projection, audit count, replay count, and parity comparison.
Synthetic successful cases use unique single-use capability references.

Captured measurements include elapsed and process CPU time, traced memory,
threads, Windows handles where available, garbage-collection counts, queue and
pending work, audit/replay/capability counts, exceptions/retries/denials,
parity and duplicate counts, and temporary files. Telemetry samples and recent
capability identifiers are bounded. Two-, four-, and eight-hour modes exist but
are not implicitly run in Pass 8.

Pass requires no unauthorized execution, duplicate capability, decision-relevant
parity mismatch, retry storm, restart loop, stale-token acceptance, uncontrolled
file growth, or unbounded thread/handle growth. Audit and replay counts must
equal workload count.

## Minimal change lineage

| Source requirement | Pass 8 finding | File/function | Test | Evidence | Result |
|---|---|---|---|---|---|
| Process supervision | No central lifecycle/owner supervisor | `operational_resilience.py` lifecycle and ownership classes | `test_runtime_pass8_operational_resilience.py` | operational evidence | Implemented |
| Safe shutdown/restart | No explicit drain/recovery classification | lifecycle and recovery assessment | operational resilience tests | recovery matrix | Implemented |
| Resource bounds | Controls existed but lacked one evidence view | `resource_budgets.py` | resource/fault/soak tests | resource snapshot | Implemented |
| Fault injection | No central test-only seam | `fault_injection.py` | per-seam/per-class tests | fault matrix | Implemented |
| Required soak | No deterministic long-run harness | `resilience_soak.py` | short harness test plus 30-minute run | soak metrics | Implemented |
| PQC readiness | Strict provider existed; migration metadata/inventory incomplete | `crypto_agility.py` | PQC/scenario tests | inventory and performance baseline | Readiness only |
| Abstract scenarios | Required scenarios absent | `pass8_resilience_scenarios.py` | scenario tests | controlled fixture package | Implemented |

## Acceptance interpretation

Pass 8 is complete only when focused tests, the established full suite, normal
runtime, replay, measured startup, local trust/evidence commands, the 30-minute
soak, and repository hygiene checks have their final recorded results. Any
critical failure remains a failure; it is not converted into a warning.
