# H7 Deterministic Execution Integrity Report

## Mission record

- Mission: H7 — Deterministic Execution Integrity
- Scope: Desktop V1 only
- Starting commit: `59ea62a6b6cdcc7a4011e2c172e569064f06ac58`
- Ending commit: the local commit containing this report; its immutable hash is recorded in the task return because a commit cannot contain its own hash
- Architecture: unchanged; the canonical Desktop V1 traversal order is preserved
- Node rule: preserved; no Node.js component, package, runtime, or distributed topology was added
- Cognitive scope: untouched; `phase19e-cognitive-pipelines-experimental` remains in its separate worktree
- GitHub: no GitHub state was changed during implementation or pre-commit verification

## Implementation

H7 adds a fail-closed execution-integrity subsystem beneath the existing canonical runtime. A successful canonical traversal retains its full signed authority internally and exposes only a one-time, non-authoritative capability reference. The runtime can then issue and execute a capability only through the H7 service and an approved, service-owned execution specification.

The implementation comprises:

- `sbp_lex/execution/capability.py`: capability model, validation, issuance, reservation, execution, cancellation, revocation, revalidation, completion, and attestation logic
- `sbp_lex/execution/capability_store.py`: durable hash-linked capability ledger, checkpoint and anchor verification, intent recovery, OS locking, writer lease, and atomic attestation sequencing
- `sbp_lex/execution/schemas/execution_capability.schema.json`: strict capability contract
- `sbp_lex/execution/schemas/capability_lifecycle_record.schema.json`: strict lifecycle-record contract
- `sbp_lex/execution/schemas/post_execution_attestation.schema.json`: strict completion-attestation contract
- canonical runtime and authority-token integration for the existing GRC stage
- H8 and local-trust critical-path coverage for the H7 sources and schemas

## Capability lifecycle and single use

The lifecycle is `PENDING`, `ACTIVE`, `RESERVED`, `EXECUTING`, then exactly one terminal state: `COMPLETED`, `CANCELLED`, `EXPIRED`, `REVOKED`, `FAILED`, `AMBIGUOUS`, or `RETIRED`. State transitions are persisted as hash-linked signed records. Reservation and start are atomic under the store lock. A traversal authority can issue only one capability, and a capability cannot be reserved or executed twice, including across concurrent callers and restarts.

An interrupted `EXECUTING` record is recovered as `AMBIGUOUS`, never silently retried. Store corruption, rollback of an individual checkpoint/anchor/ledger component, conflicting writer leases, and incomplete mutation intents fail closed.

## Binding and validation

Each signed capability binds the exact canonical request and approved execution context, including request fingerprint, EIE and state hashes, both pipeline results, convergence, procedural-truth evidence, Classification, Licensing, Governance, GRC, Domain, Aurion15, target identity, normalized parameters, runtime identity, approved measured baseline, software measurement, adapter identity, and audit linkage.

The service-owned `ExecutionSpecification` fixes target type, operation, adapter, allowed and required fields, constraints, and safe-cancellation policy. A caller cannot invent an allowlist or change the canonical action. Parameter handling applies Unicode normalization, deterministic canonicalization, exact key checks, type/depth/size limits, duplicate-key rejection, secret-key rejection, and constraint continuity. Constraints may only remain equal or become stricter between authorization and use.

## Temporal, cancellation, and mid-execution controls

The subsystem uses its internal clock and enforces activation, expiry, reservation, start, execution, and reporting deadlines. Clock rollback fails closed. Before every execution step, H7 revalidates the full binding set, authorization, lifecycle, constraints, and the H8 approved runtime measurement. Critical or unknown drift stops later effects.

Revocation and cancellation are authorized operations with race-safe retries. A live execution is labelled `CANCELLED` only when its registered adapter explicitly acknowledges `terminate()`. Caller-supplied cancellation evidence is not trusted. A revoked or failed capability cannot complete successfully.

## Completion integrity and attestation

Completion evidence is accepted only from inside the active adapter session and is linked to signed traversal-start and traversal-completion runtime events. Missing evidence, adapter communication loss after a possible effect, or failed post-effect context revalidation produces `AMBIGUOUS`, not success. The store owns a global, atomic, hash-linked attestation sequence so concurrent completions cannot fork or duplicate the sequence.

## Measured baseline and protected evidence

The final reconciled runtime and trust-store state was explicitly proposed and approved as `DESKTOP_V1_H7_APPROVED_2026_07_12_08`; the superseded H7 baseline `DESKTOP_V1_H7_APPROVED_2026_07_12_07` was retired by exact identifier. Approval reference: `H7_FINAL_LINEAGE_AND_TRUST_RECONCILIATION_D36AA22`.

Final measured-startup validation returned `MEASURED_STARTUP_APPROVED`, with runtime identity `fb898ba09cd159b26098a8145d2b7bcaea0871f52b8554c80477a5abd1eb42ed`. The persisted startup anchor was advanced through the complete, signed `_05` → `_06` → `_07` → `_08` lineage. The protected evidence chain was rebuilt only after implementation reconciliation. Its final compare returned `changed_evidence_items=0`.

## Tests and verification

Targeted H7 suite:

- `python -m pytest -q tests/test_h7_deterministic_execution_integrity.py`
- Result: 131 passed

The targeted suite covers lifecycle transitions, single-use and concurrency, request/target/parameter bindings, Unicode and malformed inputs, temporal boundaries and clock rollback, cancellation and revocation races, mid-execution mutation, H8 drift, constraint continuity, completion evidence, ambiguous outcomes, persistence, recovery, corruption, rollback, writer exclusion, and concurrent attestation.

Full verification results:

- `python -m compileall -q .`: pass
- `python -m pytest -q`: 1,253 passed
- `scripts\run_tests.bat`: 1,253 passed
- local-trust manifest: `LOCAL_TRUST_VALID`
- execution environment: `EXECUTION_ENV_VALID`
- evidence chain: `EVIDENCE_CHAIN_VALID`; zero changed evidence items
- regression matrix: `REGRESSION_MATRIX_VALID` (19/19)
- constitutional gates: `CONSTITUTIONAL_GATES_PASS` (24/24)
- toolchain guard: `TOOLCHAIN_GUARD_PASS` (39/39)
- local-trust capstone: `LOCAL_TRUST_CAPSTONE_PASS`
- release integrity: `RELEASE_INTEGRITY_PASS` (38/38)
- adversarial negative harness: `ADVERSARIAL_NEGATIVE_HARNESS_PASS` (39/39)
- validation dossier: `VALIDATION_DOSSIER_READY`
- measured startup: `MEASURED_STARTUP_APPROVED`
- `python main.py`: `ALLOW` / `EXECUTE`, convergence matched
- `python main.py replay`: matched, zero mismatches
- `git diff --check`: pass (line-ending notices only)

One order-dependent targeted-test failure was discovered during the first batch run: a mutable adapter identity inherited from the test class could leak between cases. The genuine fixture-isolation defect was repaired by assigning the approved identity on each adapter instance. A subsequent clean-commit run exposed a transient Windows `PermissionError` during `os.replace`; the durable store now applies a bounded five-attempt retry only for that error and otherwise retains fail-closed behavior. A dedicated injected-denial regression test covers the repair. Final verification also exposed that H8 accepted only an immediate baseline predecessor even though its manager permits multiple explicit approvals before startup. Lineage validation now requires a complete, acyclic, strictly sequence-increasing ancestry back to the persisted anchor; a new H8 regression test covers the legitimate multi-update case without weakening rollback detection.

## Security properties

- Fail-closed issuance and execution on missing, malformed, expired, mismatched, drifted, corrupted, rolled-back, or unverifiable state
- Exact signed binding from canonical authority through target, parameters, adapter, runtime identity, baseline, execution, and post-execution attestation
- Durable single-use semantics across threads, processes, crashes, and restarts
- No caller-defined execution policy and no caller-self-attested completion or cancellation
- Deterministic serialization, replay, lifecycle evidence, and audit linkage
- No secret material in capability identifiers, runtime identity, or measured evidence

## Remaining limitations

- Python cannot forcibly stop an adapter already blocked inside a non-cooperative, uninterruptible external call. H7 can revoke/fail the capability and prevent later checkpoints or successful completion; it reports `CANCELLED` only after adapter termination acknowledgement.
- A fully compromised host that coherently rolls back the ledger, checkpoint, and anchor together cannot be detected without an external monotonic, OS, TPM, or hardware trust anchor. Component-level rollback and inconsistency are detected.
- No production external adapter is configured in this Desktop V1 package. Execution fails closed unless an approved execution specification and registered adapter are supplied.

## Scope confirmation

Desktop V1 remains the only runtime topology. The canonical architecture, deterministic replay, and no-node rule are preserved. No cognitive artefact, experimental cognitive branch content, public deployment material, or unrelated repository file was incorporated. The existing stash was not altered.
