# Pass 7 Execution Convergence Runtime Specification

## Status and scope

This specification records the implemented SBP-LEX Dual V6 Desktop V1 terminal runtime behaviour at Pass 7. It is descriptive implementation evidence, not a canonical blueprint change.

Desktop V1 remains local/private, single-host, node-free, non-cloud and synthetic/local at external-substrate boundaries. The canonical traversal order and all existing authority ownership remain unchanged.

## Terminal runtime flow

The implemented terminal path accepts only the signed, hash-bound state produced by the existing Adapter through Aurion traversal. The final sequence is:

1. Build and verify the signed traversal receipt against the request fingerprint and measured-startup record.
2. Validate the complete governed stage prefix and terminal-aware hash chain.
3. Verify every required core token and every applicable conditional threshold token.
4. Converge Governance, Procedural Truth, Classification, Licensing, GRC, Domain and Aurion results without originating or repairing their authority.
5. Establish audit readiness before an execution-capable return.
6. Issue a bound, signed execution traversal authority and capability only after exact convergence.
7. Atomically claim the operational receipt and single-use capability.
8. Require an exact synthetic/local adapter acknowledgement for the bound target and operation.
9. Distinguish authority to attempt from confirmed effect success.
10. Preseal the whole terminal state and write terminal custody to the replay ledger, integrity store, completed event and execution authority.

Any mandatory failure produces deterministic non-execution. No partial execution, optimistic fallback or success-with-warning state is permitted.

## Execution Gate responsibilities

The Execution Gate is a convergence validator. It checks the canonical stage prefix, decision/result vocabulary, prior terminal invalidity, required state sections, exact token set, token integrity and binding, threshold applicability, collective-signal continuity, request/EIE/state/tier continuity, hash-chain continuity, measured-startup continuity, Domain/Aurion success, boundary clearance, attestation clearance and audit readiness.

The gate does not originate authority, Procedural Truth, classification, licensing, governance, domain admissibility or Aurion pathway admissibility. It cannot repair a failure and cannot treat token presence as a replacement for stage success.

## Token responsibilities

Core token verification covers authority, procedural truth, classification, licensing, governance, domain, Aurion, execution boundary and execution attestation. Conditional verification covers consequentiality, corroboration, financial, autonomy-boundary and escalation thresholds when the current state requires them.

Verification binds permitted type, issuer and issuance stage; request fingerprint; governed state and EIE; tier and applicable corroboration/collective inputs; digest; signature; temporal fields; nonce/replay status; and exact stage semantics. Extra, duplicate, malformed, missing, transplanted, stale or resigned-but-semantically-invalid token material fails closed.

Tokens are evidence of completed controls. They do not independently authorize an effect and cannot override Governance, Procedural Truth, Domain or Aurion.

## Traversal receipt and capability lifecycle

An operational traversal receipt is signed and binds the measured runtime identity, approved baseline identifier, measurement and startup-attestation digests, startup sequence, request fingerprint and traversal-start event. Its claim is atomic and process-local. An operational receipt is single-use; copied, replayed, cross-request or mismatched receipts are rejected. Replay/validation receipts are explicitly non-operational.

The existing capability mechanism is issued only after exact gate convergence. It binds request, EIE, final/preseal state, target, operation, tier, terminal result, runtime identity, issuance sequence and unique identifier. Consumption is atomic and single-use. Cancellation, revocation, expiry, state mutation, replay, cross-request transfer and duplicate consumption make it unusable. Capability material does not become an authority source.

## Denial conservation and convergence divergence

An upstream invalidity cannot become downstream validity. Root of Trust, Procedural Truth, threshold, Classification, Licensing, Governance, GRC, Domain, Aurion, token, hash-chain, EIE, collective-signal, measured-startup, replay or audit-readiness failure is conserved through terminal handling.

Retry, fallback, candidate substitution, restart, replay, direct gate invocation, copied token stacks, reconstructed states, exceptions and overlapping requests cannot restore `EXECUTE` or `APPROVED`.

Full dual-mode divergence removes success surfaces, creates a signed convergence-failure audit record, produces a controlled outcome, records the losing/non-authoritative history and places the request in persistent inoperability. Exact parity is required; near-match reconciliation has no terminal authority.

## Hash-chain and state continuity

The terminal-aware hash profile requires the canonical major-stage progression and exact previous-hash/payload-digest/resulting-hash continuity. Removal, reordering, duplication, prior-hash mutation, payload mutation, truncation, appended fake success and cross-request copying prevent execution.

Terminal finalisation computes and verifies the whole preseal state digest before terminal-only custody fields are attached. The formal verifier consumes that verified digest; it does not rely on a looser reconstruction.

## Audit, custody and replay

Audit is a required evidence layer and never an authority source. Terminal records bind request/EIE/state identity, decision, execution result, governance outcome, token and hash status, capability identifier where issued, runtime identity, failure reason and replay/evidence linkage.

Successful, denied, escalated, validation-failed, replay-rejected, measured-startup-rejected and ambiguous outcomes have distinct terminal evidence. Hard-entry rejection has signed rejection custody rather than a fabricated success-shaped record.

Terminal custody is durably cross-bound into the replay ledger, integrity store, completed event and execution authority. Partial custody, downgrade to a legacy prefix or mismatched terminal digest fails closed.

Replay reconstructs decision-relevant state for exact verification. It is marked `NOT_AUTHORISED`, cannot claim an operational traversal receipt, cannot issue or consume a live capability and cannot cause a fresh effect. Mismatch is reported rather than reconciled.

## Measured-startup continuity

The measured-startup record remains bound from traversal receipt construction through capability issuance, consumption and terminal evidence. Missing, stale, rolled-back, corrupted, unknown, unapproved or changed runtime identity prevents execution.

The test harness uses an ephemeral approved baseline and signing key. A legacy subprocess boundary explicitly discards only its invalidated parent-process startup cache, preventing test cross-contamination without weakening production drift detection.

## Effect acknowledgement and ambiguity

`AUTHORISED TO ATTEMPT` is separate from `EFFECT CONFIRMED SUCCESSFUL`. The local synthetic adapter acknowledgement must exactly match the bound target and operation and must pass integrity validation. Timeout, unknown, partial, unconfirmed, corrupted, absent or mismatched acknowledgement cannot be reported as confirmed success. Ambiguity becomes a controlled non-success terminal state.

## Race and failure semantics

Duplicate receipt claims, capability consumption, nonce reuse, stale/fresh token races, replay overlap, revocation/cancellation overlap, state mutation and concurrent terminal custody are serialized or atomically rejected by the existing single-host mechanisms. Assurance-critical exceptions, audit/custody write failures, malformed state and interrupted terminal processing fail closed.

## Explicit non-authority roles

Tokens, capability objects, audit, replay, telemetry, persistence, UI and measured startup do not own or expand execution authority. They prove, constrain, transport, record or verify the authority already established by the canonical controls.

## Remaining limitations

- The operator environment does not currently supply an authorised `SBP_LEX_SIGNING_SECRET`; direct normal and replay CLI attempts therefore fail closed before traversal.
- Stored release-integrity and local-trust capstone artifacts predate Pass 7 and require an authorised later refresh. No provenance package was created or promoted in this pass.
- The owner has deferred choosing whether ten clean clones will derive from baseline 10 or baseline 12; no clones were created.
- No live SKG/DTN provider, live actuation, cloud, node, quorum, mesh or distributed governance was introduced.
- This pass supplies local runtime engineering evidence only. It is not production readiness, external certification, independent IV&V, complete formal proof or universal containment proof.
