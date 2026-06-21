# Procedural Truth Binding During State Construction

## Purpose

Phase 18 binds evidence derived from admitted pre-context metadata into canonical state before Procedural Truth evaluation. It does not activate external-package traversal, bypass Hard Entry Gate, or move authority into an external substrate.

## Architecture position

The controlled sequence remains: external SKG and DTN substrates produce context packages; the external bridge validates package integrity; Hard Entry Gate admits or rejects input; State Builder records an immutable PT Evidence Envelope; Root of Trust anchors that envelope; Procedural Truth evaluates it inside the canonical SBP-LEX control plane.

SBP-LEX remains the sole runtime authority. SKG supplies authority-truth signals, DTN supplies operational context constrained by SKG, and neither substrate governs, executes, or mutates canonical state.

## PT Evidence Envelope

State Builder records the request fingerprint, SKG digest, DTN digest, admitted pre-context digest, source provenance, source records, aggregate verification/attestation/freshness/consistency status, locked threshold tier and requirement, qualifying-source count, and deterministic observation failures. The envelope receives a deterministic digest.

State Builder does not decide the PT outcome. Procedural Truth validates the envelope digest and request binding, recomputes the locked threshold, rejects tier substitution or threshold relaxation, and counts only sources that are verified, attested, fresh, and consistent.

## Root of Trust anchorage

Root of Trust creates a canonical-runtime signature over the request fingerprint, SKG digest, DTN digest, pre-context digest, and PT envelope digest. External package signatures do not manufacture internal authority and cannot replace the Root of Trust anchor.

## Locked threshold rules

- TOP requires 5 qualifying confirmations.
- MEDIUM requires 3 qualifying confirmations.
- LOW requires 2 qualifying confirmations.

There is no silent downgrade, tier substitution, or threshold relaxation. PT-only outcomes are `PT_PASS`, `PT_REFINE`, `PT_ESCALATE`, and `PT_FAIL`; they are not Governance, Domain, Aurion, or execution outcomes.

## Audit, replay, and controlled re-entry

Audit records the PT envelope digest, threshold tier and requirement, qualifying-source count, PT outcome, deterministic failure reasons, source provenance summary, and Root of Trust evidence anchor. Replay compares the PT outcome and envelope digest so identical input must reproduce identical PT results.

PT failure produces a non-executable state. Re-entry is not automatic: corrected evidence, a corrected source package, corrected validation state, and full retraversal are required.

## External substrate limitations

SKG, DTN, and the bridge remain external. Their packages remain untrusted until accepted by Hard Entry Gate. This phase does not make bridge metadata execution authority, does not introduce direct runtime injection, and does not change external packages to emit Governance results or execution permission. Placeholder external signing remains non-production.

Desktop V1 remains local/private. The Dual Adaptive Deterministic Pipelines are preserved. No UI, APK, cloud, node, quorum, mesh, or distributed-runtime work is introduced.
