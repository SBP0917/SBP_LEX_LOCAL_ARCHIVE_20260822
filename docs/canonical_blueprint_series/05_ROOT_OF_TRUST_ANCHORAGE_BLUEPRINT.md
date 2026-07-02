# 05 Root of Trust Anchorage Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define local Root of Trust Anchorage for EIE, SKG, DTN, evidence, state, token, and audit bindings.

## Scope

Local deterministic Root anchor only; not HSM/TPM-backed production trust custody.

## Controlling Responsibilities

Root must bind EIE identity/hash, source payload hash, adapter/source identity, SKG status/hash, DTN status/hash, evidence package hash, state hash at anchoring, traversal ID, request fingerprint, token-chain reference, and audit-chain reference.

## Required Inputs

Accepted Hard Entry state, EIE, PT evidence envelope, SKG/DTN metadata, token trace, audit trace, and state hash.

## Required Outputs

Root anchor payload, digest, signature, anchorage status, failures, and bound state-hash reference.

## Integration Position In Traversal

State Construction -> Root of Trust Anchorage -> Procedural Truth certification.

## What This Component May Do

It may deny malformed/missing/mismatched anchor material and issue the authority token only after Root engines pass.

## What This Component Must Not Do

It must not bypass SKG/DTN or certify PT sufficiency by itself.

## Failure / Denial / Escalation Behaviour

Missing, mismatched, stale, or malformed Root material fails closed and prevents PT and Classification.

## Audit / Replay / Telemetry Requirements

Root anchor digest, payload, signature, failures, token-chain reference, audit-chain reference, and bound state hash must be preserved.

## Phase 18.8B Hardening Notes

Root now invokes shared EIE/SKG/DTN validators before anchoring and preserves `root_anchor_bound_state_hash` for downstream validation.

## Source Basis

`sbp_lex/authority_first/root_of_trust_runner.py`, `sbp_lex/shared/control_chain_validation.py`, `tests/test_phase_18_8b_repository_hardening.py`.

## Supersession Note

Repository implementation alignment only.

## Remaining External-Production Requirements

Hardware-backed key custody, isolated root process, rotation/revocation, independent verifier, and external notarisation remain external.
