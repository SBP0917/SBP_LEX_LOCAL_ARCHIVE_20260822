# 01 Master Architecture and Traversal Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define the repository-contained SBP-LEX Dual V6 traversal order and the fail-closed control-chain responsibilities used for university technical review.

## Scope

Local deterministic control-plane prototype only. No production deployment readiness, external certification, safety-critical approval, or formal university validation is claimed.

## Controlling Responsibilities

The traversal must preserve order, bind request identity through the EIE, require SKG/DTN enrichment before Root/PT, deny before Classification when the chain is malformed, and deny before Governance when Classification-admissible state is not reached.

## Required Inputs

Runtime request, native payload, adapter/source identity, source payload hash, request fingerprint, pre-context SKG/DTN signals, evidence records, threshold context, token trace, and audit trace.

## Required Outputs

EIE canonical traversal state, Root anchor, PT certification, layer tokens, execution decision, audit record, replay summary, and dossier evidence.

## Integration Position In Traversal

External System -> Native Format / Protocol -> Adapter Translation -> EIE -> SKG -> DTN -> Pre-context -> Hard Entry -> State Construction -> Root -> PT -> Classification -> Licensing -> Governance -> GRC -> Domain -> Aurion -> Execution Gate -> Audit / Replay / Telemetry.

## What This Component May Do

It may coordinate stage order, assert required bindings, and describe denial boundaries.

## What This Component Must Not Do

It must not reorder traversal, invent active nodes, claim external authority, or treat dossier evidence as runtime permission.

## Failure / Denial / Escalation Behaviour

A rogue, fraudulent, malformed, mismatched, stale, weakly evidenced, contradictory, unanchored, or token-invalid EIE is designed to fail closed before Classification and before Governance under the Phase 18.8B repository-contained control-chain checks.

## Audit / Replay / Telemetry Requirements

Audit and replay must preserve EIE hash, traversal ID, request fingerprint, state hash, SKG/DTN hashes, Root anchor, PT certification, token-chain reference, execution decision, and denial reason codes.

## Phase 18.8B Hardening Notes

Phase 18.8B adds reusable control-chain validation, Root-bound state hash preservation, expanded negative tests, and dossier overclaim detection.

## Source Basis

`sbp_lex/pipeline/runner.py`, `sbp_lex/pipeline/dual_runner.py`, `sbp_lex/shared/control_chain_validation.py`, `tests/test_phase_18_8b_repository_hardening.py`.

## Supersession Note

This document aligns the repository implementation and does not silently replace owner-approved master doctrine.

## Remaining External-Production Requirements

Production requires external trust custody, real deployment isolation, authoritative registries, formal threat model, monitoring, incident response, and independent validation.
