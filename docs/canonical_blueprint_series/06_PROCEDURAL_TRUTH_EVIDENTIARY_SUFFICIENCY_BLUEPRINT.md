# 06 Procedural Truth Evidentiary Sufficiency Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define Procedural Truth certification as evidentiary sufficiency, not source-count approval.

## Scope

Local deterministic PT certification for repository traversal.

## Controlling Responsibilities

PT must require source floor, independence, provenance, integrity, attestation, authority, jurisdiction, freshness, consistency, contradiction handling, runtime validity, consequence-weighted burden, SKG status, DTN status, Root status, and explicit NOT_CERTIFIED behaviour.

## Required Inputs

PT evidence envelope, Root anchor, SKG/DTN metadata, threshold snapshot, source records, governance feedback, and token state.

## Required Outputs

PT result, PT outcome, certification object, failure reasons, required action, PT token hash, and NOT_CERTIFIED state when insufficient.

## Integration Position In Traversal

Root of Trust Anchorage -> Procedural Truth certification -> Classification.

## What This Component May Do

It may certify sufficient evidence or return REFINE, ESCALATE, or DENY/NOT_CERTIFIED.

## What This Component Must Not Do

It must not treat source count alone as sufficient or ignore unresolved contradiction.

## Failure / Denial / Escalation Behaviour

Weakly evidenced, contradictory, unanchored, SKG/DTN-invalid, or token-invalid EIEs fail before Classification.

## Audit / Replay / Telemetry Requirements

PT certification fields and reason codes must be preserved in EIE, audit, replay, and dossier evidence.

## Phase 18.8B Hardening Notes

Execution Gate now rechecks PT traversal ID, token hash, Root/SKG/DTN status, and sufficiency factors.

## Source Basis

`sbp_lex/governance/procedural_truth_engine.py`, `sbp_lex/governance/procedural_truth_envelope.py`, `tests/test_phase_18_8b_repository_hardening.py`.

## Supersession Note

Repository alignment only; owner canonisation pending.

## Remaining External-Production Requirements

Independent evidence registries, formal evidentiary standards review, external source attestation, and legal/regulatory review remain external.
