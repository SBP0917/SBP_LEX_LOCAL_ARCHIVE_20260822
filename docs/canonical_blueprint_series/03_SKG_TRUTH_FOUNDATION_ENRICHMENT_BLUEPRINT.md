# 03 SKG Truth Foundation Enrichment Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define SKG truth-foundation enrichment as non-authoritative metadata required by PT and Root.

## Scope

Local deterministic SKG metadata, hash, status, provenance, independence, freshness, consistency, attestation, authority, and jurisdiction signals.

## Controlling Responsibilities

SKG must enrich the EIE with truth-foundation metadata and `skg_enrichment_hash`, while remaining context-only and non-authoritative.

## Required Inputs

Request fingerprint, authority links, jurisdiction, source records, evidence records, policy conflicts, provenance, and source independence.

## Required Outputs

SKG metadata with `skg_verification_status=VALID`, `truth_foundation_readiness_status=READY`, and a valid enrichment hash.

## Integration Position In Traversal

EIE -> SKG verification of EIE truth foundations -> DTN -> Pre-context.

## What This Component May Do

It may provide provenance, relationship, authority, jurisdiction, freshness, consistency, contradiction, attestation, and integrity metadata.

## What This Component Must Not Do

It must not grant execution permission, produce governance results, or claim external authority.

## Failure / Denial / Escalation Behaviour

Missing, mismatched, malformed, or invalid SKG metadata fails before PT certification and before Classification.

## Audit / Replay / Telemetry Requirements

SKG status, digest, metadata, and enrichment hash must be preserved in EIE, PT envelope, Root, audit, and replay summaries.

## Phase 18.8B Hardening Notes

The shared control-chain validator requires SKG status, readiness, completeness, and enrichment hash integrity.

## Source Basis

`sbp_lex/collective/sovereign_knowledge_graph_engine.py`, `external_substrates/skg/signal_builder.py`, `sbp_lex/shared/control_chain_validation.py`.

## Supersession Note

This document aligns repository implementation and leaves owner canonisation open.

## Remaining External-Production Requirements

Authoritative SKG service deployment, external registries, real certificate-backed source identity, and independent validator process remain external requirements.
