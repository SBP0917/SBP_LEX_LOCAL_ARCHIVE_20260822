# 02 EIE Adapter Ingress Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define EIE as the canonical traversal state after adapter ingress.

## Scope

Repository-contained EIE construction and validation for local runtime requests.

## Controlling Responsibilities

EIE must carry object type, version, adapter identity, source identity, native format, source payload hash, request fingerprint, traversal ID, intent, payload, context, SKG metadata, and DTN metadata.

## Required Inputs

Native request, adapter identity, source system identity, payload, context, resolved authority, jurisdiction, and admitted pre-context signals.

## Required Outputs

Canonical EIE, EIE hash, traversal ID, source payload hash, request fingerprint, and state formalisation.

## Integration Position In Traversal

Adapter Translation -> EIE -> SKG -> DTN -> Pre-context -> Hard Entry -> State Construction.

## What This Component May Do

It may formalise request identity, bind source payload hash, and reject malformed or impossible EIE values.

## What This Component Must Not Do

It must not authorise execution, bypass SKG/DTN, or replace downstream Root/PT evidence with adapter assertions.

## Failure / Denial / Escalation Behaviour

Missing EIE identity, source identity, adapter identity, source payload hash, request fingerprint, traversal ID, or EIE hash is fail-closed before Classification.

## Audit / Replay / Telemetry Requirements

EIE hash, traversal ID, source payload hash, request fingerprint, adapter identity, and source identity must be preserved.

## Phase 18.8B Hardening Notes

`canonical_eie_digest` excludes downstream Root/PT result containers while binding identity, source, request, traversal, SKG, and DTN.

## Source Basis

`sbp_lex/shared/state_builder.py`, `sbp_lex/shared/control_chain_validation.py`, `sbp_lex/collective/context_interface.py`.

## Supersession Note

This document aligns current implementation and does not silently replace owner doctrine.

## Remaining External-Production Requirements

Real adapter contract suite, external schema registry, credentialed source identity, and deployed adapter conformance testing remain future work.
