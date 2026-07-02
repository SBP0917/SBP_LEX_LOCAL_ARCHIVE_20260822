# 08 Governance and GRC Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define Governance and GRC as downstream admissibility controls that require Classification/Licensing and valid PT control-chain state.

## Scope

Local deterministic governance and re-entry control.

## Controlling Responsibilities

Governance must deny confused-deputy attempts, token omissions, stage bypasses, and pre-governance PT/classification failures.

## Required Inputs

Authority, PT, Classification, Licensing tokens, EIE bindings, Root anchor, governance feedback, and request fingerprint.

## Required Outputs

Governance result/token, GRC result, governed re-entry state, controlled return flags, and failure reasons.

## Integration Position In Traversal

Licensing -> Governance -> GRC -> Domain.

## What This Component May Do

It may allow, deny, or escalate based on admissibility and re-entry rules.

## What This Component Must Not Do

It must not authorise execution, skip PT, or accept dossier claims as runtime authority.

## Failure / Denial / Escalation Behaviour

Missing PT certification, missing token, invalid EIE, invalid Root, or no Classification-admissible state denies before Governance success.

## Audit / Replay / Telemetry Requirements

Governance/GRC result, failure reasons, and controlled return state must be recorded.

## Phase 18.8B Hardening Notes

Pre-governance denial is covered by negative tests for missing PT token and canonical upstream failure.

## Source Basis

`sbp_lex/governance/engine.py`, `sbp_lex/governance/grc.py`, `sbp_lex/security/authority_boundary.py`.

## Supersession Note

Repository alignment only.

## Remaining External-Production Requirements

Formal governance policy review, institutional approval, operational incident response, and legal/regulatory review remain external.
