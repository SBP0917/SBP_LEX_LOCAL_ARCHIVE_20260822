# 09 Domain Admissibility Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define Domain as a downstream admissibility wrapper after Governance/GRC.

## Scope

Local domain checks for the repository traversal.

## Controlling Responsibilities

Domain may run only when Governance allows and GRC passes.

## Required Inputs

Governance result/token, GRC result, EIE/request identity, context, domain constraints, and upstream token lineage.

## Required Outputs

Domain result, domain feedback, token, and denial reason.

## Integration Position In Traversal

Governance -> GRC -> Domain -> Aurion.

## What This Component May Do

It may apply local domain admissibility constraints.

## What This Component Must Not Do

It must not bypass Governance/GRC or treat domain success as execution permission.

## Failure / Denial / Escalation Behaviour

Missing Governance/GRC admissibility, invalid upstream tokens, or control-chain mismatch denies before Aurion/Execution.

## Audit / Replay / Telemetry Requirements

Domain result and token lineage must be preserved.

## Phase 18.8B Hardening Notes

Domain remains downstream of stronger upstream control-chain validation.

## Source Basis

`sbp_lex/domains/runner.py`, `sbp_lex/security/domain_admissibility.py`, `sbp_lex/security/authority_boundary.py`.

## Supersession Note

Repository alignment only.

## Remaining External-Production Requirements

Real domain-specific authority datasets and independent domain validation remain external.
