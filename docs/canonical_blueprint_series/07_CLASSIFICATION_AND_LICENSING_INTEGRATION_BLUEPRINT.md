# 07 Classification and Licensing Integration Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define Classification and Licensing as downstream-only layers that require valid Root/PT/EIE control-chain state.

## Scope

Local classification and licensing decision gates.

## Controlling Responsibilities

Classification may run only after PT_PASS and certification. Licensing may run only after Classification ALLOW.

## Required Inputs

Canonical upstream tokens, EIE binding, PT certification, AP/ACF declaration, context, autonomy ceiling, licensing scope, and request fingerprint.

## Required Outputs

Classification result/token, pipeline mode, licensing result/token, and denial reasons.

## Integration Position In Traversal

PT -> Classification -> Licensing -> Governance.

## What This Component May Do

It may classify admissible state and apply licensing/autonomy constraints.

## What This Component Must Not Do

It must not run on missing PT certification or accept upstream labels without token/control-chain verification.

## Failure / Denial / Escalation Behaviour

Missing PT token, malformed EIE, invalid Root, or stage bypass denies before Classification or Licensing.

## Audit / Replay / Telemetry Requirements

Classification and licensing results, tokens, failures, and pipeline mode must be preserved.

## Phase 18.8B Hardening Notes

`validate_canonical_upstream` now checks shared EIE/SKG/DTN/Root bindings in addition to tokens and stage lineage.

## Source Basis

`sbp_lex/classification/engine.py`, `sbp_lex/licensing/engine.py`, `sbp_lex/security/authority_boundary.py`.

## Supersession Note

Repository alignment only.

## Remaining External-Production Requirements

Production classification policy review, licensed deployment constraints, real regulatory analysis, and independent assurance remain external.
