# 10 Aurion Constrained Pathway Selection Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define Aurion as constrained pathway selection after Domain admissibility.

## Scope

Local deterministic Aurion candidate/pathway control.

## Controlling Responsibilities

Aurion may select constrained candidates only after Domain passes and upstream control-chain state is valid.

## Required Inputs

Domain result/token, current candidate, context, pipeline mode, threshold state, EIE/request identity, and token lineage.

## Required Outputs

Aurion result/token, candidate selection, and pathway constraints.

## Integration Position In Traversal

Domain -> Aurion -> Execution Gate.

## What This Component May Do

It may rank or constrain candidate pathways.

## What This Component Must Not Do

It must not execute, override PT, or skip Execution Gate verification.

## Failure / Denial / Escalation Behaviour

No Domain pass, invalid lineage, malformed tokens, or invalid candidate state prevents Execution Gate allowance.

## Audit / Replay / Telemetry Requirements

Aurion result, candidate ID, token, and failure state must be traceable.

## Phase 18.8B Hardening Notes

Execution Gate direct-call bypass tests require Aurion stage lineage before execution.

## Source Basis

`sbp_lex/aurion15/runtime/runner.py`, `sbp_lex/aurion15/runtime/constraint_validator.py`, `sbp_lex/execution/execution_gate.py`.

## Supersession Note

Repository alignment only.

## Remaining External-Production Requirements

Production pathway validation, safety review, and operational monitoring remain external.
