# 12 Audit Replay Telemetry Blueprint

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

Define audit, replay, telemetry, and historical integrity preservation for the expanded control chain.

## Scope

Local deterministic audit/replay only.

## Controlling Responsibilities

Audit and replay must preserve expanded EIE/SKG/DTN/Root/PT/token/execution metadata and detect mutation/dropout.

## Required Inputs

State, hash chain, token trace, audit trace, EIE, Root anchor, PT envelope, PT certification, execution decision, and controlled outcome.

## Required Outputs

Audit record/hash, finalisation result, replay summary/hash/signature, historical integrity verdict, and failure reasons.

## Integration Position In Traversal

Execution Gate -> Audit / Replay / Telemetry.

## What This Component May Do

It may detect mutation, split history, missing metadata, replay mismatch, and audit corruption.

## What This Component Must Not Do

It must not claim external append-only custody or independent timestamping.

## Failure / Denial / Escalation Behaviour

If replay cannot verify the chain, it reports invalid replay. If historical integrity cannot verify metadata, it reports fail-closed invalid history.

## Audit / Replay / Telemetry Requirements

Preserve EIE hash, traversal ID, request fingerprint, source payload hash, state hash, SKG/DTN metadata/hash, Root anchor, PT certification, token-chain reference, audit-chain reference, execution decision, and denial codes.

## Phase 18.8B Hardening Notes

Replay summaries and audit records now include expanded PT-bound metadata and chain references.

## Source Basis

`sbp_lex/audit/audit_engine.py`, `sbp_lex/audit/historical_integrity.py`, `sbp_lex/pipeline/replay_runner.py`.

## Supersession Note

Repository alignment only.

## Remaining External-Production Requirements

External append-only custody, independent timestamping, notarisation export, retention policy, and operational audit review remain external.
