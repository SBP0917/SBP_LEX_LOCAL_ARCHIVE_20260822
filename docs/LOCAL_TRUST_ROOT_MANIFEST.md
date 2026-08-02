# Local Trust Root Manifest

## Purpose

The Local Trust Root Manifest records local repository provenance for Desktop V1 verification. It captures the repository commit, branch, working-tree state, Python runtime identity, intended verification commands, critical file hashes, trusted report hashes, and phase baseline evidence.

The manifest is local evidence tooling only. It is not SBP-LEX runtime authority.

## Local-Only Trust Problem

Desktop V1 is local/private, but local does not automatically mean trusted. A local baseline can be weakened by the wrong Python runtime, wrong working directory, dirty repository state, mutated reports, dependency substitution, test-runner substitution, artifact overwrite, local evidence poisoning, or operator shortcut.

Phase 18.7B makes the local verification baseline self-describing, hash-bound, provenance-bound, and verifiable.

## Manifest Structure

The manifest includes:

- manifest identity and version
- creation timestamp
- repository root provenance
- relative-path digest scope
- Git branch, commit, short status, and clean/dirty state
- Python executable, version, and runtime digest when available
- intended command provenance
- critical file hashes
- trusted report hashes
- trusted output hashes
- integrity-store and quarantine-evidence presence status
- test, runtime, replay, and phase baselines
- local trust status and validation failures
- payload digest, manifest digest, and ML-DSA-65 signature bound to the
  explicitly configured trusted public key

Absolute paths may appear as provenance fields. Digest construction uses stable JSON canonicalisation and repository-relative paths for file evidence.

## Critical File Hashing

Phase 18.7B hashes critical files that define or protect the local baseline, including:

- `main.py`
- `scripts/run_tests.bat`
- `sbp_lex/persistence/integrity_store.py`
- `sbp_lex/execution/execution_gate.py`
- `sbp_lex/governance/procedural_truth_engine.py`
- `sbp_lex/governance/procedural_truth_runner.py`
- `sbp_lex/authority_first/root_of_trust_runner.py`
- `sbp_lex/shared/hash_chain.py`
- `sbp_lex/shared/state_builder.py`
- `sbp_lex/pipeline/dual_runner.py`

Missing files are recorded deterministically as `MISSING`; they are not ignored.

## Report And Output Hashing

The manifest attempts to hash current evidence reports from Phase 18, 18.5, 18.6, RED-20A/B/C/D, and SBP Operator Assistant V1. Known output reports are also checked. Missing outputs are recorded as `MISSING`.

## Status Meanings

- `LOCAL_TRUST_VALID`: manifest digest/signature validates and required provenance is present.
- `LOCAL_TRUST_INVALID`: digest mismatch, tampering, malformed schema, or forbidden authority output detected.
- `LOCAL_TRUST_INCOMPLETE`: required sections or critical-file evidence are missing.
- `LOCAL_TRUST_STALE`: manifest commit does not match current commit during current validation.
- `LOCAL_TRUST_DIRTY`: working tree is dirty when clean validation is explicitly required.

## Forbidden Authority Outputs

The manifest and validator must not emit runtime authority outcomes. They reject or flag authority-leakage fields such as external execution permission, external Governance result, runtime authority, execution allowance, or runtime decision/execution result values.

Local trust status remains separate from SBP-LEX runtime decision outcomes.

## Relationship To Phase 18.7A

Phase 18.7A preserves poisoned integrity-store evidence. Phase 18.7B broadens that idea to the wider local verification baseline by hashing and attributing repository files, reports, outputs, runtime provenance, and command provenance.

## Relationship To Future 18.7C

Phase 18.7B records intended verification commands but does not execute them. A later execution-environment trust envelope can capture actual command execution outputs, timing, and environment evidence.

## Strict Boundary

This manifest does not change SBP-LEX runtime authority, Governance, Procedural Truth, SKG, DTN, Hard Entry Gate, Classification, Licensing, Domain, Aurion, Execution Gate, audit, replay, token logic, hash-chain logic, chronology logic, or pipeline convergence logic.

It does not introduce runtime activation, external execution authority, distributed trust, cloud service work, APK work, V2, or V3.
