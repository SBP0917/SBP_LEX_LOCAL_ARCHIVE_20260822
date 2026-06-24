# Local Evidence Chain / Report Integrity Attestation

## Purpose

The Local Evidence Chain records deterministic integrity evidence for phase reports, trusted outputs, local manifests, execution envelopes, and documentation. It makes local evidence tamper-evident after tests have already passed.

This layer is local evidence tooling only. It is not runtime authority.

## Why Local Evidence Can Drift

Reports and output artifacts can be changed after verification by overwrite, deletion, substitution, stale copy/paste, wrong checkout, or session confusion. A passing test suite does not prove that the reports and evidence files preserved afterward are still the same files that were verified.

## Relationship To 18.7A, 18.7B, And 18.7C

Phase 18.7A preserves quarantine evidence for poisoned persistence artifacts.

Phase 18.7B creates the Local Trust Root Manifest for repository and runtime provenance.

Phase 18.7C creates the Local Execution Environment Trust Envelope for command provenance and captured verification evidence.

Phase 18.7D binds to both 18.7B and 18.7C, then hashes the local evidence files that describe the completed phases.

## Evidence Chain Structure

The chain records repository provenance, Git commit, branch, working-tree state, bound manifest path/digest/status, bound execution envelope path/digest/status, evidence scope, evidence items, missing evidence items, excluded volatile paths, deterministic payload digest, chain digest, placeholder signature, signature mode, status, and validation failures.

## Evidence Item Structure

Each evidence item records evidence ID, path, category, required flag, existence, size, SHA-256 hash, last modified timestamp, content type, source phase, and attestation status.

Missing files are recorded deterministically rather than ignored.

## Manifest And Envelope Binding

The chain loads `outputs/local_trust_root_manifest.json` and `outputs/local_execution_environment_trust_envelope.json` by default. It records their digests and binding status. Missing, invalid, stale, or mismatched binding prevents the evidence chain from reporting a valid status.

## Tamper Detection

The validator detects malformed chains, digest mismatches, missing required sections, forbidden authority leakage, stale commits during current validation, and dirty working trees when clean validation is requested.

The compare mode recomputes evidence item hashes against current files and reports changed, missing, replaced, or newly appeared evidence.

## Excluded Paths

The chain explicitly excludes volatile paths:

- `.pytest_cache`
- `.pytest_tmp_*`
- `outputs/local_trust_temp`
- `__pycache__`
- `*.pyc`
- `.git`

These paths are not trusted evidence and must not be committed as evidence.

## Status Meanings

- `EVIDENCE_CHAIN_VALID`: chain structure, digests, bindings, and current evidence comparison validate.
- `EVIDENCE_CHAIN_INVALID`: chain tampering, malformed schema, changed evidence, or forbidden authority leakage was detected.
- `EVIDENCE_CHAIN_INCOMPLETE`: required binding to the manifest or envelope is missing or invalid.
- `EVIDENCE_CHAIN_STALE`: the recorded commit does not match the current checkout during current validation.
- `EVIDENCE_CHAIN_DIRTY`: clean validation was required and the working tree was not clean.

## Forbidden Authority Leakage

The evidence chain rejects active authority fields such as execution permission, Governance result, runtime authority, allow-execution fields, and external allow/deny/escalate fields.

Existing observed runtime words may appear only inside previously trusted reports, manifests, or envelopes as preserved evidence. The evidence chain itself does not issue runtime decisions.

## Strict Boundary

The evidence chain does not change SBP-LEX runtime authority, Governance, Procedural Truth, SKG, DTN, Hard Entry Gate, Classification, Licensing, Domain, Aurion, Execution Gate, audit logic, replay logic, token logic, hash-chain logic, chronology logic, or pipeline convergence logic.

It does not introduce runtime activation, automatic external traversal submission, external execution permission, nodes, quorum, mesh, distributed runtime, cloud service, APK, V2, or V3 work.
