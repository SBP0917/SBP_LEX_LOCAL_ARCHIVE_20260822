# Local Execution Environment Trust Envelope

## Purpose

The Local Execution Environment Trust Envelope records local command execution evidence for SBP-LEX Desktop V1. It binds command provenance to the Phase 18.7B Local Trust Root Manifest so local verification can be attributed to a specific repository baseline, Python runtime, working directory, manifest digest, command list, and bounded command output evidence.

This envelope is local evidence tooling only. It is not runtime authority.

## Why Local Execution Evidence Is Not Automatically Trusted

A local verification result can be misleading if it was produced with the wrong Python runtime, wrong shell path, wrong working directory, wrong checkout, stale manifest, mutated test runner, truncated command output, or operator copy/paste error. The envelope reduces that ambiguity by recording deterministic command evidence and hashing command output.

## Relationship To 18.7A And 18.7B

Phase 18.7A preserves quarantine evidence for poisoned persistence artifacts.

Phase 18.7B creates the Local Trust Root Manifest for repository provenance and baseline hashing.

Phase 18.7C binds execution evidence to the 18.7B manifest and records command provenance for verification runs. If the manifest is missing or invalid, the envelope cannot claim a valid local execution environment status.

## Manifest Binding

The envelope loads `outputs/local_trust_root_manifest.json` by default. It records the manifest path and digest. Missing manifests are recorded as `LOCAL_TRUST_MANIFEST_MISSING`; malformed or digest-invalid manifests are recorded as `LOCAL_TRUST_MANIFEST_INVALID`.

## Command Provenance

Each command result records command identity, command text, argument vector, start/finish timestamps, duration, exit code, stdout/stderr digests, bounded excerpts, working directory, Python executable for Python commands, and command status.

Supported command status values are:

- `COMMAND_PASS`
- `COMMAND_FAIL`
- `COMMAND_NOT_RUN`
- `COMMAND_SKIPPED`
- `COMMAND_TIMEOUT`
- `COMMAND_ERROR`

## Python And Working Directory Provenance

The envelope records `sys.executable`, Python version, repository root, working directory, Git commit, Git branch, working-tree cleanliness, shell type if available, and a safe PATH digest/summary. It does not store a full environment dump.

## Output Digesting And Excerpts

Stdout and stderr are SHA-256 hashed in full. Stored excerpts are bounded and deterministic, so large command output cannot overwrite the evidence envelope or create unstable report size.

## Runtime And Replay Evidence

When `python main.py` is captured, the envelope summarizes observed runtime output fields such as decision, execution result, pipeline mode, convergence match, token failures, exit code, and output digests.

When `python main.py replay` is captured, the envelope summarizes replay count, match status, mismatches, exit code, and output digests.

These are evidence-only summaries. They do not create Governance authority, execution permission, or replay legitimacy beyond the existing runtime behavior.

## Envelope Status Values

- `EXECUTION_ENV_VALID`: required fields, digest binding, manifest binding, and command structure validate.
- `EXECUTION_ENV_INVALID`: digest mismatch, malformed schema, tampering, or forbidden authority leakage detected.
- `EXECUTION_ENV_INCOMPLETE`: required provenance or manifest binding is missing or invalid.
- `EXECUTION_ENV_STALE`: the recorded commit does not match the current checkout during current validation.
- `EXECUTION_ENV_DIRTY`: clean validation was required and the working tree was not clean.

## Forbidden Authority Outputs

The envelope rejects active authority fields such as execution permission, Governance result, external allow/deny/escalate fields, runtime authority, or allow-execution fields. Runtime words from `main.py` and replay may appear only as observed evidence inside command output excerpts or runtime/replay summary fields.

## Strict Boundary

The envelope does not change Governance, Procedural Truth, SKG, DTN, Hard Entry Gate, Classification, Licensing, Domain, Aurion, Execution Gate, audit logic, replay logic, token logic, hash-chain logic, chronology logic, or pipeline convergence logic.

It does not introduce runtime activation, automatic external traversal submission, external execution permission, nodes, quorum, mesh, distributed runtime, cloud service, APK, V2, or V3 work.
