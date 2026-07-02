# Draft Audit / Replay / Telemetry Metadata Addendum

Status: Draft repository-side implementation alignment material pending owner canonisation. This addendum does not replace master canonical doctrine.

Purpose: Preserve EIE, SKG, DTN, Root of Trust, and Procedural Truth certification metadata for deterministic replay and traceability.

Affected components: `sbp_lex/audit/audit_engine.py`, `sbp_lex/pipeline/replay_runner.py`, telemetry-like dashboard/report consumers.

New responsibility boundaries: Audit records metadata and verification surfaces. Audit does not certify PT or authorise execution.

What must be implemented: audit payloads include EIE hash, traversal ID, PT envelope digest, PT certification, SKG metadata, DTN metadata, root anchor, threshold floor information, source provenance summary, reason codes, and stage order.

What must not be changed: replay remains deterministic and local; no cloud, external services, distributed runtime, active nodes, quorum, or blockchain are introduced.

Integration points: Audit runs after terminal control state; replay compares deterministic outputs including PT envelope and certification metadata.

Required tests: audit preserves new metadata and replay remains deterministic for identical inputs.

Remaining limitations: No separate telemetry transport is introduced; metadata is preserved in existing audit/runtime artifacts.
