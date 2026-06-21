# Phase 15.6B External SKG/DTN Bridge Readiness

## What bridge readiness means

Bridge readiness means the external SKG package, SKG-constrained DTN package,
and composed pre-context package can be checked as one deterministic chain.
The bridge verifies required fields, request binding, constraint and package
digests, placeholder signatures, freshness, consistency, source metadata, and
the absence of external execution or Governance authority.

The bridge manifest records whether that external chain validated. The demo CLI
can build missing sample packages, validate the chain, and write the manifest.

## What bridge readiness does not mean

Bridge readiness is not ingress acceptance, governance, admissibility, runtime
state creation, execution authorization, or automatic submission. Packages
remain external and untrusted until the existing Hard Entry Gate validates a
later manual submission. The manifest is audit/readiness metadata only; it
cannot replace or bypass request validation or the Hard Entry Gate.

The optional compatibility preview is likewise inert. It exposes package
metadata in a manually inspectable shape and explicitly requires later Hard
Entry validation. It imports no SBP-LEX runtime module and performs no
traversal.

## Preserved authority boundary

- SKG remains an external authority-truth signal producer.
- DTN remains an external operational-context producer constrained by SKG.
- SBP-LEX remains the only component that validates ingress, governs,
  constrains, executes, denies, escalates, and audits.
- Placeholder signing is deterministic test scaffolding and is not production
  cryptography.
- Desktop V1 remains local/private and unchanged.
- Dual Adaptive Deterministic Pipelines remain unchanged.
- No active-node or distributed-runtime topology was introduced.
- No UI/operator cockpit work was started.

## Demo command

```powershell
python -m external_substrates.demo.validate_demo_bridge_package
```

The command prints `BRIDGE_READY` or `BRIDGE_REJECTED` and writes
`external_substrates/demo/sample_bridge_manifest.json`. It does not call
`main.py`, submit to Hard Entry Gate, or modify runtime artifacts.

