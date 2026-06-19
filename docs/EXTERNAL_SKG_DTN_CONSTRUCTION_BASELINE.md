# Phase 15.6A External SKG/DTN Construction Baseline

## Locked architecture

1. External SKG resolves declared authority truth and prepares attested signals.
2. External DTN accepts a validated SKG package as an immutable constraint and
   prepares operational-context signals.
3. The external composer combines selected SKG and DTN signals into one
   request-bound, digest-bound, signature-bound, freshness-bearing package.
4. Only that package may later approach the existing Hard Entry Gate.
5. SBP-LEX alone validates ingress, governs, constrains, executes, denies,
   escalates, and audits.

## Non-authority guarantee

External substrates cannot return execution permission, execution results,
governance results, or final admissibility. Shared validators recursively reject
those authority fields. The demo never imports or invokes the SBP-LEX runtime.

## Preserved Desktop V1 baseline

No Phase 15.6A source is placed under `sbp_lex/`. Desktop V1 remains the local,
private prototype. Hard Entry Gate and Execution Gate strictness, deterministic
replay, token/hash/audit enforcement, and Dual Adaptive Deterministic Pipelines
are unchanged.

## Topology lock

The construction adds data-preparation modules only. It adds no active nodes,
quorum, distributed consensus, mesh, multi-node execution, cloud runtime, or
alternate execution authority.

