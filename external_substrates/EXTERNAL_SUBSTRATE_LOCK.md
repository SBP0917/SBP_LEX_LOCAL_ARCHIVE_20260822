# Phase 15.6A External Substrate Lock

- SKG and DTN are external substrates.
- They prepare authority-truth and operational-context signals only.
- They do not govern or execute.
- They do not directly mutate SBP-LEX internal state.
- SKG constrains DTN; DTN cannot evaluate without a valid SKG package.
- Only signed, digest-bound, request-bound, freshness-bearing packages may
  approach the existing Hard Entry Gate.
- The Hard Entry Gate, Execution Gate, Desktop V1 local/private posture, audit
  chain, replay determinism, and Dual Adaptive Deterministic Pipelines remain
  internal and unchanged.
- No active nodes, quorum, distributed consensus, mesh, or multi-node runtime
  execution are introduced.

