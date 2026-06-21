# External SKG and DTN Substrates

This package builds deterministic, attested pre-context signals outside the
SBP-LEX runtime. SKG prepares authority-truth signals. DTN prepares operational
context under a validated SKG constraint package. Neither substrate governs,
executes, mutates internal state, or bypasses the Hard Entry Gate.

The only supported boundary object is a signed, digest-bound, request-bound,
freshness-bearing signal package. Desktop V1 and its Dual Adaptive
Deterministic Pipelines remain unchanged.

