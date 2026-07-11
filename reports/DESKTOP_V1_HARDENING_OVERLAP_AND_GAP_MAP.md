# Desktop V1 Hardening Overlap and Gap Map

## Classification

| Candidate | Classification | Coverage / disposition |
|---|---|---|
| Strict API security-mode validation | NEW DESKTOP V1 HARDENING | H1A implemented |
| Unknown/empty mode fail-closed startup | NEW FORMALISATION | H1A implemented |
| Test-only unauthenticated mode | NEW DESKTOP V1 HARDENING | H1B implemented |
| Request body size and replay bounds | ALREADY COVERED | `access_control.py` and server enforcement |
| API rate limiting | ALREADY COVERED | `API_RATE_LIMITER` |
| JSON schema and duplicate-key rejection | ALREADY COVERED | strict JSON/schema validation |
| Canonical traversal/state/authority invariants | ALREADY COVERED | security boundary and RED tests |
| Replay determinism and causal hashes | ALREADY COVERED | replay runner and validation suites |
| JSONL/checkpoint integrity | ALREADY COVERED | persistence and local-trust suites |
| External placeholder signature rejection | PARTIALLY COVERED | External packages remain untrusted; production-signature upgrade remains separate |
| Scoped API identities and body-to-identity binding | PARTIALLY COVERED | Bearer-token boundary exists; richer identity scopes require a separately bounded design |
| Trusted proxy handling | NOT APPLICABLE TO DESKTOP V1 | Local/private single-host topology |
| Bounded ledger retention policy | PARTIALLY COVERED | Defer: policy choice and migration risk exceed this package |
| UI stale/replay/simulation distinction | ALREADY COVERED | Desktop dashboard and simulation separation |
| PQC migration readiness | ALREADY COVERED | ML-DSA provider/policy and tests |

## Overlap elimination and council review

The 31-pass, physics/control/quantum, RED, local-trust, and multidisciplinary lenses repeatedly map to the same canonical-state, authority-boundary, replay, integrity, and fail-closed properties. They are recorded once above. H1A/H1B were selected because they are objectively testable, architecture-preserving, deterministic, low-coupling, and close a confirmed unauthenticated boundary. Larger identity, retention, and production-signature changes were not partially implemented.
