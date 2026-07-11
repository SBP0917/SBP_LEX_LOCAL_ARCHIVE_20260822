# Desktop V1 Patent Engineering Alignment Preparation

This is an engineering traceability map, not a legal conclusion.

| Concept | Repository/runtime evidence | Alignment note |
|---|---|---|
| Fail-closed ingress | API mode resolver and pre-bind startup validation | Wording should distinguish invalid configuration from an access denial |
| Contained test bypass | Explicit pytest-only unauthenticated gate | Avoid wording that implies a deployable unauthenticated mode |
| Canonical authority | State construction, Root of Trust, Governance and Execution Gate | Implementation retains sole canonical-runtime authority |
| Deterministic dual traversal | Pipeline modes, convergence hashes and replay | Preserve exact-parity/reducer distinctions |
| External truth/context | SKG/DTN bridge and Hard Entry Gate | External packages remain non-authoritative |
| Classification then Licensing | Separate runtime modules and traversal evidence | Do not collapse these layers in doctrine or claims mapping |
| PQC readiness | ML-DSA provider/policy runtime evidence | Separate provider readiness from broad production certification |

Potential moat-strengthening alignment issues are terminology precision, explicit configuration-failure semantics, and test-bypass non-deployability. Trade-secret-sensitive implementation details should remain at property/traceability level rather than exposing internal key or enforcement mechanics.
