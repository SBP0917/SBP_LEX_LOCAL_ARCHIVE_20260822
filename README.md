# SBP_LEX_DUAL_V6

# SBP-LEX Dual V6 Desktop V1

## Overview

SBP-LEX Dual V6 Desktop V1 is a local-first, deterministic AI governance and execution-control architecture implementing Dual Adaptive Deterministic Pipelines for bounded execution assurance.

Desktop V1 is a single-host, no-node prototype designed to validate the engineering architecture before future pilot and production deployments.

The architecture preserves the canonical deterministic traversal:

External System → Native Format / Protocol → Adapter Translation → Execution Intent Envelope (EIE) → SKG Verification → DTN Verification → Hard Entry Gate → State Construction → Collective Signal Attachment → Root of Trust → Procedural Truth → Classification → Licensing → Governance → GRC → Domain → Aurion → Execution Gate → Audit → Controlled Outcome.

The Desktop V1 architecture remains deterministic, fail-closed and non-bypass.

---

# Current Engineering Status

Desktop V1 currently implements:

* deterministic Dual Adaptive execution pipelines
* fail-closed execution architecture
* measured startup validation
* approved runtime identity
* runtime drift detection
* deterministic replay verification
* execution gating
* scoped identities
* canonical request binding
* credential lifecycle management
* durable security-state persistence
* admission control
* transport and network-boundary protection
* external trust-boundary hardening
* asymmetric external source identity verification
* protected trust-store management
* durable external replay persistence
* Local Trust assurance
* Constitutional Gates
* Toolchain Guard
* Capstone verification

Desktop V1 remains:

* local-only
* single-host
* no-node
* non-distributed
* cognitively isolated from experimental work
* architecturally unchanged throughout the assurance programme

---

# Post-Quantum Cryptography

SBP-LEX uses a real post-quantum cryptographic provider contract for enforcement and verification evidence.

Current repository policy:

* NIST FIPS 203
* NIST FIPS 204
* NIST FIPS 205

Current algorithms:

* ML-DSA — primary digital signature algorithm
* SLH-DSA — secondary/fallback signature policy
* ML-KEM — key-establishment foundation for future secure session negotiation

Current provider:

```text
cryptography.mldsa
cryptography >= 49.0.0
```

Provider availability is mandatory.

If a required provider is unavailable:

* PQC verification fails closed.
* Verification cannot be bypassed.
* Verification cannot be simulated by forcing successful verification flags.
* Placeholder or HMAC-derived values are never accepted as valid PQC signatures.

Desktop V1 distinguishes between:

* production PQC provider signatures; and
* deterministic Local Trust placeholder evidence used only for bounded engineering validation.

Placeholder evidence is not production cryptography and must never be represented as such.

---

# Assurance Philosophy

Desktop V1 is engineered around deterministic execution assurance.

Every externally supplied object must be verified before canonical runtime traversal.

Authority is never inferred.

Execution authority is never manufactured.

Binding failures propagate forward.

No downstream component may restore an invalid upstream state.

No emergency execution path exists.

Persistent inoperability is preferred to unauthorised execution.

---

# Repository Scope

Desktop V1 intentionally excludes:

* distributed execution
* node-based convergence
* cloud authority
* production PKI infrastructure
* operational multi-host trust fabrics
* cognitive experimental runtime

These remain future engineering workstreams and are intentionally separated from the Desktop V1 canonical baseline.

---

# Current Validation Position

Desktop V1 represents the current canonical high-assurance engineering baseline for SBP-LEX Dual V6.

Its purpose is to provide a deterministic, externally governed execution-control implementation suitable for independent engineering evaluation, validation and future pilot deployment while preserving architectural stability, deterministic replay and fail-closed execution semantics.
