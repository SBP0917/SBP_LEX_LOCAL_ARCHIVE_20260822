# SBP_LEX_DUAL_V6

## PQC Provider Contract

SBP-LEX uses a real PQC provider contract for enforcement-evidence signatures. The current repository policy is `NIST_FIPS_203_204_205`: ML-DSA is the primary signature algorithm, SLH-DSA is reserved as a backup signature policy, and ML-KEM is the KEM basis for future key-establishment/session use.

The current tested provider is `cryptography.mldsa` from `cryptography>=49.0.0`. Provider availability is required. If the provider is unavailable, PQC operations fail closed; verification cannot be faked by setting `verified=true`, and placeholder/HMAC PQC signatures are not accepted as valid provider signatures.

Local-trust deterministic `PLACEHOLDER` labels in evidence tooling are not the active PQC provider path and must not be described as production cryptography.

**Local-first desktop runtime prototype for SBP-LEX Dual Adaptive Deterministic Pipelines — hardened no-node V1 with canonical runtime control, connector/API boundary protection, parity convergence, execution gating, replay/audit integrity, and local dashboard observability.**
