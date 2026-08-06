# Independent Verification Guide

This package is a detached technical evidence set. Obtain both the base64-encoded trusted ML-DSA public verification key and its SHA-256 fingerprint through a separate authenticated channel; never establish trust from values supplied only inside this package. Configure `SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY`, then pass the separately obtained fingerprint to the verifier. Verify `PACKAGE_MANIFEST.json` first, then review identity, claims, traceability, evidence inventory, and recorded runtime/replay evidence. Expected validation status is `R4_IVVP_VALID`. Results establish implemented engineering evidence, not certification or mathematical proof.

Repository commit: `f5ba5b2b7da8fbc63f1ddac1a3bce2cb1112ea5b`

Trusted repository anchor: `1f6d63422aeab848a8d4f26a6f8a46e3125c780a`

Trusted ML-DSA signer fingerprint: `cef95d11d78a54749bb07f0926e29a6f8704dc276825d0a318d1e15f6ef1f077`

Measured baseline: `DESKTOP_V1_UNIVERSITY_HANDOVER_20260806_01`

Runtime identity: `2bb0d42fcb478c0750eedbdddf7171e7a6c22f851ac651686ef095607bdf3599`
