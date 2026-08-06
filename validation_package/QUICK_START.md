# Assessor Quick Start

Expected duration: 10-20 minutes.

1. Obtain the base64-encoded trusted ML-DSA public key and its SHA-256 fingerprint through a separate authenticated channel.
2. Set `SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY` to that public key; do not copy the key from this package.
3. Run `python -m sbp_lex.ivvp.verifier validation_package --expected-signer-fingerprint EXPECTED_64_HEX_FROM_SEPARATE_CHANNEL` after replacing the fingerprint placeholder.
4. Confirm `R4_IVVP_VALID`.
5. Review claims and traceability; unsupported claims must never be treated as verified.
6. If repository access is available, repeat verification with `--repository-root PATH_TO_CANONICAL_CHECKOUT` to recompute tracked artifacts from the bound Git commit.

Repository commit: `f5ba5b2b7da8fbc63f1ddac1a3bce2cb1112ea5b`

Trusted repository anchor: `1f6d63422aeab848a8d4f26a6f8a46e3125c780a`

Trusted ML-DSA signer fingerprint: `cef95d11d78a54749bb07f0926e29a6f8704dc276825d0a318d1e15f6ef1f077`

Measured baseline: `DESKTOP_V1_UNIVERSITY_HANDOVER_20260806_01`

Runtime identity: `2bb0d42fcb478c0750eedbdddf7171e7a6c22f851ac651686ef095607bdf3599`
