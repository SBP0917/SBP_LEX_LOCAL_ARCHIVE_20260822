# Release Integrity Bundle

This directory is the Phase 18.7F reproducible validation bundle.

It is a review-readiness package, not certification, legal advice, security certification, production release behavior, runtime activation, Phase 19, or external validation.

## Files

- `RELEASE_MANIFEST.json`: top-level release integrity manifest and digest.
- `ARTIFACT_HASH_INDEX.json`: validation-relevant artifact hash index.
- `VERIFICATION_COMMANDS.json`: reproducible command sequence index.
- `CLAIMS_TO_EVIDENCE_SEED.json`: seed mapping for later claims-to-evidence work.
- `BOUNDARY_AND_SCOPE_LOCK.json`: scope and exclusion lock.
- `RELEASE_README.md`: this reviewer note.

## Verification

Run:

```bat
python -m sbp_lex.local_trust.release_integrity validate
python -m sbp_lex.local_trust.release_integrity show
```

18.7G is the next phase marker only. 18.7G is not implemented in this bundle.
