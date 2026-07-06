# PQC-01 Real Provider Contract Report

## Current Placeholder Findings

- `sbp_lex/config/security_config.py` previously set `SIGNATURE_ALGORITHM` to `HMAC-SHA256-PQC-PLACEHOLDER`.
- `sbp_lex/security/pqc.py` previously produced deterministic HMAC envelopes while labelling the signature path as PQC placeholder.
- Existing runtime persistence artifacts signed under the old placeholder/HMAC envelope failed verification after the provider contract changed and were quarantined by the existing integrity-store quarantine mechanism.

## NIST Algorithm Decision

- PQC policy: `NIST_FIPS_203_204_205`.
- Primary signature: `ML-DSA`.
- Backup/long-horizon signature option: `SLH-DSA`.
- Future KEM/session establishment basis: `ML-KEM`.
- FN-DSA/Falcon: not implemented in this phase.

## Files Modified

- `sbp_lex/security/pqc_policy.py`
- `sbp_lex/security/pqc_provider.py`
- `sbp_lex/security/pqc.py`
- `sbp_lex/config/security_config.py`
- `tests/test_pqc_01_provider_contract.py`
- `reports/PQC_01_REAL_PROVIDER_CONTRACT_REPORT.md`

## Provider Availability Result

The local bundled Python runtime includes `cryptography 49.0.0` with `cryptography.hazmat.primitives.asymmetric.mldsa`. PQC-01 uses that installed provider for real ML-DSA signing and verification.

No vendored cryptography and no homemade ML-DSA implementation were added.

## Real Sign/Verify Operational Status

Real ML-DSA sign/verify is operational through `cryptography.mldsa`.

`verify_signature()` returns `True` only when provider-backed ML-DSA verification succeeds against the signed canonical payload digest. If the provider is unavailable, verification returns `False` and signing raises a provider-unavailable fail-closed exception.

## Runtime Determinism Treatment

ML-DSA signatures are randomized provider proofs. To preserve deterministic replay hashes without fake verification, canonical hashing normalizes the raw randomized signature/public-key proof fields while keeping the real raw proof available for `verify_signature()`.

## Fail-Closed Confirmation

If the real provider is unavailable:

- signing fails closed;
- verification returns false;
- tokens cannot become valid through placeholder verification;
- no `verified=True` result is produced by a hash-only or HMAC-only path.

## Runtime Boundary Confirmation

PQC authenticates enforcement evidence only. This phase did not change pipeline order, governance logic, Procedural Truth logic, classification/licensing/domain/Aurion rules, execution gate logic, or policy decisions.

## Validation Commands

- `python -m compileall -q .`
- `python -m pytest -q tests --basetemp runtime_artifacts/pytest_tmp_pqc01`
- `python main.py`
- `python main.py replay`
- `git status --short`
- `git diff --stat`

## Validation Results

- `python -m compileall -q .`: PASS.
- Focused PQC provider contract tests: PASS, `10 passed`.
- Focused connector/PQC regression tests after ML-DSA schema sizing: PASS, current validated focused PQC count `10 passed`.
- `python -m pytest -q tests --basetemp runtime_artifacts/pytest_tmp_pqc01`: PASS, `591 passed in 377.69s`.
- `python main.py`: PASS, returned `ALLOW`, `EXECUTE`, convergence matched, and no token failures.
- `python main.py replay`: PASS, `matched: true` and `mismatches: []`.

## Runtime Artifact Migration Note

The existing `runtime_artifacts/integrity_store.jsonl` contained records signed under the previous placeholder/HMAC envelope. After PQC-01 switched verification to the real ML-DSA provider, those records failed verification and were quarantined using the repository's existing `quarantine_poisoned_integrity_store()` mechanism. The old store was not accepted under the new provider contract.
