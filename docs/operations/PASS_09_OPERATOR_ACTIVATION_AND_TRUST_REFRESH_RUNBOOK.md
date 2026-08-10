# Pass 9 Operator Activation and Trust Refresh Runbook

Status: ready for an owner-authorised secure operator session.

## Safety boundary

Do not paste the private signing seed into chat, source files, reports, command
arguments, screenshots, or committed configuration. Provision it and the public
trust values through the owner's approved secret channel. Pass 9 records only
configuration status, public fingerprint, profile digest, and results.

The environment template lists every required variable but contains no private
value. The exact dependency environment is in `requirements-pass9.lock.txt`.

## Mandatory order

1. Start from the final clean Pass 9 implementation commit.
2. Provision the ML-DSA seed, separately authenticated public key and
   fingerprint, migration approval, key ID, UTC activation and expiry, and the
   explicit revocation registry.
3. Run the non-authoritative preflight:

   ```text
   python -m sbp_lex.security.pqc_migration_activation --trust-classification OWNER_AUTHORISED_OPERATOR --output outputs/security/pass_09_owner_activation_preflight.json
   ```

4. Require `pass_status=PASS`. A test-trust preflight does not satisfy this
   owner-activation gate.
5. Run normal runtime and deterministic replay. Both must use V3 profile-bound
   signatures and the same pinned signer/profile identity.
6. Propose and explicitly approve the final measured-startup baseline; never
   rewrite a stale baseline into acceptance:

   ```text
   python -m sbp_lex.runtime.measured_startup propose --identifier OWNER_SELECTED_PASS9_BASELINE_ID
   python -m sbp_lex.runtime.measured_startup approve --identifier OWNER_SELECTED_PASS9_BASELINE_ID --retire PRIOR_APPROVED_BASELINE_ID --approval-reference OWNER_APPROVAL_REFERENCE
   python -m sbp_lex.runtime.measured_startup validate
   python -m sbp_lex.runtime.measured_startup show
   ```

7. Rebuild and validate the established local-trust chain in its documented
   dependency order, ending with:

   ```text
   python -m sbp_lex.local_trust.evidence_chain build --clean-required
   python -m sbp_lex.local_trust.evidence_chain validate --clean-required
   python -m sbp_lex.local_trust.local_trust_capstone build --clean-required
   python -m sbp_lex.local_trust.local_trust_capstone validate --clean-required
   python -m sbp_lex.local_trust.release_integrity build --clean-required
   python -m sbp_lex.local_trust.release_integrity validate --clean-required
   ```

8. Verify the integrity ledger, recovery inventory, backup/restore preflight,
   runtime, and replay against the exact approved commit and identity.
9. Preserve the resulting owner evidence. Do not replace the isolated test-trust
   soak artifact with an owner claim unless the four-hour soak is actually
   repeated under the owner-authorised identity.

## Rotation or revocation

For rotation, stop the runtime, provision the new seed/public identity/profile,
record the old public fingerprint in the revocation registry when applicable,
restart, repeat the preflight, and regenerate commit/identity-bound trust
evidence. Mid-process rotation is deliberately rejected.

For suspected compromise, revoke the public fingerprint, keep runtime admission
closed, preserve evidence, and do not use archive verification as a runtime
fallback.

## Completion evidence

The owner activation gap closes only when the owner-classified preflight,
runtime, replay, measured startup, local evidence chain, capstone, release
integrity, and ledger validation all pass against one exact clean commit. A
repository test-trust pass demonstrates readiness but is not owner authority.

