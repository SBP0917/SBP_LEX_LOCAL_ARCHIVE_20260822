# Priority 1 Security Integrity Ledger Closure Report

## Status

Technical correction prepared and regression protected. Native-Windows complete
evidence-stage regeneration remains required before any handover-readiness claim.

V1.2.14 stopped safely at its exact-input guard because its local patch preimage
for `tests/test_r1_canonical_backup_recovery.py` contained one additional final
newline. V1.2.15 is rebuilt against the exact reviewed GitHub blob
`241ad255cf0877250bfac4337ab1992b4f372172`. No runtime or validation rule was
changed to resolve that packaging mismatch.

Current controlled wording:

`HANDOVER_PREPARED_BUT_BLOCKED_PENDING_NATIVE_WINDOWS_COMPLETE_EVIDENCE_STAGE`

## Root cause

The handover generator called `_generate_current_evidence()` before
`build_package()`. Recovery inventory construction therefore consumed the
required `security.integrity_ledger` contract before a canonical runtime
traversal had created the signed ledger and companion checkpoint.

The failure was correct and fail-closed:

`required_artefact_missing:security.integrity_ledger`

## Artefact contract

- Logical name: `security.integrity_ledger`
- Runtime path: `runtime_artifacts/integrity_store.jsonl`
- Checkpoint path:
  `runtime_artifacts/integrity_store.jsonl.checkpoint.json`
- Recovery path: `audit/integrity_store.jsonl`
- Producer: canonical runtime persistence through
  `RUNTIME_INTEGRITY_STORE.append_state_summary()`
- Consumer: `build_inventory()` through the `integrity_store` validation method
- Binding: ledger SHA-256 enters the recovery inventory aggregate digest, then
  R2/R3/R4 evidence and the university handover stage manifest

## Bounded correction

The complete evidence-stage order is now:

1. build the runtime/replay IVVP package;
2. let the canonical runtime produce the signed append-only ledger and signed
   checkpoint;
3. build and validate the recovery-critical inventory;
4. bind the inventory into R2, R3, R4 and the handover stage;
5. continue existing Local Trust and final package validation.

No artefact was made optional, stubbed, copied from a dummy fixture or granted a
validation bypass. A configured `SBP_LEX_INTEGRITY_STORE` override is rejected
at the portable handover boundary so the run cannot silently consume a foreign
ledger.

## Files inspected

- `sbp_lex/assurance/handover_regeneration.py`
- `sbp_lex/ivvp/package.py`
- `sbp_lex/recovery/inventory.py`
- `sbp_lex/persistence/integrity_store.py`
- `sbp_lex/runtime/canonical_runtime.py`
- `tests/test_r1_canonical_backup_recovery.py`
- `tests/test_university_handover_regeneration.py`

## Files changed

- `sbp_lex/assurance/handover_regeneration.py`
- `tests/test_r1_canonical_backup_recovery.py`
- `tests/test_university_handover_regeneration.py`
- `reports/PRIORITY_1_SECURITY_INTEGRITY_LEDGER_CLOSURE_REPORT.md`

## Regression protection

Focused tests prove:

- a missing ledger fails closed;
- a malformed ledger fails closed;
- a tampered signed ledger fails closed;
- a valid ledger and checkpoint are accepted and hash-bound;
- a non-portable integrity-store override is rejected;
- runtime package generation precedes recovery-inventory validation.

Existing inventory and handover validators continue to block complete evidence
generation and any downstream handover claim when required evidence is missing
or invalid.

## Required verification

Preparation-side verification completed on 2026-08-05:

- exact V1.2.13 source-repair preimage reconstructed: PASS;
- V1.2.13 patch reverse/forward application: PASS;
- exact reviewed GitHub test preimage (`241ad255...`) verified: PASS;
- bounded V1.2.15 exact-preimage integrity-ledger patch application: PASS;
- `git diff --check` for the repair patch: PASS;
- Python compilation of all three changed Python files: PASS;
- PowerShell grammar parse of both kit scripts: PASS;
- kit manifest strict JSON parse: PASS.

These preparation checks do not substitute for the native-Windows complete
repository run. The controlled finalizer is configured to record the following
remaining results and to stop before any push if one fails:

The controlled Windows finalizer must record:

- `python -m compileall -q .`
- complete `pytest` suite
- `scripts\\run_tests.bat`
- three linkage-assurance runs
- source Double Triple assurance
- complete evidence-stage generation
- bounded evidence recording
- R4 package verification
- triple archive verification
- `git diff --check`
- clean final Git state

The actual ledger digest is generated during that run and is recorded in
`outputs/recovery_critical_inventory.json`. It is not predeclared in this report.

## Claim control

There is no handover-readiness claim in this source correction report. Such a
claim is permitted only if the repository finalization process completes and
emits its own explicit success status. External validation remains pending.
