# Post RED-20 Integrity Store Quarantine Record

## Action

On 2026-06-21, the corrupted default runtime integrity artifact was moved intact from:

`runtime_artifacts/integrity_store.jsonl`

to the forensic quarantine location:

`runtime_artifacts/quarantine/integrity_store.poisoned.2583181c2e028f36568266647135dfd03382bb0bc0f2b564b6403f65dd2a10d4.jsonl`

The evidence was not deleted or rewritten. The source and quarantined file were verified as:

- Size: 1,019,894 bytes
- SHA-256: `2583181c2e028f36568266647135dfd03382bb0bc0f2b564b6403f65dd2a10d4`
- Original companion checkpoint: none present
- Detection reason: `persistence_poisoning_detected`, including sequence and link discontinuities

The default path was left absent after the custody move so the existing runtime persistence implementation could regenerate a clean store and signed checkpoint during the next verified traversal. No runtime code was changed for this action.

## Boundary statement

This quarantine is an operational evidence-preservation action only. It does not weaken persistence verification, bypass the integrity guard, activate Phase 19, or change Desktop V1 authority boundaries.
