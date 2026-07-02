# Draft Root of Trust Anchorage Blueprint Addendum

Status: Draft repository-side implementation alignment material pending owner canonisation. This addendum does not replace master canonical doctrine.

Purpose: Bind validated EIE truth foundations to traversal so they cannot be substituted, weakened, replayed, detached, or silently altered.

Affected components: `sbp_lex/authority_first/root_of_trust_runner.py`, `sbp_lex/security/root_of_trust_anchor.py`, `sbp_lex/security/token_stack.py`.

New responsibility boundaries: Root of Trust Anchorage binds evidence and traversal identity. It does not perform Procedural Truth certification or downstream governance.

What must be implemented: binding over EIE identity/hash, source payload hash, adapter identity, source system identity, SKG status/hash, DTN status/hash, evidence package hash, authority reference hash, state hash, traversal ID, freshness reference, token chain reference, and audit chain reference.

What must not be changed: Root of Trust failure remains fail-closed and prevents PT certification.

Integration points: Runs after State Construction and SKG/DTN metadata attachment, before Procedural Truth certification.

Required tests: Root anchor payload contains EIE/SKG/DTN fields and fails when EIE hash or PT envelope hash mismatches.

Remaining limitations: Cryptographic signing remains the repository's deterministic local signing implementation.
