# Draft Execution Gate Enforcement Addendum

Status: Draft repository-side implementation alignment material pending owner canonisation. This addendum does not replace master canonical doctrine.

Purpose: Ensure Execution Gate denies execution unless Procedural Truth certification and all required bindings are valid.

Affected components: `sbp_lex/execution/execution_gate.py`, `sbp_lex/security/token_stack.py`, `sbp_lex/shared/hash_chain.py`.

New responsibility boundaries: Execution Gate verifies prior certifications and bindings; it does not issue PT certification.

What must be implemented: checks for PT PASS, CERTIFIED status, Root of Trust valid, SKG valid, DTN valid, matching EIE hash, matching state hash, matching request fingerprint, required PT token and hash, sufficiency factors, no unresolved material contradiction, and consequence burden met.

What must not be changed: Execution Gate remains fail-closed and must not permit execution for REFINE, ESCALATE, DENY, NOT_CERTIFIED, missing, invalid, stale, or mismatched PT states.

Integration points: runs only after Aurion pass in `run_pipeline`, and strict validator independently checks completed execution states.

Required tests: missing/mismatched PT token denies; PT not certified denies; unresolved contradictions deny; sufficiency factor false denies.

Remaining limitations: Token signature validation uses the existing local deterministic token stack.
