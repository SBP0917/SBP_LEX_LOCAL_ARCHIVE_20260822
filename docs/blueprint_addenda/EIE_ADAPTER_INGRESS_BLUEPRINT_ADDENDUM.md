# Draft EIE / Adapter Ingress Blueprint Addendum

Status: Draft repository-side implementation alignment material pending owner canonisation. This addendum does not replace master canonical doctrine.

Purpose: Align adapter ingress with EIE as the canonical SBP-LEX traversal state after native-format translation.

Affected components: `sbp_lex/shared/state_builder.py`, `sbp_lex/pipeline/hard_ingress.py`, `sbp_lex/pipeline/runner.py`, `sbp_lex/collective/context_interface.py`.

New responsibility boundaries: Adapter ingress may translate native request material into an EIE. State Construction formalises, normalises, binds, hashes, and preserves that EIE. It must not replace the EIE with an unrelated state object.

What must be implemented: deterministic EIE identity, EIE hash, source payload hash, adapter identity, source system identity, traversal ID, request fingerprint, and EIE preservation through traversal.

What must not be changed: Hard Entry Gate remains the ingress enforcement point. External packages must not become execution authority.

Integration points: Hard Entry Gate accepts request/pre-context only after validation; State Builder creates the EIE; SKG/DTN enrichment attaches to EIE metadata; PT certification and Root of Trust anchorage bind back to the EIE.

Required tests: EIE is present after State Construction, remains active traversal state, carries the same traversal ID through PT and Execution Gate, and is not discarded after ingestion.

Remaining limitations: Current implementation uses local deterministic adapter identity defaults when no explicit adapter fields are supplied.
