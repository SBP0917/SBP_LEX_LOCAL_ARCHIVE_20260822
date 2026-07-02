# Draft Procedural Truth Rebuild Blueprint Addendum

Status: Draft repository-side implementation alignment material pending owner canonisation. This addendum does not replace master canonical doctrine.

Purpose: Upgrade Procedural Truth from fixed corroboration checking into a Procedural Truth Evidentiary Sufficiency Certification Engine.

Affected components: `sbp_lex/governance/procedural_truth_engine.py`, `sbp_lex/governance/procedural_truth_envelope.py`, `sbp_lex/governance/evidence_engine.py`, `sbp_lex/governance/corroboration_engine.py`.

New responsibility boundaries: Procedural Truth certifies sufficiency over anchored, SKG-verified, DTN-contextualised EIE evidence. It does not replace Classification, Licensing, Governance, GRC, Domain, Aurion, or Execution Gate.

What must be implemented: deterministic certification result with status, certification state, tier, source floor, independence, provenance, integrity, attestation, authority, jurisdiction, freshness, consistency, runtime validity, consequence burden, contradiction flags, SKG/DTN/Root status, reason codes, required action, PT token fields, request fingerprint, EIE hash, state hash, and traversal ID.

What must not be changed: Legacy thresholds may remain only as minimum floors. Source count alone must never certify an EIE.

Integration points: Root of Trust must pass before PT; Classification and Licensing run only after certified PT; Execution Gate validates PT certification directly.

Required tests: missing foundations fail, source count without independence/provenance fails, unresolved contradictions fail, stale evidence fails, authority/jurisdiction insufficiency fails, and structured deterministic result is stable.

Remaining limitations: Compatibility defaults allow current local evidence records to pass when legacy records omit new production-grade flags but otherwise satisfy existing validity requirements.
