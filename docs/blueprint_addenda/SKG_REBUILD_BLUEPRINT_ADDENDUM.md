# Draft SKG Rebuild Blueprint Addendum

Status: Draft implementation-alignment document. This addendum does not replace master canonical doctrine.

Purpose: Make SKG Procedural-Truth-aware by enriching EIE truth foundations without becoming the Procedural Truth engine.

Affected components: `external_substrates/skg/signal_builder.py`, `external_substrates/skg/*`, `external_substrates/shared/pre_context_package.py`, `sbp_lex/governance/procedural_truth_envelope.py`.

New responsibility boundaries: SKG recognises, verifies, organises, attaches, and preserves truth-foundation metadata. SKG does not authorise execution, certify Procedural Truth, decide governance/domain admissibility, select pathways, or bypass runtime traversal.

What must be implemented: provenance, source origin, source independence, authority relationships, corroboration, freshness, staleness, consistency, contradiction, confidence, identity, attestation, integrity, chain-of-custody, jurisdictional relevance, claim linkage, support/conflict mapping, verification status, enrichment hash, and truth-foundation readiness.

What must not be changed: SKG remains an external/non-authoritative substrate and must not import canonical runtime modules.

Integration points: SKG package metadata is carried by composed pre-context packages and preserved in PT evidence metadata and EIE `skg_truth_foundation`.

Required tests: SKG enrichment is attached and hashed; SKG does not emit governance or execution authority; missing SKG readiness prevents PT certification.

Remaining limitations: Some production-grade metadata fields are represented as deterministic compatibility metadata until owner-approved source schemas are expanded.
