# Draft DTN Rebuild Blueprint Addendum

Status: Draft implementation-alignment document. This addendum does not replace master canonical doctrine.

Purpose: Make DTN Procedural-Truth-aware by enriching contextual and operational EIE metadata after SKG verification.

Affected components: `external_substrates/dtn/signal_builder.py`, `external_substrates/dtn/*`, `external_substrates/shared/pre_context_package.py`, `sbp_lex/governance/procedural_truth_envelope.py`.

New responsibility boundaries: DTN recognises, verifies, organises, attaches, and preserves contextual and operational metadata. DTN does not authorise execution, certify Procedural Truth, decide governance/domain admissibility, select pathways, or bypass runtime traversal.

What must be implemented: locality, landscape, proximity, operational state, environmental context, infrastructure relevance, system-state relevance, runtime-world correspondence, physical/digital alignment, consequence context, affected assets/dependencies, cascading-effect indicators, state-correspondence verification, contextualisation status, enrichment hash, and contextual readiness.

What must not be changed: DTN remains constrained by SKG and remains non-authoritative.

Integration points: DTN metadata is carried by pre-context packages, preserved in PT evidence metadata, and attached to EIE `dtn_contextual_verification`.

Required tests: DTN metadata is attached and hashed; DTN does not emit governance or execution authority; missing DTN readiness prevents PT certification.

Remaining limitations: Production-grade locality and physical-world alignment fields require owner-approved input schemas.
