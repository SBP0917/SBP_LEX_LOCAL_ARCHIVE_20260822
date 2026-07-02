# Draft Traversal Integration Blueprint Addendum

Status: Draft repository-side implementation alignment material pending owner canonisation. This addendum does not replace master canonical doctrine.

Purpose: Preserve the required traversal order and pass forward EIE/SKG/DTN/Root/PT metadata without redesigning unrelated layers.

Affected components: `sbp_lex/pipeline/runner.py`, Classification, Licensing, Governance, GRC, Domain, Aurion, Execution, Audit.

New responsibility boundaries: Downstream layers may recognise and preserve certification metadata. They must not reorder traversal or assume PT work.

What must be implemented: sequence remains External/System ingress, Adapter/EIE, SKG, DTN, Pre-context, Hard Entry Gate, State Construction/EIE formalisation, Root of Trust, Procedural Truth, Classification, Licensing, Governance, GRC, Domain, Aurion, Execution Gate, Audit/Replay/Telemetry.

What must not be changed: Procedural Truth must not move after Classification or Licensing; Governance must not move before PT; Domain must not move before GRC; Aurion must not move before Domain.

Integration points: `run_pipeline` already enforces downstream progression gates and now relies on PT certification as the downstream unlock.

Required tests: downstream layers remain unset when PT is not certified; Domain and Aurion do not proceed on invalid upstream certification.

Remaining limitations: Layer-specific docs may need owner-approved canonical rewrite to replace older phase terminology.
