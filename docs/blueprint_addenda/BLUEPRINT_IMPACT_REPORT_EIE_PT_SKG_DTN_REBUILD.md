# Draft Blueprint Impact Report: EIE / PT / SKG / DTN Rebuild

Status: Draft repository-side implementation alignment material pending owner canonisation. This report does not replace master canonical doctrine.

## Blueprint documents found

- `README.md`, `START_HERE.md`, `BASELINE_LOCK.md`
- `docs/PROCEDURAL_TRUTH_BINDING_DURING_STATE_CONSTRUCTION.md`
- `docs/EXTERNAL_SKG_DTN_CONSTRUCTION_BASELINE.md`
- `docs/EXTERNAL_SKG_DTN_BRIDGE_READINESS.md`
- `docs/EXTERNAL_SKG_DTN_SUBSTRATE_DEMO.md`
- `docs/LOCAL_TRUST_ROOT_MANIFEST.md`
- `docs/LOCAL_TRUST_CONSTITUTIONAL_ENFORCEMENT_GATES.md`
- `docs/LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE.md`
- `docs/LOCAL_EVIDENCE_CHAIN_REPORT_INTEGRITY_ATTESTATION.md`
- `docs/LOCAL_TRUST_REGRESSION_MATRIX.md`
- `external_substrates/skg/README.md`
- `external_substrates/dtn/README.md`
- `external_substrates/BRIDGE_CONTRACT_LOCK.md`
- `external_substrates/EXTERNAL_SUBSTRATE_LOCK.md`
- release, audit, dossier, cockpit, and demo-evidence reports under `docs/`, `reports/`, and root markdown files.

The untracked `baselines/` directory was intentionally excluded from analysis and planning.

## Affected blueprints

The affected repo-level blueprints are the Procedural Truth binding doc, external SKG/DTN construction baseline, bridge readiness docs, SKG README, DTN README, local trust/root manifest docs, audit/replay/evidence-chain docs, and execution gate / constitutional gate documentation.

## Outdated sections

- Procedural Truth is documented mainly as threshold and qualified-source validation rather than Evidentiary Sufficiency certification.
- SKG and DTN docs describe external signal packages but do not state their new PT-aware enrichment metadata obligations.
- State Construction docs describe a PT Evidence Envelope but do not identify EIE as the canonical traversal state.
- Root of Trust docs do not list the expanded anchorage fields for EIE, SKG, DTN, evidence package, state hash, traversal ID, token chain, and audit chain.
- Execution gate docs do not require direct validation of PT certification status, PT token hash, sufficiency factors, unresolved contradictions, and consequence burden.

## Addendum treatment

Addenda are safer than direct rewrites because current documents appear to be phase locks and release records. Rewriting them would risk altering canonical history. Draft addenda should sit beside the existing docs until the repository owner canonises them.

## Direct rewrite treatment

No direct rewrite is performed. Future owner-approved rewrites may be appropriate for:

- `docs/PROCEDURAL_TRUTH_BINDING_DURING_STATE_CONSTRUCTION.md`
- `docs/EXTERNAL_SKG_DTN_CONSTRUCTION_BASELINE.md`
- `docs/EXTERNAL_SKG_DTN_BRIDGE_READINESS.md`
- `external_substrates/skg/README.md`
- `external_substrates/dtn/README.md`

## Missing sections

- EIE / Adapter Ingress Blueprint Addendum
- SKG Rebuild Blueprint Addendum
- DTN Rebuild Blueprint Addendum
- Procedural Truth Rebuild Blueprint Addendum
- Root of Trust Anchorage Blueprint Addendum
- Traversal Integration Blueprint Addendum
- Execution Gate Enforcement Addendum
- Audit / Replay / Telemetry Metadata Addendum

## Documentation clarification dependencies

- Whether EIE is canonised as the permanent repo term replacing request/state/envelope language.
- Whether `LOW` should remain as a legacy alias for `LOWER`.
- Whether `EXTREME` is a distinct tier or an escalation label above `TOP`.
- Which source metadata fields are mandatory in production versus accepted as compatibility defaults for current local tests.
- Whether Root of Trust anchorage should be represented as part of the EIE body or as a binding over the formalised EIE identity hash.

## Terminology conflicts

- `Execution Intent Envelope` was not previously a dominant repo term.
- Existing docs use `PT Evidence Envelope`; new structure requires EIE as canonical traversal state and PT envelope as evidence/certification support.
- Existing threshold language treats source counts as core pass criteria; new language treats thresholds as minimum floors only.
- SKG/DTN are documented as external substrates; new instruction requires PT-aware enrichment while preserving non-authority boundaries.
