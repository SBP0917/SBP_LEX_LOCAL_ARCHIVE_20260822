# Blueprint Alignment Mismatch Table

Draft status: BLUEPRINT-SKGDTN-ALIGN-01 proposed alignment material only. This table classifies before rewriting. It does not modify canonical doctrine.

## Blueprint Documents Found

### Current Repository Draft Canonical Series

- `docs/canonical_blueprint_series/00_CANONICAL_BLUEPRINT_SERIES_INDEX.md`
- `docs/canonical_blueprint_series/01_MASTER_ARCHITECTURE_AND_TRAVERSAL_BLUEPRINT.md`
- `docs/canonical_blueprint_series/02_EIE_ADAPTER_INGRESS_BLUEPRINT.md`
- `docs/canonical_blueprint_series/03_SKG_TRUTH_FOUNDATION_ENRICHMENT_BLUEPRINT.md`
- `docs/canonical_blueprint_series/04_DTN_CONTEXTUAL_OPERATIONAL_VERIFICATION_BLUEPRINT.md`
- `docs/canonical_blueprint_series/05_ROOT_OF_TRUST_ANCHORAGE_BLUEPRINT.md`
- `docs/canonical_blueprint_series/06_PROCEDURAL_TRUTH_EVIDENTIARY_SUFFICIENCY_BLUEPRINT.md`
- `docs/canonical_blueprint_series/07_CLASSIFICATION_AND_LICENSING_INTEGRATION_BLUEPRINT.md`
- `docs/canonical_blueprint_series/08_GOVERNANCE_AND_GRC_BLUEPRINT.md`
- `docs/canonical_blueprint_series/09_DOMAIN_ADMISSIBILITY_BLUEPRINT.md`
- `docs/canonical_blueprint_series/10_AURION_CONSTRAINED_PATHWAY_SELECTION_BLUEPRINT.md`
- `docs/canonical_blueprint_series/11_EXECUTION_GATE_ENFORCEMENT_BLUEPRINT.md`
- `docs/canonical_blueprint_series/12_AUDIT_REPLAY_TELEMETRY_BLUEPRINT.md`
- `docs/canonical_blueprint_series/13_ANTI_DRIFT_IMPLEMENTATION_CONTROL_BLUEPRINT.md`
- `docs/canonical_blueprint_series/BLUEPRINT_SOURCE_AND_SUPERSESSION_MAP.md`

### Current Repository Addenda

- `docs/blueprint_addenda/EIE_ADAPTER_INGRESS_BLUEPRINT_ADDENDUM.md`
- `docs/blueprint_addenda/SKG_REBUILD_BLUEPRINT_ADDENDUM.md`
- `docs/blueprint_addenda/DTN_REBUILD_BLUEPRINT_ADDENDUM.md`
- `docs/blueprint_addenda/TRAVERSAL_INTEGRATION_BLUEPRINT_ADDENDUM.md`
- `docs/blueprint_addenda/ROOT_OF_TRUST_ANCHORAGE_BLUEPRINT_ADDENDUM.md`
- `docs/blueprint_addenda/PROCEDURAL_TRUTH_REBUILD_BLUEPRINT_ADDENDUM.md`
- `docs/blueprint_addenda/EXECUTION_GATE_ENFORCEMENT_ADDENDUM.md`
- `docs/blueprint_addenda/AUDIT_REPLAY_TELEMETRY_METADATA_ADDENDUM.md`
- `docs/blueprint_addenda/BLUEPRINT_IMPACT_REPORT_EIE_PT_SKG_DTN_REBUILD.md`

### Historical Original Blueprint Artifacts Found Under Baselines

- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/Theoretical SBP-LEX V6 blueprint..docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/The Architectural Engineering Blueprint Document.docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/V6 Intergrational Architectural Blueprint.docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/V6 definitional anti drift Blueprint.docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/DOMAIN WRAP LAYER - V6 (FINAL BLUEPRINTandDEFINITION LOCK).docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/SKG_DTN_Domain_alignment.docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/token_stack.py  V6 DEFINITION CANONICAL.docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/procedural truth output discipline engine.docx`
- `baselines/13A_architecture_thread_blueprint_documents/old_profile_onedrive_documents_architecture/CANONICAL MASTER BLUEPRINT SERIES.docx`

## Mismatch Table

| Document / Category | Repo Path | Classification | Current Wording Summary | Issue | Recommended Alignment | Canon Risk | Owner Review Required |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Theoretical Blueprint | `baselines/.../Theoretical SBP-LEX V6 blueprint..docx` | EIE_INSERTION_REQUIRED; SKG_DTN_EXTERNAL_READINESS_REQUIRED; PIPELINE_ORDER_CONSISTENCY_REQUIRED | Historical original exists as `.docx`; current markdown master series separately captures EIE/SKG/DTN order. | Original may predate EIE insertion and external readiness framing. | Add universal EIE and SKG/DTN external readiness addenda after owner review. | HIGH | true |
| Architectural Engineering Blueprint | `baselines/.../The Architectural Engineering Blueprint Document.docx` | EIE_INSERTION_REQUIRED; DUAL_ADAPTIVE_WORDING_REQUIRED; PHASE19A_PRECONDITION_REQUIRED | Historical original exists as `.docx`; current `01_MASTER...` defines repository draft traversal. | Original may use older single-pipeline or pre-Phase19A wording. | Add Dual Adaptive traversal and Phase19A precondition addenda. | HIGH | true |
| Integrational Architectural Blueprint | `baselines/.../V6 Intergrational Architectural Blueprint.docx` | EIE_INSERTION_REQUIRED; SKG_DTN_EXTERNAL_READINESS_REQUIRED | Historical original exists as `.docx`; current canonical series has separate EIE/SKG/DTN docs. | Integration point should explicitly place EIE before SKG/DTN and only pass validated pre-context signal package inward. | Add pre-context package and boundary wording. | MEDIUM | true |
| Definition & Anti-Drift Blueprint | `baselines/.../V6 definitional anti drift Blueprint.docx`; `docs/canonical_blueprint_series/13_ANTI_DRIFT_IMPLEMENTATION_CONTROL_BLUEPRINT.md` | DUAL_ADAPTIVE_WORDING_REQUIRED; HUMAN_REVIEW_REQUIRED | Current repo draft says implementation/doc/test alignment must not silently canonise owner doctrine. | Owner doctrine needs explicit addendum queue before direct canon edits. | Use owner-review queue; do not edit locked doctrine directly. | HIGH | true |
| Security Config Blueprint | current docs plus `DEPLOYMENT_SECURITY.md`; PQC report | PQC_PLACEHOLDER_STALE | Current repo uses real `cryptography.mldsa` provider contract and documents no certification claim. | Older placeholder/HMAC wording may be stale in original docs. | Add PQC stale-placeholder addendum noting supersession by current provider contract where implemented. | MEDIUM | true |
| Domain Wrap Layer Blueprint | `baselines/.../DOMAIN WRAP LAYER - V6 (FINAL BLUEPRINTandDEFINITION LOCK).docx`; `docs/canonical_blueprint_series/09_DOMAIN_ADMISSIBILITY_BLUEPRINT.md` | DOMAIN_BOUNDARY_CLARIFICATION_REQUIRED | Current draft says Domain applies local admissibility constraints after Governance/GRC. | Need stronger explicit boundary: Domain is enforcement, not intelligence; it must not absorb SKG/DTN work. | Add Domain boundary addendum. | HIGH | true |
| Adaptive Multi-Mode Governance Traversal | current SIM-02/SIM-03 docs; canonical series | DUAL_ADAPTIVE_WORDING_REQUIRED | Current simulation library locks LOW/MEDIUM/TOP mappings. | Original blueprint set may not consistently reference adaptive mapping. | Add Dual Adaptive traversal addendum. | MEDIUM | true |
| SKG/DTN/Domain Alignment | `baselines/.../SKG_DTN_Domain_alignment.docx`; external SKG/DTN docs | SKG_DTN_EXTERNAL_READINESS_REQUIRED; DOMAIN_BOUNDARY_CLARIFICATION_REQUIRED | Current external docs lock SKG external truth, DTN constrained context, SBP-LEX as sole authority. | Needs formal readiness contract as key alignment basis. | Adopt `SKG_DTN_EXTERNAL_READINESS_CONTRACT.md` after owner review. | HIGH | true |
| Token Stack Canonical | `baselines/.../token_stack.py  V6 DEFINITION CANONICAL.docx`; `sbp_lex/security/token_stack.py` | PIPELINE_ORDER_CONSISTENCY_REQUIRED | Token stack exists in runtime; current blueprints preserve EIE/SKG/DTN hashes through audit/replay. | Owner canon should state signal digest/request binding relation without moving token authority upstream. | Add token-binding note in approved addendum pass. | MEDIUM | true |
| Safety Consequentiality & Financial Tiering | MISSING_FROM_REPO as exact source title | MISSING_FROM_REPO; DUAL_ADAPTIVE_WORDING_REQUIRED | Exact named document was not found as a repo file in current search. | Tiering doctrine must map to LOW/MEDIUM/TOP traversal without changing tier doctrine. | Owner to provide source or approve addendum against known category. | HIGH | true |
| Current 13-doc canonical markdown series | `docs/canonical_blueprint_series/` | NO_CHANGE_REQUIRED; HUMAN_REVIEW_REQUIRED | Already draft-aligned to EIE -> SKG -> DTN -> Pre-context -> Hard Entry and marks owner canonisation pending. | Should not be edited in this pass. | Keep as source context; apply approved addenda later only. | LOW | true |
| External SKG/DTN bridge docs | `docs/EXTERNAL_SKG_DTN_CONSTRUCTION_BASELINE.md`; `docs/EXTERNAL_SKG_DTN_BRIDGE_READINESS.md` | NO_CHANGE_REQUIRED | Already states SKG external truth, DTN constrained by SKG, SBP-LEX alone governs/executes/audits. | No mismatch; readiness contract formalises same principle. | Reference as supporting material. | LOW | false |

## Missing From Repo

- Exact `SAFETY CONSEQUENTIALITY & FINANCIAL TIERING` source document was not found by exact title.
- Exact `V6 build Security Config` blueprint title was not found as a standalone original blueprint; related security docs/reports exist.
- Exact `Adaptive Multi Mode Governance Traversal` standalone blueprint was not found by exact title; related simulation and traversal docs exist.
- Exact `Anti_Drift_Destabilisation_Doctrines` title was not found; related anti-drift blueprint/addenda exist.
