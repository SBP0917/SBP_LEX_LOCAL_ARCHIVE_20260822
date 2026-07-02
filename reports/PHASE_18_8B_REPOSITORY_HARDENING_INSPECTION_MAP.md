# Phase 18.8B Repository Hardening Inspection Map

Phase suffix used: 18.8B

Status: Repository-contained inspection map for final university handover hardening. This report does not claim production readiness.

## Existing Repository-Contained Hardening

- EIE is built as canonical traversal state in `sbp_lex/shared/state_builder.py`.
- SKG and DTN enrichment metadata are attached to EIE/PT envelope in `sbp_lex/collective/context_interface.py` and `sbp_lex/governance/procedural_truth_envelope.py`.
- Root of Trust binds EIE, SKG, DTN, evidence package, state hash, traversal ID, token trace, and audit trace in `sbp_lex/authority_first/root_of_trust_runner.py`.
- Procedural Truth requires evidentiary sufficiency factors beyond source-count floors in `sbp_lex/governance/procedural_truth_engine.py`.
- Execution Gate validates tokens, threshold bundle, convergence, PT certification, Root status, SKG/DTN status, and audit/controlled outcome links in `sbp_lex/execution/execution_gate.py`.
- Audit and replay preserve expanded PT-bound metadata in `sbp_lex/audit/audit_engine.py` and `sbp_lex/pipeline/replay_runner.py`.
- Dossier overclaim detection exists in `sbp_lex/local_trust/dossier_validator.py`.

## Remaining Local Weaknesses Hardened In Code

- EIE binding was scattered across downstream checks. Fixed by `sbp_lex/shared/control_chain_validation.py`.
- EIE hash semantics were implicit. Fixed by `canonical_eie_digest`, excluding downstream Root/PT result containers while binding identity/source/request/SKG/DTN.
- Root-bound state hash could be confused with later post-anchor state hash. Fixed by `root_anchor_bound_state_hash`.
- Classification/Governance could rely on canonical upstream token checks without shared EIE/SKG/DTN/Root validation. Fixed in `sbp_lex/security/authority_boundary.py`.
- Execution Gate now independently invokes shared control-chain and Root anchor validators.
- Dossier detector now rejects positive production/certification overclaims while allowing explicit exclusions.

## Remaining Local Weaknesses That Can Only Be Documented

- Local deterministic signatures are not hardware-backed.
- Local SKG/DTN metadata is non-authoritative and not backed by deployed external services.
- Local audit/replay detects mutation but does not provide external append-only custody.
- Adapter coverage is limited to current repository request contracts.

## External-Production Requirements Not Fixable Inside This Repo

- Isolated service/process separation.
- TPM/HSM-backed key custody.
- Real certificate-backed identity, rotation, and revocation.
- Independent verifier process.
- External append-only audit custody and independent timestamping/notarisation.
- Deployed SKG/DTN services and authoritative registries.
- Real adapter contract library and conformance suite.
- Formal security, safety, legal, regulatory, university, or third-party validation.
- Production threat model, monitoring, and incident response.

## Affected Files / Components

- `sbp_lex/shared/control_chain_validation.py`
- `sbp_lex/shared/state_builder.py`
- `sbp_lex/collective/context_interface.py`
- `sbp_lex/authority_first/root_of_trust_runner.py`
- `sbp_lex/security/authority_boundary.py`
- `sbp_lex/execution/execution_gate.py`
- `sbp_lex/audit/audit_engine.py`
- `sbp_lex/pipeline/replay_runner.py`
- `sbp_lex/local_trust/dossier_validator.py`
- `tests/test_phase_18_8b_repository_hardening.py`
- `docs/canonical_blueprint_series/`

## Tests Already Covering Each Area

- EIE/SKG/DTN/PT/Root rebuild: `tests/test_eie_pt_sufficiency_rebuild.py`
- Execution Gate strictness: `tests/test_execution_gate_strictness.py`
- PT thresholds: `tests/test_phase_18_procedural_truth_binding.py`
- Dossier package: `tests/test_phase_18_8_university_validation_dossier.py`
- Phase 18.8B negative hardening: `tests/test_phase_18_8b_repository_hardening.py`

## Missing Tests Before This Pass

- Rogue EIE with wrong hash.
- Missing source identity and source payload hash.
- SKG/DTN metadata hash absence.
- Root evidence hash mismatch.
- Token reuse and missing threshold-token paths.
- Pre-classification and pre-governance direct-call attempts.
- Audit metadata dropout and replay mutation.
- Dossier positive production-readiness overclaim.

These are now covered by `tests/test_phase_18_8b_repository_hardening.py`.
