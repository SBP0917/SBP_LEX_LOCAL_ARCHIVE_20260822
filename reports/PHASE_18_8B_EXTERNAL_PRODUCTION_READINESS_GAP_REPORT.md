# Phase 18.8B External Production-Readiness Gap Report

Status: Repository-contained gap report. Production-grade readiness is not claimed.

## A. Fixed Inside Repository

- EIE strictness: added shared EIE validation for identity, hash, source payload hash, adapter/source identity, traversal ID, request fingerprint, payload/context binding, and malformed values. Files: `sbp_lex/shared/control_chain_validation.py`, `sbp_lex/shared/state_builder.py`, `sbp_lex/collective/context_interface.py`. Tests: `tests/test_phase_18_8b_repository_hardening.py`.
- SKG/DTN enrichment validation: added completeness, status, readiness, hash, and EIE metadata match checks. Files: `sbp_lex/shared/control_chain_validation.py`. Tests: focused 18.8B negative tests.
- Root anchorage binding: added shared validators before anchoring and downstream Root anchor validation, including evidence package hash and stable Root-bound state hash. Files: `sbp_lex/authority_first/root_of_trust_runner.py`, `sbp_lex/shared/control_chain_validation.py`.
- PT sufficiency enforcement: retained source floor as minimum only and verified independence, provenance, integrity, attestation, authority, jurisdiction, freshness, consistency, runtime validity, contradiction handling, and consequence burden. Files: `sbp_lex/governance/procedural_truth_engine.py`, `tests/test_phase_18_8b_repository_hardening.py`.
- Token-chain and threshold-token enforcement: focused tests now prove missing threshold bundle, PT token mismatch, stale token reuse, and token signed-field tampering are rejected.
- Execution Gate independent verification: wired shared control-chain and Root anchor validation into Execution Gate.
- Audit/replay metadata preservation: expanded audit and replay PT-bound metadata.
- Dossier overclaim detection: hardened positive overclaim detection for production/certification wording.
- Blueprint/dossier alignment: added 13-document canonical blueprint series and source/supersession map.

## B. Repository-Side Hardening Implemented; External Validation Still Required

- Local signing is deterministic and useful for replay, but not hardware-backed. External need: HSM/TPM or equivalent key custody.
- Local Root binding is stronger, but not isolated from the same local process. External need: independent verifier/process isolation.
- Local audit mutation detection is stronger, but no external append-only custody exists. External need: append-only store, independent timestamping, notarisation.
- Local SKG/DTN metadata is complete and hash-bound, but not authoritative. External need: deployed SKG/DTN services and authoritative source registries.
- Local adapter/EIE schema is stricter, but not a full real-world adapter suite. External need: adapter contract library and conformance tests.
- Local dossier evidence is stronger, but remains review material. External need: independent university or third-party validation.

## C. External-Production Requirements

- Isolated service/process separation.
- TPM/HSM-backed key custody.
- Real certificate-backed identity.
- Key rotation and revocation.
- Independent verifier process.
- External append-only audit custody.
- Independent timestamping/notarisation.
- Deployed SKG/DTN services.
- Authoritative source registries.
- Real adapter contract library.
- Formal security review.
- Formal safety review.
- Formal legal/regulatory review.
- Independent university or third-party validation.
- Production deployment threat model.
- Operational monitoring and incident response.

## University Handover Boundary

SBP-LEX Dual V6 is presented as a local deterministic control-plane prototype suitable for university technical review, validation discussion, architectural assessment, stress testing, and further hardening feedback.
