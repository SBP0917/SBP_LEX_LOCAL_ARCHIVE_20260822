# Blueprint Source and Supersession Map

Draft status: Phase 18.8B repository-side implementation alignment material pending owner canonisation.

## Purpose

This map ties the 13-document blueprint series to repository files, Phase 18.8A addenda, and Phase 18.8B hardening reports. It does not erase historical documents.

## Source Basis

- Runtime traversal: `sbp_lex/pipeline/runner.py`, `sbp_lex/pipeline/dual_runner.py`
- EIE/state: `sbp_lex/shared/state_builder.py`, `sbp_lex/shared/control_chain_validation.py`
- SKG/DTN: `sbp_lex/collective/context_interface.py`, `sbp_lex/collective/sovereign_knowledge_graph_engine.py`, `sbp_lex/collective/digital_twin_network_engine.py`, `external_substrates/skg/signal_builder.py`, `external_substrates/dtn/signal_builder.py`
- Root/PT: `sbp_lex/authority_first/root_of_trust_runner.py`, `sbp_lex/governance/procedural_truth_engine.py`, `sbp_lex/governance/procedural_truth_envelope.py`
- Tokens/gates: `sbp_lex/security/token_stack.py`, `sbp_lex/security/threshold_tokens.py`, `sbp_lex/security/authority_boundary.py`, `sbp_lex/execution/execution_gate.py`
- Audit/replay: `sbp_lex/audit/audit_engine.py`, `sbp_lex/audit/historical_integrity.py`, `sbp_lex/pipeline/replay_runner.py`
- Dossier: `sbp_lex/local_trust/`, `outputs/university_validation_dossier/`, `docs/UNIVERSITY_VALIDATION_DOSSIER.md`
- Tests: `tests/test_phase_18_8b_repository_hardening.py`, `tests/test_eie_pt_sufficiency_rebuild.py`, `tests/test_execution_gate_strictness.py`

## Addendum Relationship

The files under `docs/blueprint_addenda/` remain repository-side implementation alignment material pending owner canonisation. They are source inputs to this series, not deleted or replaced master doctrine.

## Supersession Note

This series supersedes no owner-approved master doctrine by itself. It reflects the repository-contained Phase 18.8B implementation state and should be canonised only by owner decision.

## External Production Requirements

Production deployment would still require independent security review, real adapter contracts, authoritative SKG/DTN services, isolated trust custody, external append-only audit custody, independent timestamping, formal safety/legal/regulatory review, and third-party or university validation.
