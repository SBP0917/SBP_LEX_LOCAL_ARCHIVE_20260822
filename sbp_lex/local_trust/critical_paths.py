from __future__ import annotations


CRITICAL_FILE_PATHS: tuple[str, ...] = (
    "main.py",
    "scripts/run_tests.bat",
    "sbp_lex/persistence/integrity_store.py",
    "sbp_lex/execution/execution_gate.py",
    "sbp_lex/execution/capability.py",
    "sbp_lex/execution/capability_store.py",
    "sbp_lex/execution/schemas/execution_capability.schema.json",
    "sbp_lex/execution/schemas/post_execution_attestation.schema.json",
    "sbp_lex/execution/schemas/capability_lifecycle_record.schema.json",
    "sbp_lex/formal/__init__.py",
    "sbp_lex/formal/model.py",
    "sbp_lex/formal/verifier.py",
    "sbp_lex/formal/assurance.py",
    "sbp_lex/formal/schemas/formal_state.schema.json",
    "sbp_lex/formal/schemas/transition_record.schema.json",
    "sbp_lex/formal/schemas/lineage_node.schema.json",
    "sbp_lex/governance/procedural_truth_engine.py",
    "sbp_lex/governance/procedural_truth_runner.py",
    "sbp_lex/governance/grc.py",
    "sbp_lex/authority_first/root_of_trust_runner.py",
    "sbp_lex/shared/hash_chain.py",
    "sbp_lex/shared/state_builder.py",
    "sbp_lex/pipeline/dual_runner.py",
    "sbp_lex/runtime/canonical_runtime.py",
)

TRUSTED_REPORT_PATHS: tuple[str, ...] = (
    "reports/PHASE_18_PROCEDURAL_TRUTH_BINDING_REPORT.md",
    "reports/PHASE_18_5_PRE_ACTIVATION_AUTHORITY_BOUNDARY_AUDIT.md",
    "reports/PHASE_18_6_HISTORICAL_AUDIT_MUTATION_ATTACK_REPORT.md",
    "reports/PHASE_RED_20A_ATTACK_REPORT.md",
    "reports/PHASE_RED_20B_ATTACK_REPORT.md",
    "reports/PHASE_RED_20C_ATTACK_REPORT.md",
    "reports/PHASE_RED_20D_ATTACK_REPORT.md",
    "reports/SBP_OPERATOR_ASSISTANT_V1_IMPLEMENTATION_REPORT.md",
    "reports/PHQ_FORMAL_DETERMINISTIC_ARCHITECTURE_REPORT.md",
)

TRUSTED_OUTPUT_PATHS: tuple[str, ...] = (
    "outputs/SBP_OPERATOR_ASSISTANT_V1_COMMIT_AND_TEST_REPORT.md",
    "outputs/phq_formal_architecture_assurance.json",
)

VERIFICATION_COMMANDS: tuple[str, ...] = (
    "python -m compileall -q .",
    "python -m pytest -q",
    "scripts\\run_tests.bat",
    "python main.py",
    "python main.py replay",
    "git diff --check",
    "git status --short",
)

PHASE_BASELINE: tuple[str, ...] = (
    "Phase 15.5A complete",
    "Phase 15.5B complete",
    "Phase 15.5C complete",
    "Phase 15.5D complete",
    "Phase 15.6A complete",
    "Phase 15.6B complete",
    "Phase 18 complete",
    "Phase 18.5 complete",
    "Phase 18.6 complete",
    "RED-20A complete",
    "RED-20B complete",
    "RED-20C complete",
    "RED-20D complete",
    "Post-RED-20 integrity-store quarantine complete",
    "SBP Operator Assistant V1 complete",
    "Phase 19 not started",
)
