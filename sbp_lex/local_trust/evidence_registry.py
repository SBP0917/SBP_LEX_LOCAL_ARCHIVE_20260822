from __future__ import annotations

from typing import Any


EvidenceSpec = dict[str, Any]

REQUIRED_EVIDENCE_SPECS: tuple[EvidenceSpec, ...] = (
    {
        "evidence_id": "phase_18_procedural_truth_binding_report",
        "path": "reports/PHASE_18_PROCEDURAL_TRUTH_BINDING_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "Phase 18",
    },
    {
        "evidence_id": "phase_18_5_authority_boundary_audit",
        "path": "reports/PHASE_18_5_PRE_ACTIVATION_AUTHORITY_BOUNDARY_AUDIT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "Phase 18.5",
    },
    {
        "evidence_id": "phase_18_6_historical_mutation_attack_report",
        "path": "reports/PHASE_18_6_HISTORICAL_AUDIT_MUTATION_ATTACK_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "Phase 18.6",
    },
    {
        "evidence_id": "phase_red_20a_attack_report",
        "path": "reports/PHASE_RED_20A_ATTACK_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "RED-20A",
    },
    {
        "evidence_id": "phase_red_20b_attack_report",
        "path": "reports/PHASE_RED_20B_ATTACK_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "RED-20B",
    },
    {
        "evidence_id": "phase_red_20c_attack_report",
        "path": "reports/PHASE_RED_20C_ATTACK_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "RED-20C",
    },
    {
        "evidence_id": "phase_red_20d_attack_report",
        "path": "reports/PHASE_RED_20D_ATTACK_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "RED-20D",
    },
    {
        "evidence_id": "sbp_operator_assistant_v1_implementation_report",
        "path": "reports/SBP_OPERATOR_ASSISTANT_V1_IMPLEMENTATION_REPORT.md",
        "category": "implementation_report",
        "required": True,
        "source_phase": "SBP Operator Assistant V1",
    },
    {
        "evidence_id": "phase_18_7b_local_trust_manifest_report",
        "path": "reports/PHASE_18_7B_LOCAL_TRUST_ROOT_MANIFEST_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "Phase 18.7B",
    },
    {
        "evidence_id": "phase_18_7c_execution_envelope_report",
        "path": "reports/PHASE_18_7C_LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE_REPORT.md",
        "category": "phase_report",
        "required": True,
        "source_phase": "Phase 18.7C",
    },
    {
        "evidence_id": "sbp_operator_assistant_v1_commit_and_test_report",
        "path": "outputs/SBP_OPERATOR_ASSISTANT_V1_COMMIT_AND_TEST_REPORT.md",
        "category": "commit_report",
        "required": True,
        "source_phase": "SBP Operator Assistant V1",
    },
    {
        "evidence_id": "local_trust_root_manifest",
        "path": "outputs/local_trust_root_manifest.json",
        "category": "manifest",
        "required": True,
        "source_phase": "Phase 18.7B",
    },
    {
        "evidence_id": "local_execution_environment_trust_envelope",
        "path": "outputs/local_execution_environment_trust_envelope.json",
        "category": "execution_envelope",
        "required": True,
        "source_phase": "Phase 18.7C",
    },
    {
        "evidence_id": "local_trust_root_manifest_documentation",
        "path": "docs/LOCAL_TRUST_ROOT_MANIFEST.md",
        "category": "documentation",
        "required": True,
        "source_phase": "Phase 18.7B",
    },
    {
        "evidence_id": "local_execution_environment_trust_envelope_documentation",
        "path": "docs/LOCAL_EXECUTION_ENVIRONMENT_TRUST_ENVELOPE.md",
        "category": "documentation",
        "required": True,
        "source_phase": "Phase 18.7C",
    },
)

EXCLUDED_PATHS: tuple[str, ...] = (
    ".pytest_cache",
    ".pytest_tmp_*",
    "outputs/local_trust_temp",
    ".sbp_lex_local_trust*",
    "__pycache__",
    "*.pyc",
    ".git",
)
