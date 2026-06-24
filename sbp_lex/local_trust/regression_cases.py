from __future__ import annotations

from typing import NamedTuple


REGRESSION_CASE_PASS = "REGRESSION_CASE_PASS"
REGRESSION_CASE_FAIL = "REGRESSION_CASE_FAIL"
REGRESSION_CASE_SKIPPED = "REGRESSION_CASE_SKIPPED"
REGRESSION_CASE_ERROR = "REGRESSION_CASE_ERROR"

REGRESSION_CASE_STATUSES = {
    REGRESSION_CASE_PASS,
    REGRESSION_CASE_FAIL,
    REGRESSION_CASE_SKIPPED,
    REGRESSION_CASE_ERROR,
}


class RegressionCaseSpec(NamedTuple):
    case_id: str
    case_name: str
    risk_category: str
    target_artifact: str
    mutation_type: str
    expected_detection: str


REGRESSION_CASE_SPECS: tuple[RegressionCaseSpec, ...] = (
    RegressionCaseSpec(
        "manifest_digest_tampering",
        "Manifest digest tampering",
        "manifest_integrity",
        "outputs/local_trust_root_manifest.json",
        "payload_digest_mutation",
        "LOCAL_TRUST_INVALID",
    ),
    RegressionCaseSpec(
        "execution_envelope_digest_tampering",
        "Execution envelope digest tampering",
        "execution_environment_integrity",
        "outputs/local_execution_environment_trust_envelope.json",
        "payload_digest_mutation",
        "EXECUTION_ENV_INVALID",
    ),
    RegressionCaseSpec(
        "evidence_chain_digest_tampering",
        "Evidence chain digest tampering",
        "evidence_chain_integrity",
        "outputs/local_evidence_chain.json",
        "payload_digest_mutation",
        "EVIDENCE_CHAIN_INVALID",
    ),
    RegressionCaseSpec(
        "missing_evidence_artifact",
        "Missing evidence artifact",
        "evidence_availability",
        "registered evidence item",
        "copied_evidence_removed",
        "MISSING_NOW",
    ),
    RegressionCaseSpec(
        "modified_evidence_artifact",
        "Modified evidence artifact",
        "evidence_integrity",
        "registered evidence item",
        "copied_evidence_modified",
        "HASH_CHANGED",
    ),
    RegressionCaseSpec(
        "stale_commit_reference",
        "Stale commit reference",
        "repository_provenance",
        "local trust manifest copy",
        "git_commit_rewrite",
        "LOCAL_TRUST_STALE",
    ),
    RegressionCaseSpec(
        "dirty_working_tree_handling",
        "Dirty working tree handling",
        "repository_provenance",
        "local trust manifest copy",
        "working_tree_flag_rewrite",
        "LOCAL_TRUST_DIRTY",
    ),
    RegressionCaseSpec(
        "missing_bound_manifest",
        "Missing bound manifest",
        "artifact_binding",
        "execution envelope binding",
        "missing_manifest_path",
        "EXECUTION_ENV_INCOMPLETE",
    ),
    RegressionCaseSpec(
        "missing_bound_execution_envelope",
        "Missing bound execution envelope",
        "artifact_binding",
        "evidence chain binding",
        "missing_envelope_path",
        "EVIDENCE_CHAIN_INCOMPLETE",
    ),
    RegressionCaseSpec(
        "missing_bound_evidence_chain",
        "Missing bound evidence chain",
        "artifact_binding",
        "regression matrix binding",
        "missing_chain_path",
        "EVIDENCE_CHAIN_MISSING",
    ),
    RegressionCaseSpec(
        "forbidden_authority_leakage_in_manifest",
        "Forbidden authority leakage in manifest",
        "authority_boundary",
        "local trust manifest copy",
        "forbidden_key_injection",
        "LOCAL_TRUST_INVALID",
    ),
    RegressionCaseSpec(
        "forbidden_authority_leakage_in_execution_envelope",
        "Forbidden authority leakage in execution envelope",
        "authority_boundary",
        "execution envelope copy",
        "forbidden_key_injection",
        "EXECUTION_ENV_INVALID",
    ),
    RegressionCaseSpec(
        "forbidden_authority_leakage_in_evidence_chain",
        "Forbidden authority leakage in evidence chain",
        "authority_boundary",
        "evidence chain copy",
        "forbidden_key_injection",
        "EVIDENCE_CHAIN_INVALID",
    ),
    RegressionCaseSpec(
        "generated_outputs_pytest_ignore",
        "Generated output collection guard",
        "test_environment_provenance",
        "pytest invocation provenance",
        "verification_option_check",
        "PYTEST_OUTPUT_IGNORE_RECORDED",
    ),
    RegressionCaseSpec(
        "temp_cache_evidence_exclusion",
        "Temporary and cache evidence exclusion",
        "evidence_scope",
        "evidence registry",
        "excluded_path_check",
        "EXCLUDED_PATHS_PRESENT",
    ),
    RegressionCaseSpec(
        "wrong_python_executable_flag",
        "Wrong Python executable flag",
        "python_provenance",
        "execution envelope copy",
        "python_executable_rewrite",
        "PYTHON_EXECUTABLE_MISMATCH",
    ),
    RegressionCaseSpec(
        "future_activation_phrase_absence",
        "Future activation phrase absence",
        "authority_boundary",
        "executable local trust source",
        "source_boundary_scan",
        "ACTIVE_IMPLEMENTATION_TERM_ABSENT",
    ),
    RegressionCaseSpec(
        "phase_19_not_started_confirmation",
        "Phase 19 not started confirmation",
        "phase_boundary",
        "repository evidence",
        "phase_boundary_scan",
        "PHASE_19_NOT_STARTED",
    ),
    RegressionCaseSpec(
        "future_surface_absence_confirmation",
        "Future surface absence confirmation",
        "scope_boundary",
        "executable source",
        "source_boundary_scan",
        "FUTURE_SURFACE_TERMS_ABSENT",
    ),
)

REQUIRED_REGRESSION_CASE_IDS = frozenset(spec.case_id for spec in REGRESSION_CASE_SPECS)
