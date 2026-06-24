from __future__ import annotations

from typing import NamedTuple


LOCAL_TRUST_CONSTITUTIONAL_GATE_POLICY_VERSION = "LOCAL_TRUST_CONSTITUTIONAL_GATE_POLICY_V1"

GATE_PASS = "GATE_PASS"
GATE_FAIL = "GATE_FAIL"
GATE_SKIPPED = "GATE_SKIPPED"
GATE_ERROR = "GATE_ERROR"

GATE_STATUSES = {GATE_PASS, GATE_FAIL, GATE_SKIPPED, GATE_ERROR}


class GateSpec(NamedTuple):
    gate_id: str
    gate_name: str
    gate_category: str
    required: bool
    input_artifact: str
    expected_condition: str


GATE_SPECS: tuple[GateSpec, ...] = (
    GateSpec("manifest_exists", "Local trust manifest exists", "artifact", True, "manifest", "PRESENT"),
    GateSpec("manifest_validates", "Local trust manifest validates", "artifact", True, "manifest", "LOCAL_TRUST_VALID"),
    GateSpec("execution_envelope_exists", "Execution environment envelope exists", "artifact", True, "execution_envelope", "PRESENT"),
    GateSpec("execution_envelope_validates", "Execution environment envelope validates", "artifact", True, "execution_envelope", "EXECUTION_ENV_VALID"),
    GateSpec("evidence_chain_exists", "Local evidence chain exists", "artifact", True, "evidence_chain", "PRESENT"),
    GateSpec("evidence_chain_validates", "Local evidence chain validates", "artifact", True, "evidence_chain", "EVIDENCE_CHAIN_VALID"),
    GateSpec("evidence_chain_zero_missing", "Evidence chain has zero missing evidence", "evidence", True, "evidence_chain", "missing_evidence_items=0"),
    GateSpec("evidence_chain_zero_changed", "Evidence chain compare reports zero changed items", "evidence", True, "evidence_chain", "changed_evidence_items=0"),
    GateSpec("regression_matrix_exists", "Local trust regression matrix exists", "artifact", True, "regression_matrix", "PRESENT"),
    GateSpec("regression_matrix_validates", "Local trust regression matrix validates", "regression", True, "regression_matrix", "REGRESSION_MATRIX_VALID"),
    GateSpec("regression_cases_passed", "Required regression cases passed", "regression", True, "regression_matrix", "no failed or error cases"),
    GateSpec("manifest_digest_binding", "Manifest digest matches bound digest", "binding", True, "manifest", "digest_match"),
    GateSpec("execution_envelope_digest_binding", "Execution envelope digest matches bound digest", "binding", True, "execution_envelope", "digest_match"),
    GateSpec("evidence_chain_digest_binding", "Evidence chain digest matches bound digest", "binding", True, "evidence_chain", "digest_match"),
    GateSpec("regression_matrix_digest_binding", "Regression matrix digest matches bound digest", "binding", True, "regression_matrix", "digest_match"),
    GateSpec("working_tree_policy", "Working tree policy is satisfied", "repository", True, "git", "policy_recorded"),
    GateSpec("branch_recorded", "Current branch is recorded", "repository", True, "git", "branch_recorded"),
    GateSpec("commit_recorded", "Current commit is recorded", "repository", True, "git", "commit_recorded"),
    GateSpec("forbidden_authority_absent", "Forbidden authority leakage absent from local trust outputs", "boundary", True, "local_trust_outputs", "forbidden_keys_absent"),
    GateSpec("future_activation_absent", "Future activation active implementation absent", "boundary", True, "local_trust_source", "active_term_absent"),
    GateSpec("phase_19_boundary_preserved", "Phase 19 not-started boundary preserved", "boundary", True, "repository_evidence", "phase_19_not_started"),
    GateSpec("future_surface_absent", "Future surface active implementation absent", "boundary", True, "local_trust_source", "active_terms_absent"),
    GateSpec("generated_outputs_pytest_policy", "Generated output folders excluded from pytest collection policy", "test_policy", True, "regression_matrix", "pytest_output_ignore_recorded"),
    GateSpec("temp_cache_evidence_exclusion", "Temporary and cache folders excluded from evidence", "evidence", True, "evidence_chain", "excluded_paths_present"),
)

REQUIRED_GATE_IDS = frozenset(spec.gate_id for spec in GATE_SPECS if spec.required)
