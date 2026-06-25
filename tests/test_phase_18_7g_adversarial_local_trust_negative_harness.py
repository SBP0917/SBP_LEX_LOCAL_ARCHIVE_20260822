from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from sbp_lex.local_trust.adversarial_cases import required_adversarial_case_ids
from sbp_lex.local_trust.adversarial_negative_harness import (
    DEFAULT_ADVERSARIAL_OUTPUT_PATH,
    build_adversarial_harness,
    load_adversarial_harness,
    validate_adversarial_harness_file,
    write_adversarial_harness,
)
from sbp_lex.local_trust.adversarial_validator import (
    ADVERSARIAL_NEGATIVE_HARNESS_FAIL,
    ADVERSARIAL_NEGATIVE_HARNESS_PASS,
    validate_adversarial_harness,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"
PROTECTED_RUNTIME_PATHS = {
    "main.py",
    "sbp_lex/execution/execution_gate.py",
    "sbp_lex/governance/procedural_truth_engine.py",
    "sbp_lex/governance/procedural_truth_runner.py",
    "sbp_lex/authority_first/root_of_trust_runner.py",
    "sbp_lex/shared/hash_chain.py",
    "sbp_lex/shared/state_builder.py",
    "sbp_lex/pipeline/dual_runner.py",
}
BASELINE_ARTIFACTS = (
    "outputs/local_trust_root_manifest.json",
    "outputs/local_execution_environment_trust_envelope.json",
    "outputs/local_evidence_chain.json",
    "outputs/local_trust_regression_matrix.json",
    "outputs/local_constitutional_gates.json",
    "outputs/local_toolchain_guard.json",
    "outputs/local_trust_25_year_capstone.json",
    "outputs/release_integrity_bundle/RELEASE_MANIFEST.json",
)


def test_builds_adversarial_harness_output(tmp_path: Path) -> None:
    harness = build_adversarial_harness(REPOSITORY_ROOT)
    path = write_adversarial_harness(harness, tmp_path / "harness.json", repository_root=REPOSITORY_ROOT)

    assert path.exists()
    assert harness["adversarial_status"] == ADVERSARIAL_NEGATIVE_HARNESS_PASS
    assert harness["adversarial_summary"]["total_cases"] == 39


def test_adversarial_output_binds_manifest_digest() -> None:
    harness = _harness()

    assert harness["bound_manifest_digest"] == _load_repo_json("outputs/local_trust_root_manifest.json")["manifest_digest"]


def test_adversarial_output_binds_execution_envelope_digest() -> None:
    harness = _harness()

    assert harness["bound_execution_envelope_digest"] == _load_repo_json(
        "outputs/local_execution_environment_trust_envelope.json"
    )["envelope_digest"]


def test_adversarial_output_binds_evidence_chain_digest() -> None:
    harness = _harness()

    assert harness["bound_evidence_chain_digest"] == _load_repo_json("outputs/local_evidence_chain.json")["chain_digest"]


def test_adversarial_output_binds_regression_matrix_digest() -> None:
    harness = _harness()

    assert harness["bound_regression_matrix_digest"] == _load_repo_json("outputs/local_trust_regression_matrix.json")[
        "matrix_digest"
    ]


def test_adversarial_output_binds_constitutional_gates_digest() -> None:
    harness = _harness()

    assert harness["bound_constitutional_gates_digest"] == _load_repo_json("outputs/local_constitutional_gates.json")[
        "gate_digest"
    ]


def test_adversarial_output_binds_toolchain_guard_digest() -> None:
    harness = _harness()

    assert harness["bound_toolchain_guard_digest"] == _load_repo_json("outputs/local_toolchain_guard.json")[
        "toolchain_digest"
    ]


def test_adversarial_output_binds_capstone_digest() -> None:
    harness = _harness()

    assert harness["bound_capstone_digest"] == _load_repo_json("outputs/local_trust_25_year_capstone.json")[
        "capstone_digest"
    ]


def test_adversarial_output_binds_release_integrity_digest() -> None:
    harness = _harness()

    assert harness["bound_release_integrity_digest"] == _load_repo_json(
        "outputs/release_integrity_bundle/RELEASE_MANIFEST.json"
    )["release_digest"]


def test_adversarial_digest_validates(tmp_path: Path) -> None:
    path = _write_tmp_harness(tmp_path)

    assert validate_adversarial_harness_file(REPOSITORY_ROOT, path=path) == {
        "adversarial_status": ADVERSARIAL_NEGATIVE_HARNESS_PASS,
        "validation_failures": [],
    }


def test_tampered_adversarial_digest_is_detected() -> None:
    harness = _harness()
    harness["adversarial_digest"] = "0" * 64
    validation = validate_adversarial_harness(harness, repository_root=REPOSITORY_ROOT)

    assert validation["adversarial_status"] == ADVERSARIAL_NEGATIVE_HARNESS_FAIL
    assert "adversarial_digest_mismatch" in validation["validation_failures"]


@pytest.mark.parametrize(
    "case_id",
    sorted(required_adversarial_case_ids()),
)
def test_required_negative_case_passes(case_id: str) -> None:
    case = _case_by_id(case_id)

    assert case["status"] == "ADVERSARIAL_CASE_PASS"


def test_missing_manifest_negative_case_passes() -> None:
    assert _case_by_id("missing_local_trust_manifest")["actual_detection"] == "LOCAL_TRUST_MANIFEST_MISSING"


def test_tampered_manifest_negative_case_passes() -> None:
    assert _case_by_id("tampered_local_trust_manifest_digest")["actual_detection"] == "LOCAL_TRUST_INVALID"


def test_missing_execution_envelope_negative_case_passes() -> None:
    assert _case_by_id("missing_execution_envelope")["actual_detection"] == "EXECUTION_ENVELOPE_MISSING"


def test_tampered_execution_envelope_negative_case_passes() -> None:
    assert _case_by_id("tampered_execution_envelope_digest")["actual_detection"] == "EXECUTION_ENV_INVALID"


def test_missing_evidence_chain_negative_case_passes() -> None:
    assert _case_by_id("missing_evidence_chain")["actual_detection"] == "EVIDENCE_CHAIN_MISSING"


def test_tampered_evidence_chain_negative_case_passes() -> None:
    assert _case_by_id("tampered_evidence_chain_digest")["actual_detection"] == "EVIDENCE_CHAIN_INVALID"


def test_missing_evidence_item_negative_case_passes() -> None:
    assert _case_by_id("evidence_chain_missing_required_item")["actual_detection"] == "MISSING_REQUIRED_EVIDENCE_ITEM"


def test_changed_evidence_item_negative_case_passes() -> None:
    assert _case_by_id("evidence_chain_changed_item")["actual_detection"] == "EVIDENCE_CHAIN_INVALID"


def test_failed_regression_matrix_negative_case_passes() -> None:
    assert _case_by_id("failed_regression_matrix_case")["actual_detection"] == "REGRESSION_MATRIX_FAILED"


def test_failed_constitutional_gate_negative_case_passes() -> None:
    assert _case_by_id("failed_constitutional_gate")["actual_detection"] == "CONSTITUTIONAL_GATES_FAIL"


def test_toolchain_drift_negative_case_passes() -> None:
    assert _case_by_id("wrong_python_version_evidence")["actual_detection"] == "TOOLCHAIN_GUARD_FAIL"
    assert _case_by_id("wrong_pytest_version_evidence")["actual_detection"] == "TOOLCHAIN_GUARD_FAIL"


def test_dependency_digest_mutation_negative_case_passes() -> None:
    assert _case_by_id("changed_dependency_file_digest")["actual_detection"] == "DEPENDENCY_DIGEST_CHANGED"


def test_capstone_tamper_negative_case_passes() -> None:
    assert _case_by_id("tampered_capstone_digest")["actual_detection"] == "LOCAL_TRUST_CAPSTONE_FAIL"


def test_release_manifest_tamper_negative_case_passes() -> None:
    assert _case_by_id("tampered_release_manifest_digest")["actual_detection"] == "RELEASE_INTEGRITY_FAIL"


def test_artifact_hash_mismatch_negative_case_passes() -> None:
    assert _case_by_id("artifact_hash_mismatch")["actual_detection"] == "RELEASE_INTEGRITY_FAIL"


def test_missing_release_artifact_negative_case_passes() -> None:
    assert _case_by_id("missing_required_release_artifact")["actual_detection"] == "RELEASE_INTEGRITY_INCOMPLETE"


def test_verification_command_removal_negative_case_passes() -> None:
    assert _case_by_id("verification_command_removed")["actual_detection"] == "RELEASE_INTEGRITY_INCOMPLETE"


def test_claims_seed_overclaim_negative_case_passes() -> None:
    assert _case_by_id("claims_seed_overclaim")["actual_detection"] == "CLAIMS_SEED_FALSE_CLAIM"


def test_boundary_lock_external_validation_false_claim_negative_case_passes() -> None:
    assert _case_by_id("boundary_lock_claims_external_validation")["actual_detection"] == "RELEASE_INTEGRITY_FAIL"


def test_runtime_activation_active_implementation_negative_case_passes() -> None:
    assert _case_by_id("runtimeActivation_active_implementation")["actual_detection"] == "RELEASE_INTEGRITY_FAIL"


def test_forbidden_authority_leakage_negative_case_passes() -> None:
    assert _case_by_id("forbidden_authority_leakage_appears")["actual_detection"] == "FORBIDDEN_AUTHORITY_LEAKAGE"


def test_phase_19_false_start_negative_case_passes() -> None:
    assert _case_by_id("boundary_lock_claims_phase_19_started")["actual_detection"] == "RELEASE_INTEGRITY_FAIL"


def test_future_surface_active_implementation_negative_case_passes() -> None:
    assert _case_by_id("future_surface_active_implementation")["actual_detection"] == "RELEASE_INTEGRITY_FAIL"


def test_cli_run_creates_adversarial_output(tmp_path: Path) -> None:
    path = tmp_path / "adversarial.json"
    result = _run_cli("run", "--path", str(path))

    assert result.returncode == 0
    assert "ADVERSARIAL_NEGATIVE_HARNESS_PASS" in result.stdout
    assert path.exists()


def test_cli_validate_validates_adversarial_output(tmp_path: Path) -> None:
    path = tmp_path / "adversarial.json"
    _run_cli("run", "--path", str(path))
    result = _run_cli("validate", "--path", str(path))

    assert result.returncode == 0
    assert result.stdout.strip() == "ADVERSARIAL_NEGATIVE_HARNESS_PASS"


def test_cli_show_prints_adversarial_status(tmp_path: Path) -> None:
    path = tmp_path / "adversarial.json"
    _run_cli("run", "--path", str(path))
    result = _run_cli("show", "--path", str(path))

    assert result.returncode == 0
    assert "ADVERSARIAL_NEGATIVE_HARNESS_PASS" in result.stdout
    assert "next_phase=18.8" in result.stdout


def test_importing_modules_does_not_execute_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.adversarial_negative_harness; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_adversarial_sources_do_not_execute_runtime_replay_pytest_or_batch() -> None:
    source = _adversarial_source()

    assert "subprocess.run" not in source
    assert "python main.py" not in source
    assert "main.py replay" not in source
    assert "run_tests.bat" not in source


def test_no_prohibited_active_terms_in_adversarial_implementation() -> None:
    source = _adversarial_source()

    for term in (
        "node_quorum",
        "node_attestation",
        "distributed_consensus",
        "mesh_runtime",
        "cloud_runtime",
        "runtime_activation",
        "external_execution_permission",
        "external_governance_result",
    ):
        assert term not in source


def test_real_baseline_artifacts_remain_unchanged_after_adversarial_run() -> None:
    before = {path: _sha256(REPOSITORY_ROOT / path) for path in BASELINE_ARTIFACTS}

    build_adversarial_harness(REPOSITORY_ROOT)

    after = {path: _sha256(REPOSITORY_ROOT / path) for path in BASELINE_ARTIFACTS}
    assert after == before


def test_temporary_adversarial_folders_are_excluded_from_commit() -> None:
    assert not (REPOSITORY_ROOT / "outputs/local_trust_adversarial_temp").exists()


def test_no_sbp_lex_runtime_authority_files_are_modified() -> None:
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    changed = {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}

    assert not (changed & PROTECTED_RUNTIME_PATHS)


def _harness() -> dict:
    return build_adversarial_harness(REPOSITORY_ROOT)


def _write_tmp_harness(tmp_path: Path) -> Path:
    return write_adversarial_harness(_harness(), tmp_path / "adversarial.json", repository_root=REPOSITORY_ROOT)


def _case_by_id(case_id: str) -> dict:
    cases = {case["case_id"]: case for case in _harness()["adversarial_case_results"]}
    return cases[case_id]


def _load_repo_json(path: str) -> dict:
    return json.loads((REPOSITORY_ROOT / path).read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.adversarial_negative_harness", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _adversarial_source() -> str:
    return "\n".join(
        (LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8")
        for name in (
            "adversarial_cases.py",
            "adversarial_negative_harness.py",
            "adversarial_runner.py",
            "adversarial_validator.py",
        )
    )

