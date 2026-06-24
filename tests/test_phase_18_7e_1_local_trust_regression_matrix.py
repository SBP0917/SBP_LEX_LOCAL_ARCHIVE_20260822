from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.regression_cases import REQUIRED_REGRESSION_CASE_IDS
from sbp_lex.local_trust.regression_matrix import (
    build_local_trust_regression_matrix,
    hash_matrix_payload,
    load_local_trust_regression_matrix,
    matrix_digest_for,
    matrix_signature_for,
    write_local_trust_regression_matrix,
)
from sbp_lex.local_trust.regression_validator import (
    REGRESSION_MATRIX_DIRTY,
    REGRESSION_MATRIX_INCOMPLETE,
    REGRESSION_MATRIX_INVALID,
    REGRESSION_MATRIX_STALE,
    REGRESSION_MATRIX_VALID,
    validate_local_trust_regression_matrix,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"


def test_build_creates_valid_skipped_case_matrix() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT)

    assert matrix["matrix_type"] == "local_trust_regression_matrix"
    assert matrix["matrix_version"] == "18.7E.1"
    assert matrix["matrix_status"] == REGRESSION_MATRIX_VALID
    assert matrix["regression_summary"]["total_cases"] == 19
    assert matrix["regression_summary"]["skipped_cases"] == 19


def test_run_creates_valid_passing_matrix() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)

    assert matrix["matrix_status"] == REGRESSION_MATRIX_VALID
    assert matrix["regression_summary"] == {
        "total_cases": 19,
        "passed_cases": 19,
        "failed_cases": 0,
        "skipped_cases": 0,
        "error_cases": 0,
        "all_cases_passed": True,
    }


def test_matrix_includes_repository_and_binding_provenance() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)

    assert matrix["repository_root"] == str(REPOSITORY_ROOT)
    assert matrix["git_branch"] == "main"
    assert len(matrix["git_commit"]) == 40
    assert len(matrix["bound_manifest_digest"]) == 64
    assert len(matrix["bound_execution_envelope_digest"]) == 64
    assert len(matrix["bound_evidence_chain_digest"]) == 64


def test_matrix_contains_required_regression_cases() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)
    case_ids = {case["case_id"] for case in matrix["regression_cases"]}

    assert REQUIRED_REGRESSION_CASE_IDS <= case_ids


def test_matrix_digest_validates() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)
    validation = validate_local_trust_regression_matrix(matrix, repository_root=REPOSITORY_ROOT)

    assert validation == {"matrix_status": REGRESSION_MATRIX_VALID, "validation_failures": []}


def test_matrix_tampering_is_detected() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)
    matrix["git_branch"] = "tampered"
    validation = validate_local_trust_regression_matrix(matrix, repository_root=REPOSITORY_ROOT)

    assert validation["matrix_status"] == REGRESSION_MATRIX_INVALID
    assert "matrix_payload_digest_mismatch" in validation["validation_failures"]


def test_missing_required_sections_produce_incomplete_status() -> None:
    validation = validate_local_trust_regression_matrix({"matrix_type": "local_trust_regression_matrix"})

    assert validation["matrix_status"] == REGRESSION_MATRIX_INCOMPLETE
    assert any(item.startswith("missing_required_section:") for item in validation["validation_failures"])


def test_stale_commit_reference_can_be_detected() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)
    matrix["git_commit"] = "0" * 40
    _refresh_digests(matrix)
    validation = validate_local_trust_regression_matrix(matrix, repository_root=REPOSITORY_ROOT, current_validation=True)

    assert validation == {"matrix_status": REGRESSION_MATRIX_STALE, "validation_failures": ["git_commit_stale"]}


def test_dirty_working_tree_can_be_detected_when_required() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)
    matrix["working_tree_clean"] = False
    _refresh_digests(matrix)
    validation = validate_local_trust_regression_matrix(matrix, clean_required=True)

    assert validation == {"matrix_status": REGRESSION_MATRIX_DIRTY, "validation_failures": ["working_tree_dirty"]}


def test_forbidden_authority_leakage_in_matrix_is_rejected() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)
    matrix["unsafe"] = {"execution_permission": True}
    _refresh_digests(matrix)
    validation = validate_local_trust_regression_matrix(matrix, repository_root=REPOSITORY_ROOT)

    assert validation["matrix_status"] == REGRESSION_MATRIX_INVALID
    assert "forbidden_authority_key:$.unsafe.execution_permission" in validation["validation_failures"]


def test_cli_build_creates_output_matrix(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_regression_matrix.json"
    result = _run_cli("build", "--path", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "REGRESSION_MATRIX_VALID" in result.stdout


def test_cli_run_creates_passing_output_matrix(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_regression_matrix.json"
    result = _run_cli("run", "--path", str(output))
    matrix = load_local_trust_regression_matrix(output, repository_root=REPOSITORY_ROOT)

    assert result.returncode == 0
    assert matrix["matrix_status"] == REGRESSION_MATRIX_VALID
    assert matrix["regression_summary"]["passed_cases"] == 19


def test_cli_validate_validates_output_matrix(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_regression_matrix.json"
    _run_cli("run", "--path", str(output))
    result = _run_cli("validate", "--path", str(output))

    assert result.returncode == 0
    assert result.stdout.strip() == "REGRESSION_MATRIX_VALID"


def test_cli_show_prints_summary(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_regression_matrix.json"
    _run_cli("run", "--path", str(output))
    result = _run_cli("show", "--path", str(output))

    assert result.returncode == 0
    assert "REGRESSION_MATRIX_VALID" in result.stdout
    assert "cases=19" in result.stdout
    assert "passed=19" in result.stdout


def test_write_and_load_round_trip(tmp_path: Path) -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)
    output = write_local_trust_regression_matrix(matrix, tmp_path / "matrix.json", repository_root=REPOSITORY_ROOT)
    loaded = load_local_trust_regression_matrix(output, repository_root=REPOSITORY_ROOT)

    assert loaded == matrix


def test_regression_package_does_not_execute_runtime_replay_or_tests() -> None:
    source = _regression_source()

    assert "python main.py" not in source
    assert "main.py replay" not in source
    assert "scripts\\run_tests.bat" not in source
    assert "subprocess.run" not in source
    assert "capture_supported_commands" not in source


def test_no_prohibited_future_surface_terms_in_regression_implementation() -> None:
    source = _regression_source()

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


def test_output_matrix_path_is_not_a_runtime_authority() -> None:
    matrix = build_local_trust_regression_matrix(REPOSITORY_ROOT, run_cases=True)

    assert "execution_permission" not in matrix
    assert "governance_result" not in matrix
    assert "runtime_authority" not in matrix


def _refresh_digests(matrix: dict) -> None:
    payload_digest = hash_matrix_payload(matrix)
    matrix["matrix_payload_digest"] = payload_digest
    matrix["matrix_signature"] = matrix_signature_for(payload_digest)
    matrix["matrix_digest"] = matrix_digest_for(payload_digest, matrix["matrix_signature"])


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.regression_matrix", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _regression_source() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(LOCAL_TRUST_ROOT.glob("regression_*.py"))
    )
