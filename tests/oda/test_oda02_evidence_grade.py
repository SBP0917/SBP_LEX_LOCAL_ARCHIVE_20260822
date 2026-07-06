import json
import subprocess
import sys

from sbp_oda.boundary_checker import run_boundary_check
from sbp_oda.dependencies import inspect_dependency_and_pqc_provider, parse_requirements
from sbp_oda.health.local_deployment_scanner import scan_local_deployment
from sbp_oda.maintenance.work_package_planner import plan_maintenance_work_package
from sbp_oda.query_assistant import answer_query
from sbp_oda.status import FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS, ODAStatus
from sbp_oda.support.support_bundle_builder import verify_support_bundle_digest


def test_health_scan_returns_real_repo_and_python_status_fields() -> None:
    scan = scan_local_deployment(".")

    assert scan["repository_root_exists"] is True
    assert scan["main_py_exists"] is True
    assert "current_branch" in scan
    assert "current_commit_hash" in scan
    assert isinstance(scan["dirty_tree"], bool)
    assert isinstance(scan["untracked_file_count"], int)
    assert isinstance(scan["tracked_modified_file_count"], int)
    assert scan["python_executable"]
    assert scan["python_version"]


def test_dependency_scan_detects_cryptography_requirement_and_provider_field() -> None:
    requirements = parse_requirements(".")
    dependency = inspect_dependency_and_pqc_provider(".")

    assert requirements["cryptography_requirement"]
    assert dependency["provider_status"] in {"PQC_PROVIDER_AVAILABLE", "PQC_PROVIDER_UNAVAILABLE", "PQC_PROVIDER_UNKNOWN"}
    assert dependency["certification_claimed"] is False
    assert dependency["post_quantum_compliance_claimed"] is False


def test_deterministic_query_assistant_known_and_unknown_queries() -> None:
    known = answer_query("what_is_oda", ".")
    unknown = answer_query("invent_architecture", ".")

    assert known["status"] == ODAStatus.HARNESS_OK
    assert "local Onsite Deployment Assistant" in known["answer"]
    assert unknown["status"] == ODAStatus.HARNESS_WARNING
    assert unknown["answer"] == "unsupported by deterministic ODA query map"


def test_query_assistant_reports_pqc_provider_without_certification_claim() -> None:
    result = answer_query("pqc_provider_status", ".")

    assert result["dependency_status"]["provider_status"].startswith("PQC_PROVIDER_")
    assert result["dependency_status"]["certification_claimed"] is False


def test_maintenance_work_package_never_auto_applies() -> None:
    drift = plan_maintenance_work_package("validation_dossier_drift", ".")
    runtime = plan_maintenance_work_package("sbp_lex_runtime_authority_change", ".")

    assert drift["auto_apply_allowed"] is False
    assert drift["execution_authority"] == "NONE"
    assert drift["owner_approval_required"] is True
    assert runtime["canonical_boundary_risk"] is True
    assert runtime["owner_approval_required"] is True
    assert runtime["status"] == ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY


def test_boundary_checker_confirms_runtime_detachment() -> None:
    result = run_boundary_check(".")

    assert result["status"] == ODAStatus.HARNESS_OK
    assert result["findings"] == []


def test_oda_statuses_never_use_runtime_decision_terms() -> None:
    assert {status.value for status in ODAStatus}.isdisjoint(FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS)


def test_cli_support_bundle_writes_digest_verified_json(tmp_path) -> None:
    out = tmp_path / "support_bundle.json"
    completed = subprocess.run(
        [sys.executable, "-m", "sbp_oda.cli", "--support-bundle", "--runtime-root", ".", "--out", str(out)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["bundle_type"] == "ODA_LOCAL_SUPPORT_BUNDLE"
    assert verify_support_bundle_digest(payload) is True


def test_cli_query_and_boundary_are_json() -> None:
    query = subprocess.run(
        [sys.executable, "-m", "sbp_oda.cli", "--query", "what_is_oda", "--runtime-root", "."],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    boundary = subprocess.run(
        [sys.executable, "-m", "sbp_oda.cli", "--boundary-check", "--runtime-root", "."],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert json.loads(query.stdout)["status"] == ODAStatus.HARNESS_OK
    assert json.loads(boundary.stdout)["status"] == ODAStatus.HARNESS_OK
