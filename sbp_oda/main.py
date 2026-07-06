from __future__ import annotations

from sbp_oda.boundary_checker import run_boundary_check
from sbp_oda.dependencies import inspect_dependency_and_pqc_provider
from sbp_oda.health.config_health import check_config_files
from sbp_oda.health.health_runner import HealthRunner
from sbp_oda.health.local_deployment_scanner import scan_local_deployment
from sbp_oda.health.repo_health import check_repo_root
from sbp_oda.maintenance.work_package_planner import plan_maintenance_work_package
from sbp_oda.profile.deployment_profile import build_default_deployment_profile
from sbp_oda.query_assistant import answer_query
from sbp_oda.support.support_bundle_builder import write_support_bundle_manifest


def run_oda_health_check(runtime_root: str = ".") -> dict[str, object]:
    profile = build_default_deployment_profile(runtime_root)
    runner = HealthRunner(profile=profile)
    runner.register_check(check_repo_root)
    runner.register_check(check_config_files)
    result = runner.run()
    return {
        "status": result.status.value,
        "deployment_id": result.deployment_id,
        "finding_count": len(result.findings),
        "findings": [
            {
                "finding_id": finding.finding_id,
                "category": finding.category,
                "severity": finding.severity,
                "message": finding.message,
                "recommended_action": finding.recommended_action,
                "owner_approval_required": finding.owner_approval_required,
            }
            for finding in result.findings
        ],
        "runtime_authority": "NONE",
    }


def run_oda_diagnostics(runtime_root: str = ".") -> dict[str, object]:
    deployment = scan_local_deployment(runtime_root)
    dependency = inspect_dependency_and_pqc_provider(runtime_root)
    boundary = run_boundary_check(runtime_root)
    return {
        "status": boundary["status"] if boundary["finding_count"] else deployment["status"],
        "deployment_status": deployment,
        "dependency_status": dependency,
        "boundary_status": boundary,
        "runtime_authority": "NONE",
    }


def run_oda_query(query_id: str, runtime_root: str = ".") -> dict[str, object]:
    return answer_query(query_id, runtime_root)


def run_oda_boundary_check(runtime_root: str = ".") -> dict[str, object]:
    return run_boundary_check(runtime_root)


def run_oda_maintenance_plan(finding: str, runtime_root: str = ".") -> dict[str, object]:
    return plan_maintenance_work_package(finding, runtime_root)


def run_oda_support_bundle(runtime_root: str = ".", output_path: str = "runtime_artifacts/oda_02/support_bundle.json") -> dict[str, object]:
    profile = build_default_deployment_profile(runtime_root)
    path = write_support_bundle_manifest(profile, output_path)
    return {"status": "HARNESS_OK", "support_bundle_path": str(path), "runtime_authority": "NONE"}


if __name__ == "__main__":
    print(run_oda_health_check("."))
