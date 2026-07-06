from __future__ import annotations

from sbp_oda.health.config_health import check_config_files
from sbp_oda.health.health_runner import HealthRunner
from sbp_oda.health.repo_health import check_repo_root
from sbp_oda.profile.deployment_profile import build_default_deployment_profile


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


if __name__ == "__main__":
    print(run_oda_health_check("."))
