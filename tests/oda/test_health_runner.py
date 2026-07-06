from pathlib import Path

from sbp_oda.health.config_health import check_config_files
from sbp_oda.health.health_runner import HealthRunner
from sbp_oda.health.repo_health import check_repo_root
from sbp_oda.profile.deployment_profile import build_default_deployment_profile
from sbp_oda.status import ODAStatus


def test_health_runner_passes_for_repo_root() -> None:
    profile = build_default_deployment_profile(".")
    runner = HealthRunner(profile)
    runner.register_check(check_repo_root)
    runner.register_check(check_config_files)

    result = runner.run()

    assert result.status == ODAStatus.HARNESS_OK
    assert result.deployment_id


def test_health_runner_warns_for_missing_root(tmp_path: Path) -> None:
    profile = build_default_deployment_profile(tmp_path / "missing")
    runner = HealthRunner(profile)
    runner.register_check(check_repo_root)

    result = runner.run()

    assert result.status == ODAStatus.HARNESS_WARNING
    assert result.has_findings is True
