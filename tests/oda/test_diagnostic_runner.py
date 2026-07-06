from pathlib import Path

from sbp_oda.diagnostics.diagnostic_runner import run_basic_diagnostics
from sbp_oda.diagnostics.severity_mapper import normalise_severity
from sbp_oda.profile.deployment_profile import build_default_deployment_profile
from sbp_oda.status import ODAStatus


def test_basic_diagnostics_warn_for_missing_root(tmp_path: Path) -> None:
    result = run_basic_diagnostics(build_default_deployment_profile(tmp_path / "missing"))

    assert result.status == ODAStatus.HARNESS_WARNING
    assert result.has_findings


def test_severity_mapper_defaults_unknown_to_info() -> None:
    assert normalise_severity("unknown") == "INFO"
    assert normalise_severity("critical") == "CRITICAL"
