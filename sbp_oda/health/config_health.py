from __future__ import annotations

from pathlib import Path

from sbp_oda.diagnostics.diagnostic_result import DiagnosticFinding
from sbp_oda.profile.deployment_profile import DeploymentProfile


EXPECTED_CONFIG_FILES = (
    "sbp_lex/config/security_config.py",
    "sbp_lex/config/pipeline_config.py",
    "sbp_lex/config/thresholds.py",
)


def check_config_files(profile: DeploymentProfile) -> list[DiagnosticFinding]:
    root = Path(profile.runtime_root)
    findings: list[DiagnosticFinding] = []

    for relative_path in EXPECTED_CONFIG_FILES:
        if not (root / relative_path).exists():
            findings.append(
                DiagnosticFinding(
                    finding_id=f"missing_config::{relative_path}",
                    category="CONFIG",
                    severity="HIGH",
                    message=f"Expected config file missing: {relative_path}",
                    recommended_action="Generate diagnostic support bundle and compare against deployment baseline.",
                    owner_approval_required=True,
                )
            )

    return findings
