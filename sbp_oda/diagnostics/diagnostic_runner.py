from __future__ import annotations

from sbp_oda.diagnostics.diagnostic_result import DiagnosticFinding, DiagnosticResult
from sbp_oda.profile.deployment_profile import DeploymentProfile
from sbp_oda.status import ODAStatus


def run_basic_diagnostics(profile: DeploymentProfile) -> DiagnosticResult:
    findings: list[DiagnosticFinding] = []
    if not profile.runtime_root.exists():
        findings.append(
            DiagnosticFinding(
                finding_id="runtime_root_missing",
                category="DEPLOYMENT",
                severity="CRITICAL",
                message="Runtime root is missing.",
                recommended_action="Verify licensed deployment path before further support work.",
            )
        )
    return DiagnosticResult(
        status=ODAStatus.HARNESS_OK if not findings else ODAStatus.HARNESS_WARNING,
        deployment_id=profile.deployment_id,
        findings=findings,
    )
