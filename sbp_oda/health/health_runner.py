from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from sbp_oda.diagnostics.diagnostic_result import DiagnosticFinding, DiagnosticResult
from sbp_oda.profile.deployment_profile import DeploymentProfile
from sbp_oda.status import ODAStatus


HealthCheck = Callable[[DeploymentProfile], list[DiagnosticFinding]]


@dataclass
class HealthRunner:
    profile: DeploymentProfile
    checks: list[HealthCheck] = field(default_factory=list)

    def register_check(self, check: HealthCheck) -> None:
        self.checks.append(check)

    def run(self) -> DiagnosticResult:
        findings: list[DiagnosticFinding] = []

        for check in self.checks:
            result = check(self.profile)
            if isinstance(result, list):
                findings.extend(result)

        status = ODAStatus.HARNESS_OK if not findings else ODAStatus.HARNESS_WARNING
        return DiagnosticResult(
            status=status,
            deployment_id=self.profile.deployment_id,
            findings=findings,
        )
