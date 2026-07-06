from __future__ import annotations

from dataclasses import dataclass, field

from sbp_oda.status import ODAStatus


@dataclass(frozen=True)
class DiagnosticFinding:
    finding_id: str
    category: str
    severity: str
    message: str
    recommended_action: str
    owner_approval_required: bool = False


@dataclass(frozen=True)
class DiagnosticResult:
    status: ODAStatus
    deployment_id: str
    findings: list[DiagnosticFinding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)
