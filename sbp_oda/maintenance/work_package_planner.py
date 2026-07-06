from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from sbp_oda.status import ODAStatus


@dataclass(frozen=True)
class MaintenanceWorkPackage:
    finding: str
    severity: str
    recommended_action: str
    owner_approval_required: bool
    canonical_boundary_risk: bool
    auto_apply_allowed: bool
    execution_authority: str
    status: str


FINDING_RULES: dict[str, tuple[str, str, bool, bool]] = {
    "missing_dependency": ("HIGH", "Prepare dependency installation evidence and ask owner to approve dependency update.", True, False),
    "dirty_repo": ("MEDIUM", "Record dirty files, separate intended work from unrelated changes, and request owner review before handover.", False, False),
    "missing_report": ("MEDIUM", "Prepare a report creation work package; do not fabricate report results.", False, False),
    "validation_dossier_drift": ("HIGH", "Regenerate or rebuild dossier evidence in a controlled documentation/evidence pass.", True, False),
    "pqc_provider_unavailable": ("HIGH", "Install or verify the tested cryptography provider dependency in an owner-approved environment.", True, False),
    "pvpl_missing": ("MEDIUM", "Plan PVPL scaffold restoration or implementation in a separate PVPL phase.", False, False),
    "runtime_artifact_drift": ("HIGH", "Quarantine or review runtime artifacts through SBP-LEX evidence procedures; ODA must not mutate runtime evidence.", True, True),
    "sbp_lex_runtime_authority_change": ("CRITICAL", "Block the request and require separate canonical runtime-authority review.", True, True),
}


def plan_maintenance_work_package(finding: str, runtime_root: str | Path = ".") -> dict[str, object]:
    key = finding.strip().lower()
    severity, action, approval, canonical = FINDING_RULES.get(
        key,
        ("MEDIUM", "Unsupported finding. Prepare an owner-reviewed diagnostic note only.", True, False),
    )
    if key.startswith("sbp_lex") or "runtime_authority" in key or "execution_gate" in key:
        canonical = True
        approval = True
        severity = "CRITICAL"
        action = "Block the request and require separate canonical runtime-authority review."
    status = ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY if canonical else ODAStatus.HARNESS_REPAIR_RECOMMENDED
    package = MaintenanceWorkPackage(
        finding=key,
        severity=severity,
        recommended_action=action,
        owner_approval_required=approval,
        canonical_boundary_risk=canonical,
        auto_apply_allowed=False,
        execution_authority="NONE",
        status=status.value,
    )
    return asdict(package)
