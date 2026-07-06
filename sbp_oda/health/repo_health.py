from __future__ import annotations

from pathlib import Path

from sbp_oda.diagnostics.diagnostic_result import DiagnosticFinding
from sbp_oda.profile.deployment_profile import DeploymentProfile


def check_repo_root(profile: DeploymentProfile) -> list[DiagnosticFinding]:
    root = Path(profile.runtime_root)

    if not root.exists():
        return [
            DiagnosticFinding(
                finding_id="repo_root_missing",
                category="REPOSITORY",
                severity="CRITICAL",
                message=f"Runtime root does not exist: {root}",
                recommended_action="Verify licensed deployment installation path.",
            )
        ]

    if not (root / "main.py").exists():
        return [
            DiagnosticFinding(
                finding_id="main_py_missing",
                category="REPOSITORY",
                severity="HIGH",
                message="main.py was not found at runtime root.",
                recommended_action="Run repository inventory and support bundle generation.",
                owner_approval_required=True,
            )
        ]

    return []
