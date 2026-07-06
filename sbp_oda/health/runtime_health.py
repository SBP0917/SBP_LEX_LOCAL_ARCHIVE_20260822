from __future__ import annotations

from sbp_oda.diagnostics.diagnostic_result import DiagnosticFinding
from sbp_oda.profile.deployment_profile import DeploymentProfile


def check_runtime_entrypoint(profile: DeploymentProfile) -> list[DiagnosticFinding]:
    return [] if (profile.runtime_root / "main.py").exists() else [
        DiagnosticFinding("runtime_entrypoint_missing", "RUNTIME", "HIGH", "Runtime entrypoint missing.", "Escalate to support.")
    ]
