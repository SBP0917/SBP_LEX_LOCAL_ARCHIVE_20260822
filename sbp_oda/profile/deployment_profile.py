from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DeploymentProfile:
    deployment_id: str
    runtime_root: Path
    deployment_class: str = "LOCAL_LICENSED_PREMISES"
    support_mode: str = "OUTBOUND_ONLY"
    runtime_authority: str = "NONE"


def build_default_deployment_profile(runtime_root: str | Path = ".") -> DeploymentProfile:
    root = Path(runtime_root).resolve()
    return DeploymentProfile(
        deployment_id=f"ODA-{root.name or 'ROOT'}",
        runtime_root=root,
    )
