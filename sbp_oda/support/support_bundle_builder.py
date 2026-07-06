from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import json

from sbp_oda.profile.deployment_profile import DeploymentProfile


@dataclass(frozen=True)
class SupportBundleManifest:
    bundle_type: str
    deployment_id: str
    created_at: str
    included_sections: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def build_support_bundle_manifest(profile: DeploymentProfile) -> SupportBundleManifest:
    return SupportBundleManifest(
        bundle_type="ODA_SUPPORT_BUNDLE",
        deployment_id=profile.deployment_id,
        created_at=datetime.now(UTC).isoformat(),
        included_sections=[
            "deployment_profile",
            "health_summary",
            "diagnostic_findings",
            "repo_status_placeholder",
            "config_status_placeholder",
            "remote_support_status_placeholder",
        ],
        notes=[
            "Support bundle is diagnostic evidence only.",
            "Support bundle does not grant runtime authority.",
        ],
    )


def write_support_bundle_manifest(
    profile: DeploymentProfile,
    output_path: str | Path,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_support_bundle_manifest(profile)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(asdict(manifest), handle, indent=2, sort_keys=True)
    return path
