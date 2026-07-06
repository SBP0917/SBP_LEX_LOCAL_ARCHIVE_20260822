from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import hashlib
import json

from sbp_oda.boundary_checker import run_boundary_check
from sbp_oda.capability_index import FUTURE_CAPABILITY_REGISTER, ODA_CAPABILITY_INDEX
from sbp_oda.dependencies import inspect_dependency_and_pqc_provider
from sbp_oda.health.local_deployment_scanner import scan_local_deployment
from sbp_oda.maintenance.work_package_planner import FINDING_RULES
from sbp_oda.profile.deployment_profile import DeploymentProfile
from sbp_oda.query_assistant import deterministic_query_index
from sbp_oda.repo_control.branch_status import capture_branch_status
from sbp_oda.repo_control.commit_evidence import capture_commit_evidence


@dataclass(frozen=True)
class SupportBundleManifest:
    bundle_type: str
    deployment_id: str
    created_at: str
    bundle_version: str = "ODA_02"
    included_sections: list[str] = field(default_factory=list)
    repo_status: dict[str, object] = field(default_factory=dict)
    config_status: dict[str, object] = field(default_factory=dict)
    remote_support_status: dict[str, object] = field(default_factory=dict)
    repository_status: dict[str, object] = field(default_factory=dict)
    dependency_status: dict[str, object] = field(default_factory=dict)
    pqc_provider_status: dict[str, object] = field(default_factory=dict)
    pvpl_presence_status: dict[str, object] = field(default_factory=dict)
    local_trust_presence_status: dict[str, object] = field(default_factory=dict)
    validation_dossier_status: dict[str, object] = field(default_factory=dict)
    safe_reviewer_commands: list[str] = field(default_factory=list)
    blocked_capabilities: dict[str, object] = field(default_factory=dict)
    owner_approval_policy: dict[str, object] = field(default_factory=dict)
    maintenance_policy_summary: dict[str, object] = field(default_factory=dict)
    boundary_status: dict[str, object] = field(default_factory=dict)
    deterministic_query_index: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    support_bundle_digest: str = ""


EXPECTED_CONFIG_FILES = ("requirements.txt",)


def collect_repo_status(profile: DeploymentProfile) -> dict[str, object]:
    root = profile.runtime_root
    branch = capture_branch_status(root)
    commit = capture_commit_evidence(root)
    return {
        "runtime_root": str(root),
        "root_exists": root.exists(),
        "main_py_exists": (root / "main.py").exists(),
        "branch": branch.get("branch"),
        "commit": commit.get("commit_hash"),
        "dirty_state": branch.get("dirty"),
        "branch_captured": branch.get("captured"),
        "commit_captured": commit.get("captured"),
        "branch_error": branch.get("error"),
        "commit_error": commit.get("error"),
    }


def collect_config_status(profile: DeploymentProfile) -> dict[str, object]:
    root = profile.runtime_root
    present = [path for path in EXPECTED_CONFIG_FILES if (root / path).exists()]
    missing = [path for path in EXPECTED_CONFIG_FILES if path not in present]
    return {
        "expected_config_files": list(EXPECTED_CONFIG_FILES),
        "present_config_files": present,
        "missing_config_files": missing,
    }


def collect_remote_support_status() -> dict[str, object]:
    return {
        "outbound_only_required": True,
        "remote_shell_allowed": False,
        "live_remote_support_channel": False,
        "signed_package_installation_active": False,
        "automatic_repair_active": False,
        "runtime_authority": "NONE",
        "support_mode": "OUTBOUND_ONLY_LOCAL_METADATA",
        "status": "local_support_record_only",
    }


def _canonical_digest(payload: dict[str, object]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "support_bundle_digest"}
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_support_bundle_digest(payload: dict[str, object]) -> bool:
    return payload.get("support_bundle_digest") == _canonical_digest(payload)


def collect_pvpl_presence(profile: DeploymentProfile) -> dict[str, object]:
    root = profile.runtime_root
    return {
        "package_exists": (root / "sbp_pvpl").is_dir(),
        "tests_exist": (root / "tests/pvpl").is_dir(),
        "report_exists": (root / "reports/PVPL_V1_SKELETON_IMPLEMENTATION_REPORT.md").exists(),
        "runtime_attached_claimed": False,
    }


def collect_local_trust_presence(profile: DeploymentProfile) -> dict[str, object]:
    root = profile.runtime_root
    return {
        "local_trust_package_exists": (root / "sbp_lex/local_trust").is_dir(),
        "validation_dossier_outputs_exist": (root / "outputs/university_validation_dossier").is_dir(),
        "release_integrity_doc_exists": (root / "docs/RELEASE_INTEGRITY_PACKAGE.md").exists(),
    }


def collect_validation_dossier_status(profile: DeploymentProfile) -> dict[str, object]:
    manifest = profile.runtime_root / "outputs/university_validation_dossier/DOSSIER_MANIFEST.json"
    if not manifest.exists():
        return {"exists": False, "status": "NOT_PRESENT"}
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"exists": True, "status": "INVALID_JSON", "error": str(exc)}
    return {
        "exists": True,
        "status": data.get("dossier_status", "UNKNOWN"),
        "reviewer_command_count": data.get("dossier_summary", {}).get("reviewer_command_count"),
        "validation_failures": data.get("validation_failures", []),
        "note": "ODA reports recorded dossier status only; it does not rebuild or validate the dossier.",
    }


def safe_reviewer_commands() -> list[str]:
    return [
        "python -m compileall -q .",
        "python -m pytest -q tests/oda --basetemp runtime_artifacts/pytest_tmp_oda02",
        "python -m pytest -q tests/test_pqc_01_provider_contract.py --basetemp runtime_artifacts/pytest_tmp_oda02_pqc",
        "python -m pytest -q tests/pvpl --basetemp runtime_artifacts/pytest_tmp_oda02_pvpl",
        "python main.py",
        "python main.py replay",
        "python -m sbp_oda.cli --boundary-check --runtime-root .",
    ]


def owner_approval_policy() -> dict[str, object]:
    return {
        "sensitive_actions_require_owner_approval": True,
        "canonical_runtime_actions_blocked_even_with_owner_approval": True,
        "approval_grants_execution_authority": False,
        "execution_authority": "NONE",
    }


def maintenance_policy_summary() -> dict[str, object]:
    return {
        "supported_findings": sorted(FINDING_RULES),
        "auto_apply_allowed": False,
        "signed_package_receipt_implemented": False,
        "remote_shell_allowed": False,
        "execution_authority": "NONE",
    }


def build_support_bundle_manifest(profile: DeploymentProfile) -> SupportBundleManifest:
    repository_status = scan_local_deployment(profile.runtime_root)
    dependency_status = inspect_dependency_and_pqc_provider(profile.runtime_root)
    boundary_status = run_boundary_check(profile.runtime_root)
    payload = SupportBundleManifest(
        bundle_type="ODA_LOCAL_SUPPORT_BUNDLE",
        deployment_id=profile.deployment_id,
        created_at=datetime.now(UTC).isoformat(),
        included_sections=[
            "repository_status",
            "dependency_status",
            "pqc_provider_status",
            "pvpl_presence_status",
            "local_trust_presence_status",
            "validation_dossier_status",
            "safe_reviewer_commands",
            "blocked_capabilities",
            "owner_approval_policy",
            "maintenance_policy_summary",
            "boundary_status",
            "deterministic_query_index",
            "remote_support_status",
        ],
        repo_status=collect_repo_status(profile),
        config_status=collect_config_status(profile),
        remote_support_status=collect_remote_support_status(),
        repository_status=repository_status,
        dependency_status=dependency_status,
        pqc_provider_status={
            "provider_status": dependency_status["provider_status"],
            "cryptography_installed_version": dependency_status["cryptography_installed_version"],
            "mldsa_import_available": dependency_status["mldsa_import_available"],
            "certification_claimed": False,
        },
        pvpl_presence_status=collect_pvpl_presence(profile),
        local_trust_presence_status=collect_local_trust_presence(profile),
        validation_dossier_status=collect_validation_dossier_status(profile),
        safe_reviewer_commands=safe_reviewer_commands(),
        blocked_capabilities={name: item for name, item in FUTURE_CAPABILITY_REGISTER.items()},
        owner_approval_policy=owner_approval_policy(),
        maintenance_policy_summary=maintenance_policy_summary(),
        boundary_status=boundary_status,
        deterministic_query_index=deterministic_query_index(),
        notes=[
            "Support bundle is diagnostic evidence only.",
            "Support bundle does not grant runtime authority.",
            "Support bundle does not activate remote live support, automatic repair, signed package installation, or production deployment.",
            f"Active capability count: {len(ODA_CAPABILITY_INDEX)}.",
        ],
    )
    payload_dict = asdict(payload)
    payload_dict["support_bundle_digest"] = _canonical_digest(payload_dict)
    return SupportBundleManifest(**payload_dict)


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
