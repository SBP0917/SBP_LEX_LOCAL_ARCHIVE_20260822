import json

from sbp_oda.profile.deployment_profile import build_default_deployment_profile
from sbp_oda.support.support_bundle_builder import (
    build_support_bundle_manifest,
    verify_support_bundle_digest,
    write_support_bundle_manifest,
)


def test_support_bundle_is_diagnostic_evidence_only(tmp_path) -> None:
    profile = build_default_deployment_profile(".")
    manifest = build_support_bundle_manifest(profile)

    assert manifest.bundle_type == "ODA_LOCAL_SUPPORT_BUNDLE"
    assert any("does not grant runtime authority" in note for note in manifest.notes)
    assert "repository_status" in manifest.included_sections
    assert "dependency_status" in manifest.included_sections
    assert "pqc_provider_status" in manifest.included_sections
    assert "blocked_capabilities" in manifest.included_sections
    assert "remote_support_status" in manifest.included_sections
    assert all("placeholder" not in section for section in manifest.included_sections)
    assert manifest.repository_status["repository_root"]
    assert "current_branch" in manifest.repository_status
    assert "current_commit_hash" in manifest.repository_status
    assert "dirty_tree" in manifest.repository_status
    assert "python_executable" in manifest.repository_status
    assert manifest.repo_status["runtime_root"]
    assert "root_exists" in manifest.repo_status
    assert "main_py_exists" in manifest.repo_status
    assert "branch" in manifest.repo_status
    assert "commit" in manifest.repo_status
    assert "dirty_state" in manifest.repo_status
    assert manifest.config_status["expected_config_files"]
    assert "present_config_files" in manifest.config_status
    assert "missing_config_files" in manifest.config_status
    assert manifest.remote_support_status == {
        "outbound_only_required": True,
        "automatic_repair_active": False,
        "live_remote_support_channel": False,
        "remote_shell_allowed": False,
        "runtime_authority": "NONE",
        "signed_package_installation_active": False,
        "support_mode": "OUTBOUND_ONLY_SUPPORT",
        "status": "local_support_record_only",
    } | {"support_mode": "OUTBOUND_ONLY_LOCAL_METADATA"}
    assert manifest.support_bundle_digest
    assert manifest.owner_approval_policy["approval_grants_execution_authority"] is False
    assert manifest.maintenance_policy_summary["auto_apply_allowed"] is False

    path = write_support_bundle_manifest(profile, tmp_path / "support_bundle.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["bundle_type"] == "ODA_LOCAL_SUPPORT_BUNDLE"
    assert "repository_status" in payload
    assert "dependency_status" in payload
    assert "pqc_provider_status" in payload
    assert "blocked_capabilities" in payload
    assert all("placeholder" not in section for section in payload["included_sections"])
    assert verify_support_bundle_digest(payload) is True
    payload["repository_status"]["repository_root_exists"] = not payload["repository_status"]["repository_root_exists"]
    assert verify_support_bundle_digest(payload) is False
