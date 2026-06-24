from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.file_digest import collect_file_hashes
from sbp_lex.local_trust.manifest import (
    build_local_trust_manifest,
    hash_manifest_payload,
    load_local_trust_manifest,
    manifest_digest_for,
    manifest_signature_for,
    write_local_trust_manifest,
)
from sbp_lex.local_trust.manifest_validator import (
    LOCAL_TRUST_DIRTY,
    LOCAL_TRUST_INCOMPLETE,
    LOCAL_TRUST_INVALID,
    LOCAL_TRUST_STALE,
    LOCAL_TRUST_VALID,
    validate_local_trust_manifest,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"


def test_builds_manifest_successfully() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)

    assert manifest["manifest_type"] == "local_trust_root_manifest"
    assert manifest["manifest_version"] == "18.7B"
    assert manifest["local_trust_status"] == LOCAL_TRUST_VALID


def test_manifest_includes_repository_root_provenance() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)

    assert manifest["repository_root"] == str(REPOSITORY_ROOT)
    assert manifest["repository_root_digest_scope"] == "relative_paths_only"


def test_manifest_includes_git_commit_and_branch_fields() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)

    assert manifest["git_branch"] == "main"
    assert isinstance(manifest["git_commit"], str)
    assert len(manifest["git_commit"]) == 40


def test_manifest_records_working_tree_status() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)

    assert "git_status_short" in manifest
    assert isinstance(manifest["working_tree_clean"], bool)


def test_manifest_records_python_executable_and_version() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)

    assert manifest["python_executable"]
    assert manifest["python_version"].startswith(str(sys.version_info.major))


def test_manifest_hashes_critical_files() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    records = {record["path"]: record for record in manifest["critical_file_hashes"]}

    assert records["main.py"]["status"] == "PRESENT"
    assert records["main.py"]["sha256"]
    assert records["sbp_lex/execution/execution_gate.py"]["status"] == "PRESENT"


def test_missing_critical_files_are_recorded_deterministically(tmp_path: Path) -> None:
    records = collect_file_hashes(tmp_path, ["missing.py"])

    assert records == [
        {
            "path": "missing.py",
            "status": "MISSING",
            "sha256": None,
            "size_bytes": None,
        }
    ]


def test_manifest_hashes_trusted_reports_when_present() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    records = {record["path"]: record for record in manifest["trusted_report_hashes"]}

    assert records["reports/PHASE_RED_20D_ATTACK_REPORT.md"]["status"] == "PRESENT"
    assert records["reports/PHASE_RED_20D_ATTACK_REPORT.md"]["sha256"]


def test_missing_outputs_are_recorded_deterministically() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    records = {record["path"]: record for record in manifest["trusted_output_hashes"]}

    assert records["outputs/SBP_OPERATOR_ASSISTANT_V1_COMMIT_AND_TEST_REPORT.md"]["status"] == "MISSING"


def test_manifest_digest_validates() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    validation = validate_local_trust_manifest(manifest)

    assert validation == {"local_trust_status": LOCAL_TRUST_VALID, "validation_failures": []}
    assert manifest["manifest_payload_digest"] == hash_manifest_payload(manifest)
    assert manifest["manifest_signature"] == manifest_signature_for(manifest["manifest_payload_digest"])
    assert manifest["manifest_digest"] == manifest_digest_for(
        manifest["manifest_payload_digest"],
        manifest["manifest_signature"],
    )


def test_manifest_tampering_is_detected() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    manifest["phase_baseline"].append("tampered")

    validation = validate_local_trust_manifest(manifest)

    assert validation["local_trust_status"] == LOCAL_TRUST_INVALID
    assert "manifest_payload_digest_mismatch" in validation["validation_failures"]


def test_dirty_working_tree_can_produce_dirty_status_when_required() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    manifest["working_tree_clean"] = False
    payload_digest = hash_manifest_payload(manifest)
    manifest["manifest_payload_digest"] = payload_digest
    manifest["manifest_signature"] = manifest_signature_for(payload_digest)
    manifest["manifest_digest"] = manifest_digest_for(payload_digest, manifest["manifest_signature"])

    validation = validate_local_trust_manifest(manifest, clean_required=True)

    assert validation == {"local_trust_status": LOCAL_TRUST_DIRTY, "validation_failures": ["working_tree_dirty"]}


def test_stale_commit_can_produce_stale_status() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    manifest["git_commit"] = "0" * 40
    payload_digest = hash_manifest_payload(manifest)
    manifest["manifest_payload_digest"] = payload_digest
    manifest["manifest_signature"] = manifest_signature_for(payload_digest)
    manifest["manifest_digest"] = manifest_digest_for(payload_digest, manifest["manifest_signature"])

    validation = validate_local_trust_manifest(
        manifest,
        repository_root=REPOSITORY_ROOT,
        current_validation=True,
    )

    assert validation == {"local_trust_status": LOCAL_TRUST_STALE, "validation_failures": ["git_commit_stale"]}


def test_malformed_manifest_produces_invalid_status() -> None:
    validation = validate_local_trust_manifest([])

    assert validation == {"local_trust_status": LOCAL_TRUST_INVALID, "validation_failures": ["manifest_not_mapping"]}


def test_missing_required_sections_produce_incomplete_status() -> None:
    validation = validate_local_trust_manifest({"manifest_type": "local_trust_root_manifest"})

    assert validation["local_trust_status"] == LOCAL_TRUST_INCOMPLETE
    assert any(item.startswith("missing_required_section:") for item in validation["validation_failures"])


def test_forbidden_authority_output_fields_are_flagged() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    manifest["unsafe"] = {"decision": "ALLOW"}
    payload_digest = hash_manifest_payload(manifest)
    manifest["manifest_payload_digest"] = payload_digest
    manifest["manifest_signature"] = manifest_signature_for(payload_digest)
    manifest["manifest_digest"] = manifest_digest_for(payload_digest, manifest["manifest_signature"])

    validation = validate_local_trust_manifest(manifest)

    assert validation["local_trust_status"] == LOCAL_TRUST_INVALID
    assert "forbidden_authority_value:$.unsafe.decision" in validation["validation_failures"]


def test_cli_build_creates_output_manifest(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_root_manifest.json"
    result = _run_cli("build", "--path", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "LOCAL_TRUST_VALID" in result.stdout


def test_cli_validate_validates_output_manifest(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_root_manifest.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("validate", "--path", str(output))

    assert result.returncode == 0
    assert result.stdout.strip() == "LOCAL_TRUST_VALID"


def test_cli_show_prints_local_trust_status(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_root_manifest.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("show", "--path", str(output))

    assert result.returncode == 0
    assert "LOCAL_TRUST_VALID" in result.stdout
    assert "branch=main" in result.stdout


def test_load_and_write_local_trust_manifest_round_trip(tmp_path: Path) -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    output = write_local_trust_manifest(manifest, tmp_path / "manifest.json", repository_root=REPOSITORY_ROOT)

    assert load_local_trust_manifest(output, repository_root=REPOSITORY_ROOT)["manifest_digest"] == manifest["manifest_digest"]


def test_no_runtime_activation_occurs() -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)

    assert all(command["executed_by_manifest"] is False for command in manifest["command_provenance"]["commands"])


def test_no_python_main_call_occurs_inside_local_trust_package() -> None:
    source = _local_trust_source()

    assert "subprocess.run([\"python\", \"main.py\"]" not in source
    assert "subprocess.run(['python', 'main.py']" not in source


def test_no_replay_call_occurs_inside_local_trust_package() -> None:
    source = _local_trust_source()

    assert "subprocess.run([\"python\", \"main.py\", \"replay\"]" not in source
    assert "subprocess.run(['python', 'main.py', 'replay']" not in source


def test_no_pytest_execution_occurs_inside_local_trust_package() -> None:
    source = _local_trust_source()

    assert "-m pytest" in source
    assert "subprocess.run([\"python\", \"-m\", \"pytest\"]" not in source
    assert "subprocess.run(['python', '-m', 'pytest']" not in source


def test_no_prohibited_topology_terms_added_to_implementation() -> None:
    source = _local_trust_source()

    for term in [
        "node_quorum",
        "node_attestation",
        "distributed_consensus",
        "mesh_runtime",
        "cloud_runtime",
        "runtime_activation",
        "external_execution_permission",
    ]:
        assert term not in source


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.manifest", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _local_trust_source() -> str:
    parts = []
    for path in LOCAL_TRUST_ROOT.glob("*.py"):
        parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)
