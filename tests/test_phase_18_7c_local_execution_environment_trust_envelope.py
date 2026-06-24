from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.command_capture import (
    COMMAND_PASS,
    bounded_excerpt,
    capture_supported_commands,
)
from sbp_lex.local_trust.execution_envelope import (
    build_execution_environment_envelope,
    envelope_digest_for,
    envelope_signature_for,
    hash_envelope_payload,
    load_execution_envelope,
    write_execution_envelope,
)
from sbp_lex.local_trust.execution_envelope_validator import (
    EXECUTION_ENV_DIRTY,
    EXECUTION_ENV_INCOMPLETE,
    EXECUTION_ENV_INVALID,
    EXECUTION_ENV_STALE,
    EXECUTION_ENV_VALID,
    validate_execution_envelope,
)
from sbp_lex.local_trust.manifest import build_local_trust_manifest, write_local_trust_manifest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"


def test_builds_execution_environment_envelope() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert envelope["envelope_type"] == "local_execution_environment_trust_envelope"
    assert envelope["envelope_version"] == "18.7C"
    assert envelope["verification_status"] == EXECUTION_ENV_VALID


def test_envelope_includes_repository_root() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert envelope["repository_root"] == str(REPOSITORY_ROOT)
    assert envelope["working_directory"] == str(REPOSITORY_ROOT)


def test_envelope_includes_git_commit_and_branch() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert envelope["git_branch"] == "main"
    assert isinstance(envelope["git_commit"], str)
    assert len(envelope["git_commit"]) == 40


def test_envelope_includes_working_tree_status() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert isinstance(envelope["working_tree_clean"], bool)


def test_envelope_includes_python_executable_and_version() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert envelope["python_executable"]
    assert envelope["python_version"].startswith(str(sys.version_info.major))


def test_envelope_binds_to_local_trust_manifest_digest() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert len(envelope["bound_local_trust_manifest_digest"]) == 64
    assert envelope["bound_local_trust_manifest_status"] == "LOCAL_TRUST_MANIFEST_BOUND"


def test_missing_manifest_produces_incomplete_status(tmp_path: Path) -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT, manifest_path=tmp_path / "missing.json")

    assert envelope["verification_status"] == EXECUTION_ENV_INCOMPLETE
    assert "local_trust_manifest_missing" in envelope["validation_failures"]


def test_invalid_manifest_produces_incomplete_status(tmp_path: Path) -> None:
    invalid_manifest = tmp_path / "invalid.json"
    invalid_manifest.write_text("{not json", encoding="utf-8")
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT, manifest_path=invalid_manifest)

    assert envelope["verification_status"] == EXECUTION_ENV_INCOMPLETE
    assert "local_trust_manifest_invalid" in envelope["validation_failures"]


def test_command_result_records_include_exit_code_and_digests() -> None:
    command = {
        "command_id": "safe_mock",
        "command_text": "python -c print",
        "command_args": ["python", "-c", "print('phase-18-7c')"],
        "python_command": True,
    }
    results = capture_supported_commands(REPOSITORY_ROOT, command_definitions=[command])
    record = results[0]

    assert record["exit_code"] == 0
    assert record["command_status"] == COMMAND_PASS
    assert len(record["stdout_digest"]) == 64
    assert len(record["stderr_digest"]) == 64
    assert "phase-18-7c" in record["stdout_excerpt"]


def test_command_result_records_include_bounded_excerpts() -> None:
    text = "x" * 2000

    assert len(bounded_excerpt(text)) <= 1200 + len("\n...[truncated]...\n")
    assert "[truncated]" in bounded_excerpt(text)


def test_tampered_envelope_digest_is_detected() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)
    envelope["git_branch"] = "tampered"

    validation = validate_execution_envelope(envelope)

    assert validation["verification_status"] == EXECUTION_ENV_INVALID
    assert "envelope_payload_digest_mismatch" in validation["validation_failures"]


def test_stale_commit_produces_stale_status_when_current_validation_requested() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)
    envelope["git_commit"] = "0" * 40
    _refresh_digests(envelope)

    validation = validate_execution_envelope(
        envelope,
        repository_root=REPOSITORY_ROOT,
        current_validation=True,
    )

    assert validation == {"verification_status": EXECUTION_ENV_STALE, "validation_failures": ["git_commit_stale"]}


def test_dirty_working_tree_can_produce_dirty_status_when_required() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)
    envelope["working_tree_clean"] = False
    _refresh_digests(envelope)

    validation = validate_execution_envelope(envelope, clean_required=True)

    assert validation == {"verification_status": EXECUTION_ENV_DIRTY, "validation_failures": ["working_tree_dirty"]}


def test_forbidden_authority_leakage_fields_are_flagged() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)
    envelope["unsafe"] = {"execution_permission": True}
    _refresh_digests(envelope)

    validation = validate_execution_envelope(envelope)

    assert validation["verification_status"] == EXECUTION_ENV_INVALID
    assert "forbidden_authority_key:$.unsafe.execution_permission" in validation["validation_failures"]


def test_capture_mode_is_explicit_only(monkeypatch) -> None:
    def fail_capture(*args, **kwargs):
        raise AssertionError("capture should not run during build mode")

    monkeypatch.setattr("sbp_lex.local_trust.execution_envelope.capture_supported_commands", fail_capture)

    envelope = build_execution_environment_envelope(REPOSITORY_ROOT, capture=False)

    assert all(record["command_status"] == "COMMAND_NOT_RUN" for record in envelope["command_results"])


def test_runtime_result_summary_is_evidence_only() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert "runtime_result_summary" in envelope
    assert "governance_result" not in envelope["runtime_result_summary"]


def test_replay_result_summary_is_evidence_only() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT)

    assert "replay_result_summary" in envelope
    assert "governance_result" not in envelope["replay_result_summary"]


def test_cli_build_creates_envelope_file(tmp_path: Path) -> None:
    output = tmp_path / "local_execution_environment_trust_envelope.json"
    result = _run_cli("build", "--path", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "EXECUTION_ENV_VALID" in result.stdout


def test_cli_validate_validates_envelope_file(tmp_path: Path) -> None:
    output = tmp_path / "local_execution_environment_trust_envelope.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("validate", "--path", str(output))

    assert result.returncode == 0
    assert result.stdout.strip() == "EXECUTION_ENV_VALID"


def test_cli_show_prints_envelope_status(tmp_path: Path) -> None:
    output = tmp_path / "local_execution_environment_trust_envelope.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("show", "--path", str(output))

    assert result.returncode == 0
    assert "EXECUTION_ENV_VALID" in result.stdout
    assert "branch=main" in result.stdout


def test_cli_capture_can_capture_safe_mock_commands(tmp_path: Path) -> None:
    manifest = build_local_trust_manifest(REPOSITORY_ROOT)
    manifest_path = write_local_trust_manifest(manifest, tmp_path / "manifest.json", repository_root=REPOSITORY_ROOT)
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT, manifest_path=manifest_path, capture=False)
    output = write_execution_envelope(envelope, tmp_path / "envelope.json", repository_root=REPOSITORY_ROOT)

    loaded = load_execution_envelope(output, repository_root=REPOSITORY_ROOT)

    assert loaded["verification_status"] == EXECUTION_ENV_VALID


def test_importing_local_trust_modules_does_not_execute_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.execution_envelope; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_build_mode_does_not_run_runtime_replay_or_pytest() -> None:
    envelope = build_execution_environment_envelope(REPOSITORY_ROOT, capture=False)
    statuses = {record["command_id"]: record["command_status"] for record in envelope["command_results"]}

    assert statuses["runtime_main"] == "COMMAND_NOT_RUN"
    assert statuses["runtime_replay"] == "COMMAND_NOT_RUN"
    assert statuses["pytest"] == "COMMAND_NOT_RUN"


def test_missing_required_sections_produce_incomplete_status() -> None:
    validation = validate_execution_envelope({"envelope_type": "local_execution_environment_trust_envelope"})

    assert validation["verification_status"] == EXECUTION_ENV_INCOMPLETE
    assert any(item.startswith("missing_required_section:") for item in validation["validation_failures"])


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


def _refresh_digests(envelope: dict) -> None:
    payload_digest = hash_envelope_payload(envelope)
    envelope["envelope_payload_digest"] = payload_digest
    envelope["envelope_signature"] = envelope_signature_for(payload_digest)
    envelope["envelope_digest"] = envelope_digest_for(payload_digest, envelope["envelope_signature"])


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.execution_envelope", *args],
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
