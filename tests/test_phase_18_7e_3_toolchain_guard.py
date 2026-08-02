from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.command_policy import required_command_ids
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.toolchain_guard import (
    build_toolchain_guard,
    hash_toolchain_payload,
    load_toolchain_guard,
    toolchain_digest_for,
    toolchain_signature_for,
)
from sbp_lex.local_trust.toolchain_inventory import collect_dependency_file_digests
from sbp_lex.local_trust.toolchain_validator import TOOLCHAIN_GUARD_FAIL, TOOLCHAIN_GUARD_PASS, validate_toolchain_guard


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRUST_ROOT = REPOSITORY_ROOT / "sbp_lex" / "local_trust"
PROTECTED_RUNTIME_PATHS = {
    "main.py",
    "sbp_lex/execution/execution_gate.py",
    "sbp_lex/governance/procedural_truth_engine.py",
    "sbp_lex/governance/procedural_truth_runner.py",
    "sbp_lex/authority_first/root_of_trust_runner.py",
    "sbp_lex/shared/hash_chain.py",
    "sbp_lex/shared/state_builder.py",
    "sbp_lex/pipeline/dual_runner.py",
}

AUTHORIZED_EIE_PT_REBUILD_TOUCHPOINTS = {
    "sbp_lex/execution/execution_gate.py",
    "sbp_lex/governance/procedural_truth_engine.py",
    "sbp_lex/authority_first/root_of_trust_runner.py",
    "sbp_lex/shared/state_builder.py",
}


def test_builds_toolchain_guard_output() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["toolchain_guard_type"] == "local_trust_dependency_toolchain_guard"
    assert guard["toolchain_guard_version"] == "18.7E.3"
    assert guard["toolchain_status"] == TOOLCHAIN_GUARD_PASS
    assert guard["toolchain_summary"]["total_checks"] == 39
    assert guard["toolchain_summary"]["failed_checks"] == 0


def test_toolchain_output_binds_to_manifest_digest() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["bound_manifest_digest"] == _load_json("outputs/local_trust_root_manifest.json")["manifest_digest"]


def test_toolchain_output_binds_to_execution_envelope_digest() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["bound_execution_envelope_digest"] == _load_json("outputs/local_execution_environment_trust_envelope.json")["envelope_digest"]


def test_toolchain_output_binds_to_evidence_chain_digest() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["bound_evidence_chain_digest"] == _load_json("outputs/local_evidence_chain.json")["chain_digest"]


def test_toolchain_output_binds_to_regression_matrix_digest() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["bound_regression_matrix_digest"] == _load_json("outputs/local_trust_regression_matrix.json")["matrix_digest"]


def test_toolchain_output_binds_to_constitutional_gates_digest() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["bound_constitutional_gates_digest"] == _load_json("outputs/local_constitutional_gates.json")["gate_digest"]


def test_toolchain_digest_validates() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert validate_toolchain_guard(guard, repository_root=REPOSITORY_ROOT) == {
        "toolchain_status": TOOLCHAIN_GUARD_PASS,
        "validation_failures": [],
    }


def test_tampered_toolchain_digest_is_detected() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)
    guard["toolchain_digest"] = "0" * 64
    validation = validate_toolchain_guard(guard, repository_root=REPOSITORY_ROOT)

    assert validation["toolchain_status"] == TOOLCHAIN_GUARD_FAIL
    assert "toolchain_digest_mismatch" in validation["validation_failures"]


def test_python_executable_and_version_are_recorded() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["python_executable"]
    assert Path(guard["python_executable"]).exists()
    assert guard["python_version"].startswith(str(sys.version_info.major))


def test_pytest_version_is_recorded() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["pytest_version"]


def test_dependency_files_are_discovered_or_explicit_none_state_recorded() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert guard["dependency_files"]
    assert "requirements.txt" in {record["path"] for record in guard["dependency_file_digests"]}


def test_dependency_file_digests_are_stable() -> None:
    first = collect_dependency_file_digests(REPOSITORY_ROOT)
    second = collect_dependency_file_digests(REPOSITORY_ROOT)

    assert first == second


def test_verification_command_policy_exists_and_records_required_commands() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)
    command_ids = {command["command_id"] for command in guard["verification_command_policy"]["commands"]}

    assert required_command_ids() <= command_ids


def test_pytest_ignore_outputs_policy_exists() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)
    options = set(guard["pytest_collection_policy"]["required_options"])

    assert "--ignore=outputs" in options


def test_temp_cache_exclusion_policy_exists() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert ".pytest_cache" in guard["ignored_temp_paths"]
    assert "__pycache__" in guard["ignored_temp_paths"]
    assert "outputs" in guard["ignored_output_paths"]


def test_forbidden_authority_leakage_fails_validation() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)
    guard["unsafe"] = {"execution_permission": True}
    _refresh_guard(guard)

    validation = validate_toolchain_guard(guard, repository_root=REPOSITORY_ROOT)

    assert validation["toolchain_status"] == TOOLCHAIN_GUARD_FAIL
    assert "forbidden_authority_key:$.unsafe.execution_permission" in validation["validation_failures"]


def test_runtime_activation_active_implementation_fails_validation() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)
    check = _check(guard, "future_activation_absent")
    check["status"] = "TOOLCHAIN_CHECK_FAIL"
    check["observed_condition"] = "matches=1"
    check["reason"] = "copied negative test"
    _refresh_summary(guard)
    _refresh_guard(guard)

    validation = validate_toolchain_guard(guard, repository_root=REPOSITORY_ROOT)

    assert validation["toolchain_status"] == TOOLCHAIN_GUARD_FAIL


def test_phase_19_boundary_check_exists() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert _check(guard, "phase_19_boundary_preserved")["status"] == "TOOLCHAIN_CHECK_PASS"


def test_future_surface_absence_check_exists() -> None:
    guard = build_toolchain_guard(REPOSITORY_ROOT)

    assert _check(guard, "future_surface_absent")["status"] == "TOOLCHAIN_CHECK_PASS"


def test_cli_build_creates_toolchain_output(tmp_path: Path) -> None:
    output = tmp_path / "local_toolchain_guard.json"
    result = _run_cli("build", "--path", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "TOOLCHAIN_GUARD_PASS" in result.stdout


def test_cli_validate_validates_toolchain_output(tmp_path: Path) -> None:
    output = tmp_path / "local_toolchain_guard.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("validate", "--path", str(output))

    assert result.returncode == 0
    assert result.stdout.strip() == "TOOLCHAIN_GUARD_PASS"


def test_cli_show_prints_toolchain_status(tmp_path: Path) -> None:
    output = tmp_path / "local_toolchain_guard.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("show", "--path", str(output))

    assert result.returncode == 0
    assert "TOOLCHAIN_GUARD_PASS" in result.stdout
    assert "checks=39" in result.stdout


def test_load_round_trip(tmp_path: Path) -> None:
    output = tmp_path / "guard.json"
    _run_cli("build", "--path", str(output))
    loaded = load_toolchain_guard(output, repository_root=REPOSITORY_ROOT)

    assert loaded["toolchain_status"] == TOOLCHAIN_GUARD_PASS


def test_importing_modules_does_not_execute_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.toolchain_guard; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_toolchain_cli_sources_do_not_execute_runtime_replay_pytest_or_batch() -> None:
    source = _toolchain_source()

    assert "subprocess.run" not in source
    assert "capture_supported_commands" not in source
    assert "os.system" not in source


def test_no_prohibited_active_terms_in_toolchain_implementation() -> None:
    source = _toolchain_source()

    for term in (
        "node_quorum",
        "node_attestation",
        "distributed_consensus",
        "mesh_runtime",
        "cloud_runtime",
        "runtime_activation",
        "external_execution_permission",
        "external_governance_result",
    ):
        assert term not in source


def test_no_sbp_lex_runtime_authority_files_are_modified() -> None:
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    changed = {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}

    unauthorized = (changed & PROTECTED_RUNTIME_PATHS) - AUTHORIZED_EIE_PT_REBUILD_TOUCHPOINTS
    assert not unauthorized


def _load_json(path: str) -> dict:
    return json.loads(resolve_local_trust_path(REPOSITORY_ROOT, path).read_text(encoding="utf-8"))


def _check(guard: dict, check_id: str) -> dict:
    for check in guard["toolchain_checks"]:
        if check["check_id"] == check_id:
            return check
    raise AssertionError(f"missing check {check_id}")


def _refresh_guard(guard: dict) -> None:
    payload_digest = hash_toolchain_payload(guard)
    guard["toolchain_payload_digest"] = payload_digest
    guard["toolchain_signature"] = toolchain_signature_for(payload_digest)
    guard["toolchain_digest"] = toolchain_digest_for(payload_digest, guard["toolchain_signature"])


def _refresh_summary(guard: dict) -> None:
    statuses = [check["status"] for check in guard["toolchain_checks"]]
    guard["toolchain_summary"] = {
        **guard["toolchain_summary"],
        "total_checks": len(statuses),
        "passed_checks": statuses.count("TOOLCHAIN_CHECK_PASS"),
        "failed_checks": statuses.count("TOOLCHAIN_CHECK_FAIL"),
        "skipped_checks": statuses.count("TOOLCHAIN_CHECK_SKIPPED"),
        "error_checks": statuses.count("TOOLCHAIN_CHECK_ERROR"),
        "all_required_checks_passed": statuses.count("TOOLCHAIN_CHECK_FAIL") == 0
        and statuses.count("TOOLCHAIN_CHECK_ERROR") == 0,
    }


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.toolchain_guard", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _toolchain_source() -> str:
    return "\n".join(
        (LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8")
        for name in (
            "command_policy.py",
            "toolchain_guard.py",
            "toolchain_inventory.py",
            "toolchain_policy.py",
            "toolchain_validator.py",
        )
    )
