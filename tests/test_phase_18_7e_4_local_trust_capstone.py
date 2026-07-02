from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.capstone_validator import LOCAL_TRUST_CAPSTONE_FAIL, LOCAL_TRUST_CAPSTONE_PASS
from sbp_lex.local_trust.local_trust_capstone import (
    build_local_trust_capstone,
    capstone_digest_for,
    capstone_signature_for,
    hash_capstone_payload,
    load_local_trust_capstone,
)
from sbp_lex.local_trust.capstone_validator import validate_local_trust_capstone


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


def test_builds_capstone_output() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["capstone_type"] == "local_trust_25_year_completion_lock"
    assert capstone["capstone_version"] == "18.7E.4"
    assert capstone["capstone_status"] == LOCAL_TRUST_CAPSTONE_PASS
    assert capstone["local_trust_completion_summary"]["completed_phase_count"] == 5
    assert capstone["local_trust_completion_summary"]["bound_artifact_count"] == 6


def test_capstone_binds_manifest_digest() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["bound_manifest_digest"] == _load_json("outputs/local_trust_root_manifest.json")["manifest_digest"]


def test_capstone_binds_execution_envelope_digest() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["bound_execution_envelope_digest"] == _load_json(
        "outputs/local_execution_environment_trust_envelope.json"
    )["envelope_digest"]


def test_capstone_binds_evidence_chain_digest() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["bound_evidence_chain_digest"] == _load_json("outputs/local_evidence_chain.json")["chain_digest"]


def test_capstone_binds_regression_matrix_digest() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["bound_regression_matrix_digest"] == _load_json("outputs/local_trust_regression_matrix.json")[
        "matrix_digest"
    ]


def test_capstone_binds_constitutional_gates_digest() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["bound_constitutional_gates_digest"] == _load_json("outputs/local_constitutional_gates.json")[
        "gate_digest"
    ]


def test_capstone_binds_toolchain_guard_digest() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["bound_toolchain_guard_digest"] == _load_json("outputs/local_toolchain_guard.json")[
        "toolchain_digest"
    ]


def test_capstone_digest_validates() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert validate_local_trust_capstone(capstone, repository_root=REPOSITORY_ROOT) == {
        "capstone_status": LOCAL_TRUST_CAPSTONE_PASS,
        "validation_failures": [],
    }


def test_tampered_capstone_digest_is_detected() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)
    capstone["capstone_digest"] = "0" * 64

    validation = validate_local_trust_capstone(capstone, repository_root=REPOSITORY_ROOT)

    assert validation["capstone_status"] == LOCAL_TRUST_CAPSTONE_FAIL
    assert "capstone_digest_mismatch" in validation["validation_failures"]


def test_completed_phase_index_includes_required_phases() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)
    phase_ids = {phase["phase_id"] for phase in capstone["completed_phases"]}

    assert {"18.7D.1", "18.7E.1", "18.7E.2", "18.7E.3", "18.7E.4"} <= phase_ids


def test_verification_command_index_exists() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)
    command_ids = {command["command_id"] for command in capstone["verification_command_index"]["commands"]}

    assert {"capstone_build", "capstone_validate", "capstone_show", "runtime_main", "runtime_replay"} <= command_ids


def test_boundary_confirmation_summary_exists() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)
    summary = capstone["boundary_confirmation_summary"]

    assert summary["skgDtnRemainExternalNonAuthoritative"] is True
    assert summary["capstoneIsExecutionAuthority"] is False


def test_phase_19_not_started_boundary_exists() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)

    assert capstone["local_trust_completion_summary"]["phase_19_not_started"] is True
    assert capstone["boundary_confirmation_summary"]["phase19Started"] is False


def test_18_7f_next_phase_readiness_exists() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)
    readiness = capstone["next_phase_readiness"]

    assert readiness["next_phase_id"] == "18.7F"
    assert readiness["readiness_status"] == "READY_MARKER_ONLY"
    assert readiness["implemented_in_this_phase"] is False


def test_runtime_activation_active_implementation_fails_validation() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)
    capstone["boundary_confirmation_summary"]["runtimeActivationIntroduced"] = True
    _refresh_capstone(capstone)

    validation = validate_local_trust_capstone(capstone, repository_root=REPOSITORY_ROOT)

    assert validation["capstone_status"] == LOCAL_TRUST_CAPSTONE_FAIL


def test_future_surface_active_implementation_fails_validation() -> None:
    capstone = build_local_trust_capstone(REPOSITORY_ROOT)
    capstone["boundary_confirmation_summary"]["futureRuntimeSurfacesIntroduced"] = True
    _refresh_capstone(capstone)

    validation = validate_local_trust_capstone(capstone, repository_root=REPOSITORY_ROOT)

    assert validation["capstone_status"] == LOCAL_TRUST_CAPSTONE_FAIL


def test_cli_build_creates_capstone_output(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_25_year_capstone.json"
    result = _run_cli("build", "--path", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "LOCAL_TRUST_CAPSTONE_PASS" in result.stdout


def test_cli_validate_validates_capstone_output(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_25_year_capstone.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("validate", "--path", str(output))

    assert result.returncode == 0
    assert result.stdout.strip() == "LOCAL_TRUST_CAPSTONE_PASS"


def test_cli_show_prints_capstone_status(tmp_path: Path) -> None:
    output = tmp_path / "local_trust_25_year_capstone.json"
    _run_cli("build", "--path", str(output))
    result = _run_cli("show", "--path", str(output))

    assert result.returncode == 0
    assert "LOCAL_TRUST_CAPSTONE_PASS" in result.stdout
    assert "next_phase=18.7F" in result.stdout


def test_load_round_trip(tmp_path: Path) -> None:
    output = tmp_path / "capstone.json"
    _run_cli("build", "--path", str(output))
    loaded = load_local_trust_capstone(output, repository_root=REPOSITORY_ROOT)

    assert loaded["capstone_status"] == LOCAL_TRUST_CAPSTONE_PASS


def test_importing_modules_does_not_execute_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.local_trust_capstone; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_capstone_cli_sources_do_not_execute_runtime_replay_pytest_or_batch() -> None:
    source = _capstone_source()

    assert '["python"' not in source
    assert '["pytest"' not in source
    assert '["cmd"' not in source
    assert "shell=True" not in source


def test_no_prohibited_active_terms_in_capstone_implementation() -> None:
    source = _capstone_source()

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
    return json.loads((REPOSITORY_ROOT / path).read_text(encoding="utf-8"))


def _refresh_capstone(capstone: dict) -> None:
    payload_digest = hash_capstone_payload(capstone)
    capstone["capstone_payload_digest"] = payload_digest
    capstone["capstone_signature"] = capstone_signature_for(payload_digest)
    capstone["capstone_digest"] = capstone_digest_for(payload_digest, capstone["capstone_signature"])


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.local_trust_capstone", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _capstone_source() -> str:
    return "\n".join(
        (LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8")
        for name in (
            "capstone_report.py",
            "capstone_validator.py",
            "local_trust_capstone.py",
        )
    )
