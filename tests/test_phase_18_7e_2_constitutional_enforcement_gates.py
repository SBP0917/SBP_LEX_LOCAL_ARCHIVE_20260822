from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_lex.local_trust.constitutional_gates import (
    build_constitutional_gate_result,
    gate_digest_for,
    gate_signature_for,
    hash_gate_payload,
    load_constitutional_gate_result,
)
from sbp_lex.local_trust.evidence_chain import chain_digest_for, chain_signature_for, hash_chain_payload
from sbp_lex.local_trust.execution_envelope import envelope_digest_for, envelope_signature_for, hash_envelope_payload
from sbp_lex.local_trust.gate_validator import (
    CONSTITUTIONAL_GATES_FAIL,
    CONSTITUTIONAL_GATES_PASS,
    validate_constitutional_gate_result,
)
from sbp_lex.local_trust.manifest import hash_manifest_payload, manifest_digest_for, manifest_signature_for
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.regression_matrix import hash_matrix_payload, matrix_digest_for, matrix_signature_for


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


def test_builds_constitutional_gate_result() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert result["gate_result_type"] == "local_trust_constitutional_enforcement_gates"
    assert result["gate_result_version"] == "18.7E.2"
    assert result["gate_status"] == CONSTITUTIONAL_GATES_PASS
    assert result["gate_summary"]["total_gates"] == 24
    assert result["gate_summary"]["failed_gates"] == 0


def test_gate_output_binds_to_manifest_digest() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert result["bound_manifest_digest"] == _load_json("outputs/local_trust_root_manifest.json")["manifest_digest"]


def test_gate_output_binds_to_execution_envelope_digest() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert result["bound_execution_envelope_digest"] == _load_json("outputs/local_execution_environment_trust_envelope.json")["envelope_digest"]


def test_gate_output_binds_to_evidence_chain_digest() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert result["bound_evidence_chain_digest"] == _load_json("outputs/local_evidence_chain.json")["chain_digest"]


def test_gate_output_binds_to_regression_matrix_digest() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert result["bound_regression_matrix_digest"] == _load_json("outputs/local_trust_regression_matrix.json")["matrix_digest"]


def test_gate_digest_validates() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert validate_constitutional_gate_result(result, repository_root=REPOSITORY_ROOT) == {
        "gate_status": CONSTITUTIONAL_GATES_PASS,
        "validation_failures": [],
    }


def test_tampered_gate_digest_is_detected() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)
    result["gate_digest"] = "0" * 64
    validation = validate_constitutional_gate_result(result, repository_root=REPOSITORY_ROOT)

    assert validation["gate_status"] == CONSTITUTIONAL_GATES_FAIL
    assert "gate_digest_mismatch" in validation["validation_failures"]


def test_missing_manifest_fails_gate(tmp_path: Path) -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT, manifest_path=tmp_path / "missing_manifest.json")

    assert _gate(result, "manifest_exists")["status"] == "GATE_FAIL"
    assert result["gate_status"] != CONSTITUTIONAL_GATES_PASS


def test_invalid_manifest_fails_gate(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("{not json", encoding="utf-8")
    result = build_constitutional_gate_result(REPOSITORY_ROOT, manifest_path=path)

    assert _gate(result, "manifest_validates")["status"] == "GATE_FAIL"


def test_missing_execution_envelope_fails_gate(tmp_path: Path) -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT, envelope_path=tmp_path / "missing_envelope.json")

    assert _gate(result, "execution_envelope_exists")["status"] == "GATE_FAIL"


def test_invalid_execution_envelope_fails_gate(tmp_path: Path) -> None:
    envelope = _load_json("outputs/local_execution_environment_trust_envelope.json")
    envelope["envelope_digest"] = "0" * 64
    path = _write_json(tmp_path / "envelope.json", envelope)

    result = build_constitutional_gate_result(REPOSITORY_ROOT, envelope_path=path)

    assert _gate(result, "execution_envelope_validates")["status"] == "GATE_FAIL"


def test_missing_evidence_chain_fails_gate(tmp_path: Path) -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT, evidence_chain_path=tmp_path / "missing_chain.json")

    assert _gate(result, "evidence_chain_exists")["status"] == "GATE_FAIL"


def test_invalid_evidence_chain_fails_gate(tmp_path: Path) -> None:
    chain = _load_json("outputs/local_evidence_chain.json")
    chain["chain_digest"] = "0" * 64
    path = _write_json(tmp_path / "chain.json", chain)

    result = build_constitutional_gate_result(REPOSITORY_ROOT, evidence_chain_path=path)

    assert _gate(result, "evidence_chain_validates")["status"] == "GATE_FAIL"


def test_evidence_chain_with_missing_evidence_fails_gate(tmp_path: Path) -> None:
    chain = _load_json("outputs/local_evidence_chain.json")
    item = chain["evidence_items"][0]
    item.update({"exists": False, "size_bytes": None, "sha256": None, "last_modified_utc": None, "attestation_status": "MISSING"})
    chain["missing_evidence_items"] = [{"evidence_id": item["evidence_id"], "path": item["path"], "category": item["category"], "required": True, "attestation_status": "MISSING"}]
    chain["evidence_scope"]["present_item_count"] -= 1
    chain["evidence_scope"]["missing_item_count"] += 1
    _refresh_chain(chain)
    path = _write_json(tmp_path / "chain_missing.json", chain)

    result = build_constitutional_gate_result(REPOSITORY_ROOT, evidence_chain_path=path)

    assert _gate(result, "evidence_chain_zero_missing")["status"] == "GATE_FAIL"


def test_evidence_chain_with_changed_evidence_fails_gate(tmp_path: Path) -> None:
    chain = _load_json("outputs/local_evidence_chain.json")
    chain["evidence_items"][0]["sha256"] = "0" * 64
    _refresh_chain(chain)
    path = _write_json(tmp_path / "chain_changed.json", chain)

    result = build_constitutional_gate_result(REPOSITORY_ROOT, evidence_chain_path=path)

    assert _gate(result, "evidence_chain_zero_changed")["status"] == "GATE_FAIL"


def test_missing_regression_matrix_fails_gate(tmp_path: Path) -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT, regression_matrix_path=tmp_path / "missing_matrix.json")

    assert _gate(result, "regression_matrix_exists")["status"] == "GATE_FAIL"


def test_invalid_regression_matrix_fails_gate(tmp_path: Path) -> None:
    matrix = _load_json("outputs/local_trust_regression_matrix.json")
    matrix["matrix_digest"] = "0" * 64
    path = _write_json(tmp_path / "matrix.json", matrix)

    result = build_constitutional_gate_result(REPOSITORY_ROOT, regression_matrix_path=path)

    assert _gate(result, "regression_matrix_validates")["status"] == "GATE_FAIL"


def test_failed_regression_case_fails_gate(tmp_path: Path) -> None:
    matrix = _load_json("outputs/local_trust_regression_matrix.json")
    matrix["regression_cases"][0]["status"] = "REGRESSION_CASE_FAIL"
    matrix["regression_cases"][0]["reason"] = "copied negative test"
    _refresh_matrix_summary(matrix)
    _refresh_matrix(matrix)
    path = _write_json(tmp_path / "matrix_failed_case.json", matrix)

    result = build_constitutional_gate_result(REPOSITORY_ROOT, regression_matrix_path=path)

    assert _gate(result, "regression_cases_passed")["status"] == "GATE_FAIL"


def test_forbidden_authority_leakage_fails_gate(tmp_path: Path) -> None:
    manifest = _load_json("outputs/local_trust_root_manifest.json")
    manifest["unsafe"] = {"execution_permission": True}
    _refresh_manifest(manifest)
    path = _write_json(tmp_path / "manifest_forbidden.json", manifest)

    result = build_constitutional_gate_result(REPOSITORY_ROOT, manifest_path=path)

    assert _gate(result, "forbidden_authority_absent")["status"] == "GATE_FAIL"


def test_runtime_activation_active_implementation_fails_gate(monkeypatch) -> None:
    from sbp_lex.local_trust import gate_runner

    monkeypatch.setattr(gate_runner, "_active_source_matches", lambda root, terms: ["sbp_lex/local_trust/copied_negative.py"])

    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert _gate(result, "future_activation_absent")["status"] == "GATE_FAIL"


def test_phase_19_boundary_gate_exists() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert _gate(result, "phase_19_boundary_preserved")["status"] == "GATE_PASS"


def test_future_surface_absence_gate_exists() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert _gate(result, "future_surface_absent")["status"] == "GATE_PASS"


def test_generated_outputs_pytest_policy_gate_exists() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert _gate(result, "generated_outputs_pytest_policy")["status"] == "GATE_PASS"


def test_temp_cache_exclusion_gate_exists() -> None:
    result = build_constitutional_gate_result(REPOSITORY_ROOT)

    assert _gate(result, "temp_cache_evidence_exclusion")["status"] == "GATE_PASS"


def test_cli_evaluate_creates_gate_output(tmp_path: Path) -> None:
    output = tmp_path / "local_constitutional_gates.json"
    result = _run_cli("evaluate", "--path", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "CONSTITUTIONAL_GATES_PASS" in result.stdout


def test_cli_validate_validates_gate_output(tmp_path: Path) -> None:
    output = tmp_path / "local_constitutional_gates.json"
    _run_cli("evaluate", "--path", str(output))
    result = _run_cli("validate", "--path", str(output))

    assert result.returncode == 0
    assert result.stdout.strip() == "CONSTITUTIONAL_GATES_PASS"


def test_cli_show_prints_gate_status(tmp_path: Path) -> None:
    output = tmp_path / "local_constitutional_gates.json"
    _run_cli("evaluate", "--path", str(output))
    result = _run_cli("show", "--path", str(output))

    assert result.returncode == 0
    assert "CONSTITUTIONAL_GATES_PASS" in result.stdout
    assert "gates=24" in result.stdout


def test_importing_modules_does_not_execute_runtime_commands() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import sbp_lex.local_trust.constitutional_gates; print('imported')"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "imported"


def test_gate_cli_sources_do_not_run_runtime_replay_pytest_or_batch() -> None:
    source = _gate_source()

    assert "main.py" not in source
    assert "subprocess.run" not in source
    assert "run_tests.bat" not in source
    assert "capture_supported_commands" not in source


def test_no_prohibited_active_terms_in_gate_implementation() -> None:
    source = _gate_source()

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


def _write_json(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _gate(result: dict, gate_id: str) -> dict:
    for gate in result["gate_results"]:
        if gate["gate_id"] == gate_id:
            return gate
    raise AssertionError(f"missing gate {gate_id}")


def _refresh_manifest(manifest: dict) -> None:
    payload_digest = hash_manifest_payload(manifest)
    manifest["manifest_payload_digest"] = payload_digest
    manifest["manifest_signature"] = manifest_signature_for(payload_digest)
    manifest["manifest_digest"] = manifest_digest_for(payload_digest, manifest["manifest_signature"])


def _refresh_envelope(envelope: dict) -> None:
    payload_digest = hash_envelope_payload(envelope)
    envelope["envelope_payload_digest"] = payload_digest
    envelope["envelope_signature"] = envelope_signature_for(payload_digest)
    envelope["envelope_digest"] = envelope_digest_for(payload_digest, envelope["envelope_signature"])


def _refresh_chain(chain: dict) -> None:
    payload_digest = hash_chain_payload(chain)
    chain["chain_payload_digest"] = payload_digest
    chain["chain_signature"] = chain_signature_for(payload_digest)
    chain["chain_digest"] = chain_digest_for(payload_digest, chain["chain_signature"])


def _refresh_matrix(matrix: dict) -> None:
    payload_digest = hash_matrix_payload(matrix)
    matrix["matrix_payload_digest"] = payload_digest
    matrix["matrix_signature"] = matrix_signature_for(payload_digest)
    matrix["matrix_digest"] = matrix_digest_for(payload_digest, matrix["matrix_signature"])


def _refresh_gate_digest(result: dict) -> None:
    payload_digest = hash_gate_payload(result)
    result["gate_payload_digest"] = payload_digest
    result["gate_signature"] = gate_signature_for(payload_digest)
    result["gate_digest"] = gate_digest_for(payload_digest, result["gate_signature"])


def _refresh_matrix_summary(matrix: dict) -> None:
    statuses = [case["status"] for case in matrix["regression_cases"]]
    matrix["regression_summary"] = {
        "total_cases": len(statuses),
        "passed_cases": statuses.count("REGRESSION_CASE_PASS"),
        "failed_cases": statuses.count("REGRESSION_CASE_FAIL"),
        "skipped_cases": statuses.count("REGRESSION_CASE_SKIPPED"),
        "error_cases": statuses.count("REGRESSION_CASE_ERROR"),
        "all_cases_passed": statuses.count("REGRESSION_CASE_FAIL") == 0
        and statuses.count("REGRESSION_CASE_ERROR") == 0
        and statuses.count("REGRESSION_CASE_SKIPPED") == 0,
    }


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbp_lex.local_trust.constitutional_gates", *args],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _gate_source() -> str:
    return "\n".join(
        (LOCAL_TRUST_ROOT / name).read_text(encoding="utf-8")
        for name in (
            "constitutional_gates.py",
            "gate_policy.py",
            "gate_runner.py",
            "gate_validator.py",
        )
    )
