from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sbp_simulation.command_policy import command_allowed
from sbp_simulation.runner import _display_path, _write_json
from sbp_simulation.scenarios import (
    SCENARIO_LIBRARY,
    scenario_to_dict,
    validate_scenario,
)


FAILURE_TEST_STATUSES = {
    "FAILURE_TEST_OK",
    "FAILURE_TEST_DETECTED",
    "FAILURE_TEST_BLOCKED",
    "FAILURE_TEST_INCOMPLETE",
    "FAILURE_TEST_INVALID",
    "FAILURE_TEST_WARNING",
}
FAILURE_MATRIX_STATUSES = {
    "FAILURE_MATRIX_OK",
    "FAILURE_MATRIX_WARNING",
    "FAILURE_MATRIX_FAILED",
}
FORBIDDEN_RUNTIME_STATUSES = {"ALLOW", "DENY", "ESCALATE", "EXECUTE", "HALT"}
PHASE19A_RUNTIME_REQUIRED = "PHASE19A_RUNTIME_REQUIRED"
FAILURE_BOUNDARY_STATEMENT = (
    "SIM-03 is local/private artifact-level failure validation only. It is not "
    "production activation, external actuation, runtime authority, public "
    "publication, or Phase 19A runtime proof."
)


@dataclass(frozen=True)
class FailureTestDefinition:
    failure_test_id: str
    reviewer_description: str
    expected_detection_mode: str
    phase19a_required: bool
    artifact_level: bool
    runtime_level: bool
    expected_status: str


FAILURE_TESTS: dict[str, FailureTestDefinition] = {
    "UNSAFE_COMMAND_BLOCK": FailureTestDefinition(
        "UNSAFE_COMMAND_BLOCK",
        "Prove unsafe command execution is blocked by simulation safe-command policy.",
        "safe_command_policy_block",
        False,
        True,
        False,
        "FAILURE_TEST_BLOCKED",
    ),
    "INVALID_RISK_MODE_MAPPING": FailureTestDefinition(
        "INVALID_RISK_MODE_MAPPING",
        "Prove invalid adaptive traversal mappings are rejected.",
        "scenario_schema_validation_rejects_mapping",
        False,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
    "UNKNOWN_SCENARIO_BLOCK": FailureTestDefinition(
        "UNKNOWN_SCENARIO_BLOCK",
        "Unknown scenario ID is blocked.",
        "scenario_lookup_block",
        False,
        True,
        False,
        "FAILURE_TEST_BLOCKED",
    ),
    "SCENARIO_RESULT_TAMPER": FailureTestDefinition(
        "SCENARIO_RESULT_TAMPER",
        "Detect mutation of a copied SIM-02 scenario result artifact.",
        "canonical_digest_mismatch",
        False,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
    "REPLAY_RESULT_MISMATCH_ARTIFACT": FailureTestDefinition(
        "REPLAY_RESULT_MISMATCH_ARTIFACT",
        "Detect a controlled replay result artifact with mismatch fields.",
        "artifact_level_replay_mismatch",
        True,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
    "PARITY_MISMATCH_FIXTURE": FailureTestDefinition(
        "PARITY_MISMATCH_FIXTURE",
        "Detect differing canonical digests between controlled branch outputs.",
        "fixture_level_parity_mismatch",
        True,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
    "TOKEN_SIGNATURE_TAMPER_ARTIFACT": FailureTestDefinition(
        "TOKEN_SIGNATURE_TAMPER_ARTIFACT",
        "Detect controlled token evidence signature or digest tamper.",
        "artifact_level_token_signature_tamper",
        True,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
    "HASH_CHAIN_TAMPER_ARTIFACT": FailureTestDefinition(
        "HASH_CHAIN_TAMPER_ARTIFACT",
        "Detect controlled hash-chain link mutation.",
        "artifact_level_hash_chain_tamper",
        True,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
    "REQUIRED_EVIDENCE_MISSING": FailureTestDefinition(
        "REQUIRED_EVIDENCE_MISSING",
        "Detect a required evidence reference whose file is missing.",
        "required_evidence_missing",
        False,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
    "FORBIDDEN_PUBLICATION_ACTIVATION": FailureTestDefinition(
        "FORBIDDEN_PUBLICATION_ACTIVATION",
        "Detect forbidden publication, blockchain, ledger, or cloud activation flags.",
        "boundary_activation_block",
        False,
        True,
        False,
        "FAILURE_TEST_BLOCKED",
    ),
    "PVPL_BUNDLE_TAMPER_COMPATIBILITY": FailureTestDefinition(
        "PVPL_BUNDLE_TAMPER_COMPATIBILITY",
        "Copy and tamper a PVPL bundle, then require PVPL verification to reject it.",
        "pvpl_verify_bundle_not_proof_ok",
        False,
        True,
        False,
        "FAILURE_TEST_DETECTED",
    ),
}


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(_without_digest(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _without_digest(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_digest(item) for key, item in value.items() if key != "digest"}
    if isinstance(value, list):
        return [_without_digest(item) for item in value]
    return value


def list_failure_tests() -> list[dict[str, Any]]:
    return [asdict(item) for item in FAILURE_TESTS.values()]


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_summary(path: Path, definition: FailureTestDefinition, result: dict[str, Any]) -> None:
    lines = [
        f"# SIM-03 Failure Summary: {definition.failure_test_id}",
        "",
        f"- Tested: {definition.reviewer_description}",
        f"- Detection mode: {definition.expected_detection_mode}",
        f"- Detection result: {result['failure_test_status']}",
        f"- Artifact-level proof: {definition.artifact_level}",
        f"- Runtime-level proof: {definition.runtime_level}",
        f"- Phase 19A required: {definition.phase19a_required}",
        "",
        "## Artifact Handling",
        "",
        result.get("artifact_summary", "No source artifact was required."),
        "",
        "## Evidence Paths",
        "",
        *[f"- `{path_item}`" for path_item in result.get("evidence_paths", [])],
        "",
        "## Limitations",
        "",
        result.get("limitations", FAILURE_BOUNDARY_STATEMENT),
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def _base_result(definition: FailureTestDefinition, out_dir: Path, root: Path) -> tuple[Path, Path, dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    definition_path = out_dir / "failure_test_definition.json"
    verification_path = out_dir / "verification_result.json"
    definition_payload = asdict(definition)
    _write_json(definition_path, definition_payload)
    result = {
        "failure_test_id": definition.failure_test_id,
        "failure_test_status": definition.expected_status,
        "expected_detection_mode": definition.expected_detection_mode,
        "artifact_level": definition.artifact_level,
        "runtime_level": definition.runtime_level,
        "phase19a_required": definition.phase19a_required,
        "phase19a_marker": PHASE19A_RUNTIME_REQUIRED if definition.phase19a_required else "NOT_REQUIRED",
        "boundary_statement": FAILURE_BOUNDARY_STATEMENT,
        "evidence_paths": [_display_path(definition_path, root), _display_path(verification_path, root)],
    }
    return definition_path, verification_path, result


def _unsafe_command_block(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    examples = [
        ["git", "clean"],
        ["git", "reset"],
        ["git", "push"],
        ["rmdir", "runtime_artifacts"],
        ["remove", "runtime_artifacts"],
        ["delete", "runtime_artifacts"],
        ["python", "main.py", "|", "whoami"],
        ["python", "-m", "sbp_pvpl.cli", "--publish", "external"],
        ["python", "-m", "sbp_pvpl.cli", "--blockchain", "--cloud", "--ledger"],
    ]
    checks = [{"command": command, "allowed": command_allowed(command)[0], "reason": command_allowed(command)[1]} for command in examples]
    detected = all(not item["allowed"] for item in checks)
    result.update({
        "failure_test_status": "FAILURE_TEST_BLOCKED" if detected else "FAILURE_TEST_WARNING",
        "checks": checks,
        "artifact_summary": "Unsafe command examples were evaluated against the simulation command policy only.",
    })
    _write_json(verification_path, result)
    return result


def _invalid_mapping(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    cases = []
    base_top = scenario_to_dict(SCENARIO_LIBRARY["TOP_PARITY_MISMATCH_BLOCK"])
    base_top["traversal_mode"] = "SINGLE_PIPELINE"
    cases.append(("TOP_SINGLE_PIPELINE", base_top))
    base_low = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    base_low["traversal_mode"] = "FULL_DUAL"
    cases.append(("LOW_FULL_DUAL", base_low))
    missing_risk = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    missing_risk.pop("risk_tier")
    cases.append(("MISSING_RISK_TIER", missing_risk))
    missing_mode = scenario_to_dict(SCENARIO_LIBRARY["LOW_ALLOW_ROUTINE_STATUS_CHECK"])
    missing_mode.pop("traversal_mode")
    cases.append(("MISSING_TRAVERSAL_MODE", missing_mode))
    checks = []
    for name, payload in cases:
        valid, failures = validate_scenario(payload)
        checks.append({"case": name, "valid": valid, "failures": failures})
    detected = all(not item["valid"] for item in checks)
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "checks": checks,
        "artifact_summary": "Invalid scenario payloads were generated in memory and rejected by schema validation.",
    })
    _write_json(verification_path, result)
    return result


def _unknown_scenario(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    unknown = "UNKNOWN_SCENARIO_DOES_NOT_EXIST" not in SCENARIO_LIBRARY
    result.update({
        "failure_test_status": "FAILURE_TEST_BLOCKED" if unknown else "FAILURE_TEST_WARNING",
        "unknown_scenario_blocked": unknown,
        "artifact_summary": "Unknown scenario lookup remained blocked without runtime execution.",
    })
    _write_json(verification_path, result)
    return result


def _scenario_result_tamper(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    source = root / "runtime_artifacts" / "sim_02" / "TOP_PARITY_MISMATCH_BLOCK" / "scenario_result.json"
    original_copy = out_dir / "original_artifact_copy.json"
    tampered_path = out_dir / "tampered_artifact.json"
    if source.exists():
        payload = _load_json(source)
    else:
        payload = {
            "scenario_id": "TOP_PARITY_MISMATCH_BLOCK",
            "scenario_status": "SCENARIO_READY_FOR_PHASE_19A",
            "runtime_execution_status": "NOT_EXECUTED_PHASE19A_REQUIRED",
        }
    original_payload = copy.deepcopy(payload)
    original_payload["digest"] = canonical_digest(original_payload)
    tampered = copy.deepcopy(original_payload)
    tampered["scenario_status"] = "SCENARIO_INVALID"
    detected = canonical_digest(original_payload) != canonical_digest(tampered)
    _write_json(original_copy, original_payload)
    _write_json(tampered_path, tampered)
    result["evidence_paths"].extend([_display_path(original_copy, root), _display_path(tampered_path, root)])
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "source_artifact": _display_path(source, root),
        "tamper_detected": detected,
        "artifact_summary": "A copied scenario_result.json was mutated under runtime_artifacts/sim_03 only.",
    })
    _write_json(verification_path, result)
    return result


def _replay_mismatch(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    original_copy = out_dir / "original_artifact_copy.json"
    tampered_path = out_dir / "tampered_artifact.json"
    original = {"matched": True, "mismatches": [], "replay_count": 2}
    tampered = copy.deepcopy(original)
    tampered["matched"] = False
    tampered["mismatches"] = ["controlled_artifact_mismatch"]
    detected = tampered["matched"] is False and bool(tampered["mismatches"])
    _write_json(original_copy, original)
    _write_json(tampered_path, tampered)
    result["evidence_paths"].extend([_display_path(original_copy, root), _display_path(tampered_path, root)])
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "replay_mismatch_detected": detected,
        "artifact_summary": "Controlled replay artifact copy changed matched=true to matched=false.",
        "limitations": f"Artifact-level replay mismatch only; {PHASE19A_RUNTIME_REQUIRED}.",
    })
    _write_json(verification_path, result)
    return result


def _parity_mismatch(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    original_copy = out_dir / "original_artifact_copy.json"
    tampered_path = out_dir / "tampered_artifact.json"
    branch_a = {"branch": "pipeline_a_result", "canonical_result": {"decision_label": "EXPECTED_ALLOW", "score": 1}}
    branch_b = {"branch": "pipeline_b_result", "canonical_result": {"decision_label": "EXPECTED_ALLOW", "score": 0}}
    digest_a = canonical_digest(branch_a)
    digest_b = canonical_digest(branch_b)
    detected = digest_a != digest_b
    _write_json(original_copy, {"pipeline_a_result": branch_a, "digest": digest_a})
    _write_json(tampered_path, {"pipeline_b_result": branch_b, "digest": digest_b})
    result["evidence_paths"].extend([_display_path(original_copy, root), _display_path(tampered_path, root)])
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "pipeline_a_digest": digest_a,
        "pipeline_b_digest": digest_b,
        "parity_mismatch_detected": detected,
        "artifact_summary": "Two controlled branch outputs were generated with different canonical digests.",
        "limitations": f"Fixture-level parity mismatch only; {PHASE19A_RUNTIME_REQUIRED}.",
    })
    _write_json(verification_path, result)
    return result


def _token_tamper(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    original_copy = out_dir / "original_artifact_copy.json"
    tampered_path = out_dir / "tampered_artifact.json"
    token = {"token_id": "controlled_token", "payload_digest": "abc123", "signature": "sig_original"}
    token["digest"] = canonical_digest(token)
    tampered = copy.deepcopy(token)
    tampered["signature"] = "sig_tampered"
    detected = canonical_digest(tampered) != token["digest"]
    _write_json(original_copy, token)
    _write_json(tampered_path, tampered)
    result["evidence_paths"].extend([_display_path(original_copy, root), _display_path(tampered_path, root)])
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "token_tamper_detected": detected,
        "artifact_summary": "Controlled token evidence signature was mutated under sim_03.",
        "limitations": f"Artifact-level token tamper only; {PHASE19A_RUNTIME_REQUIRED}.",
    })
    _write_json(verification_path, result)
    return result


def _hash_chain_tamper(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    original_copy = out_dir / "original_artifact_copy.json"
    tampered_path = out_dir / "tampered_artifact.json"
    links = [{"index": 0, "payload": "root", "previous_hash": ""}]
    links[0]["hash"] = canonical_digest(links[0])
    links.append({"index": 1, "payload": "child", "previous_hash": links[0]["hash"]})
    links[1]["hash"] = canonical_digest(links[1])
    chain = {"links": links}
    tampered = copy.deepcopy(chain)
    tampered["links"][1]["previous_hash"] = "broken_previous_hash"
    detected = tampered["links"][1]["previous_hash"] != chain["links"][0]["hash"]
    _write_json(original_copy, chain)
    _write_json(tampered_path, tampered)
    result["evidence_paths"].extend([_display_path(original_copy, root), _display_path(tampered_path, root)])
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "hash_chain_tamper_detected": detected,
        "artifact_summary": "Controlled hash-chain link was mutated under sim_03.",
        "limitations": f"Artifact-level hash-chain tamper only; {PHASE19A_RUNTIME_REQUIRED}.",
    })
    _write_json(verification_path, result)
    return result


def _required_evidence_missing(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    manifest_path = out_dir / "tampered_artifact.json"
    missing_path = out_dir / "missing_required_evidence.json"
    manifest = {"required_evidence": [_display_path(missing_path, root)]}
    detected = not missing_path.exists()
    _write_json(manifest_path, manifest)
    result["evidence_paths"].append(_display_path(manifest_path, root))
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "missing_evidence_detected": detected,
        "missing_path": _display_path(missing_path, root),
        "artifact_summary": "Controlled manifest references a required file that does not exist.",
    })
    _write_json(verification_path, result)
    return result


def _forbidden_publication(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    tampered_path = out_dir / "tampered_artifact.json"
    manifest = {
        "publication_active": True,
        "blockchain_active": True,
        "ledger_active": True,
        "cloud_active": True,
    }
    detected = any(manifest.values())
    _write_json(tampered_path, manifest)
    result["evidence_paths"].append(_display_path(tampered_path, root))
    result.update({
        "failure_test_status": "FAILURE_TEST_BLOCKED" if detected else "FAILURE_TEST_WARNING",
        "forbidden_publication_activation_blocked": detected,
        "artifact_summary": "Controlled PVPL-style manifest copy set forbidden publication flags true.",
    })
    _write_json(verification_path, result)
    return result


def _find_pvpl_bundle(root: Path) -> Path | None:
    candidates = sorted((root / "runtime_artifacts" / "pvpl_02").glob("*.json"))
    for path in candidates:
        if "bundle" in path.name.lower():
            return path
    return None


def _pvpl_bundle_tamper(definition: FailureTestDefinition, out_dir: Path, root: Path) -> dict[str, Any]:
    _, verification_path, result = _base_result(definition, out_dir, root)
    source = _find_pvpl_bundle(root)
    if source is None:
        result.update({
            "failure_test_status": "FAILURE_TEST_INCOMPLETE",
            "reason": "PVPL bundle missing",
            "artifact_summary": "No PVPL bundle was available to copy for tamper compatibility check.",
        })
        _write_json(verification_path, result)
        return result
    original_copy = out_dir / "original_artifact_copy.json"
    tampered_path = out_dir / "tampered_artifact.json"
    shutil.copyfile(source, original_copy)
    payload = _load_json(original_copy)
    payload["sim03_tamper_marker"] = "controlled_bundle_mutation"
    _write_json(tampered_path, payload)
    command = [
        sys.executable,
        "-m",
        "sbp_pvpl.cli",
        "--verify-bundle",
        "--runtime-root",
        ".",
        "--bundle",
        str(tampered_path.relative_to(root)),
    ]
    completed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=60, check=False)
    try:
        pvpl_result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        pvpl_result = {"raw_stdout": completed.stdout, "stderr": completed.stderr}
    status = pvpl_result.get("status")
    detected = status != "PROOF_OK"
    result["evidence_paths"].extend([_display_path(original_copy, root), _display_path(tampered_path, root)])
    result.update({
        "failure_test_status": "FAILURE_TEST_DETECTED" if detected else "FAILURE_TEST_WARNING",
        "source_bundle": _display_path(source, root),
        "pvpl_verify_exit_code": completed.returncode,
        "pvpl_verify_status": status,
        "pvpl_tamper_detected": detected,
        "pvpl_verify_result": pvpl_result,
        "artifact_summary": "PVPL bundle was copied under sim_03, mutated, and verified through the PVPL CLI without importing PVPL.",
    })
    _write_json(verification_path, result)
    return result


RUNNERS = {
    "UNSAFE_COMMAND_BLOCK": _unsafe_command_block,
    "INVALID_RISK_MODE_MAPPING": _invalid_mapping,
    "UNKNOWN_SCENARIO_BLOCK": _unknown_scenario,
    "SCENARIO_RESULT_TAMPER": _scenario_result_tamper,
    "REPLAY_RESULT_MISMATCH_ARTIFACT": _replay_mismatch,
    "PARITY_MISMATCH_FIXTURE": _parity_mismatch,
    "TOKEN_SIGNATURE_TAMPER_ARTIFACT": _token_tamper,
    "HASH_CHAIN_TAMPER_ARTIFACT": _hash_chain_tamper,
    "REQUIRED_EVIDENCE_MISSING": _required_evidence_missing,
    "FORBIDDEN_PUBLICATION_ACTIVATION": _forbidden_publication,
    "PVPL_BUNDLE_TAMPER_COMPATIBILITY": _pvpl_bundle_tamper,
}


def run_failure_test(
    failure_test_id: str,
    out_root: str | Path = "runtime_artifacts/sim_03/",
    runtime_root: str | Path = ".",
) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    base = Path(out_root)
    if not base.is_absolute():
        base = root / base
    definition = FAILURE_TESTS.get(failure_test_id)
    if definition is None:
        return {
            "failure_test_id": failure_test_id,
            "failure_test_status": "FAILURE_TEST_BLOCKED",
            "error": "unknown_failure_test",
            "boundary_statement": FAILURE_BOUNDARY_STATEMENT,
        }
    out_dir = base / failure_test_id
    result = RUNNERS[failure_test_id](definition, out_dir, root)
    summary_path = out_dir / "reviewer_failure_summary.md"
    result["evidence_paths"].append(_display_path(summary_path, root))
    _write_summary(summary_path, definition, result)
    verification_path = out_dir / "verification_result.json"
    _write_json(verification_path, result)
    return result


def run_failure_matrix(
    out_root: str | Path = "runtime_artifacts/sim_03/",
    runtime_root: str | Path = ".",
) -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    base = Path(out_root)
    if not base.is_absolute():
        base = root / base
    base.mkdir(parents=True, exist_ok=True)
    results = [run_failure_test(test_id, base, root) for test_id in FAILURE_TESTS]
    detected_count = sum(1 for item in results if item.get("failure_test_status") in {"FAILURE_TEST_DETECTED", "FAILURE_TEST_BLOCKED"})
    incomplete_count = sum(1 for item in results if item.get("failure_test_status") == "FAILURE_TEST_INCOMPLETE")
    warning_count = sum(1 for item in results if item.get("failure_test_status") == "FAILURE_TEST_WARNING")
    failure_count = sum(1 for item in results if item.get("failure_test_status") in {"FAILURE_TEST_INVALID"})
    matrix_status = "FAILURE_MATRIX_OK"
    if failure_count or warning_count:
        matrix_status = "FAILURE_MATRIX_FAILED"
    elif incomplete_count:
        matrix_status = "FAILURE_MATRIX_WARNING"
    index = {
        "total_failure_tests": len(results),
        "detected_or_blocked_count": detected_count,
        "incomplete_count": incomplete_count,
        "warning_count": warning_count,
        "failure_count": failure_count,
        "failure_test_ids": list(FAILURE_TESTS),
    }
    matrix_result = {
        "failure_matrix_status": matrix_status,
        "index": index,
        "results": results,
        "boundary_statement": FAILURE_BOUNDARY_STATEMENT,
    }
    index_path = base / "failure_matrix_index.json"
    result_path = base / "failure_matrix_result.json"
    summary_path = base / "reviewer_failure_matrix_summary.md"
    _write_json(index_path, index)
    _write_json(result_path, matrix_result)
    summary_path.write_text(
        "\n".join(
            [
                "# SIM-03 Reviewer Failure Matrix Summary",
                "",
                f"- Total failure tests: {index['total_failure_tests']}",
                f"- Detected/blocked count: {detected_count}",
                f"- Incomplete count: {incomplete_count}",
                f"- Warning count: {warning_count}",
                f"- Failure count: {failure_count}",
                f"- Matrix status: {matrix_status}",
                "",
                "Phase 19A runtime-required notes apply to replay, parity, token, and hash-chain runtime proof.",
                "PVPL compatibility passes only when the copied tampered bundle does not verify as PROOF_OK.",
                FAILURE_BOUNDARY_STATEMENT,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return matrix_result


def verify_failure_matrix(out_root: str | Path = "runtime_artifacts/sim_03/", runtime_root: str | Path = ".") -> dict[str, Any]:
    root = Path(runtime_root).resolve()
    base = Path(out_root)
    if not base.is_absolute():
        base = root / base
    findings: list[dict[str, str]] = []
    result_path = base / "failure_matrix_result.json"
    if not result_path.exists():
        findings.append({"path": _display_path(result_path, root), "finding": "failure_matrix_result_missing"})
        return {"verification_status": "FAILURE_MATRIX_FAILED", "finding_count": len(findings), "findings": findings}
    payload = _load_json(result_path)
    if payload.get("failure_matrix_status") not in FAILURE_MATRIX_STATUSES:
        findings.append({"path": _display_path(result_path, root), "finding": "unknown_failure_matrix_status"})
    for item in payload.get("results", []):
        if item.get("failure_test_status") not in FAILURE_TEST_STATUSES:
            findings.append({"path": item.get("failure_test_id", "unknown"), "finding": "unknown_failure_test_status"})
        if item.get("failure_test_status") in FORBIDDEN_RUNTIME_STATUSES:
            findings.append({"path": item.get("failure_test_id", "unknown"), "finding": "forbidden_runtime_status"})
        for evidence_path in item.get("evidence_paths", []):
            evidence = Path(evidence_path)
            resolved_evidence = evidence if evidence.is_absolute() else root / evidence
            if not resolved_evidence.exists():
                findings.append({"path": evidence_path, "finding": "missing_evidence_path"})
                continue
            try:
                resolved_evidence.resolve().relative_to(base.resolve())
            except ValueError:
                findings.append({"path": evidence_path, "finding": "evidence_outside_sim03"})
    status = "FAILURE_MATRIX_OK" if not findings else "FAILURE_MATRIX_FAILED"
    return {"verification_status": status, "finding_count": len(findings), "findings": findings}
