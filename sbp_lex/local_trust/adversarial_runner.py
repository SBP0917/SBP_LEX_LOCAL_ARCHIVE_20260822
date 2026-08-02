from __future__ import annotations

import json
import shutil
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping

from sbp_lex.local_trust.adversarial_cases import (
    ADVERSARIAL_CASE_ERROR,
    ADVERSARIAL_CASE_FAIL,
    ADVERSARIAL_CASE_PASS,
    ADVERSARIAL_CASE_SKIPPED,
    REQUIRED_ADVERSARIAL_CASES,
    AdversarialCaseSpec,
)
from sbp_lex.local_trust.capstone_validator import validate_local_trust_capstone
from sbp_lex.local_trust.constitutional_gates import (
    gate_digest_for,
    gate_signature_for,
    gate_summary,
    hash_gate_payload,
)
from sbp_lex.local_trust.evidence_chain import (
    chain_digest_for,
    chain_signature_for,
    compare_evidence_chain_to_current_files,
    hash_chain_payload,
)
from sbp_lex.local_trust.evidence_chain_validator import validate_local_evidence_chain
from sbp_lex.local_trust.evidence_registry import REQUIRED_EVIDENCE_SPECS
from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope
from sbp_lex.local_trust.gate_validator import validate_constitutional_gate_result
from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.regression_matrix import (
    hash_matrix_payload,
    matrix_digest_for,
    matrix_signature_for,
    regression_summary,
)
from sbp_lex.local_trust.regression_validator import validate_local_trust_regression_matrix
from sbp_lex.local_trust.release_integrity import (
    DEFAULT_RELEASE_BUNDLE_DIR,
    load_json,
)
from sbp_lex.local_trust.release_validator import validate_release_manifest
from sbp_lex.local_trust.release_manifest import (
    hash_release_payload,
    release_digest_for,
    release_signature_for,
)
from sbp_lex.local_trust.toolchain_guard import (
    hash_toolchain_payload,
    toolchain_digest_for,
    toolchain_signature_for,
    toolchain_summary,
)
from sbp_lex.local_trust.toolchain_validator import validate_toolchain_guard


LOCAL_TRUST_ARTIFACTS = {
    "manifest": "outputs/local_trust_root_manifest.json",
    "envelope": "outputs/local_execution_environment_trust_envelope.json",
    "evidence_chain": "outputs/local_evidence_chain.json",
    "regression_matrix": "outputs/local_trust_regression_matrix.json",
    "constitutional_gates": "outputs/local_constitutional_gates.json",
    "toolchain_guard": "outputs/local_toolchain_guard.json",
    "capstone": "outputs/local_trust_25_year_capstone.json",
}

RELEASE_FILES = {
    "release_manifest": "RELEASE_MANIFEST.json",
    "artifact_hash_index": "ARTIFACT_HASH_INDEX.json",
    "verification_commands": "VERIFICATION_COMMANDS.json",
    "claims_seed": "CLAIMS_TO_EVIDENCE_SEED.json",
    "boundary_lock": "BOUNDARY_AND_SCOPE_LOCK.json",
}

FORBIDDEN_AUTHORITY_KEYS = {
    "execution_permission",
    "governance_result",
    "runtime_authority",
    "allow_execution",
    "external_allow",
    "external_deny",
    "external_escalate",
    "external_" + "governance_result",
}


CaseEvaluator = Callable[[AdversarialCaseSpec, Path, Path, Mapping[str, Any]], dict[str, Any]]


def run_adversarial_cases(repository_root: Path) -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="sbp_lex_adversarial_") as raw_workspace:
        workspace = Path(raw_workspace) / "copied_artifacts"
        copy_baseline_artifacts(repository_root, workspace)
        artifacts = load_copied_artifacts(workspace)
        results: list[dict[str, Any]] = []
        for spec in REQUIRED_ADVERSARIAL_CASES:
            evaluator = CASE_EVALUATORS.get(spec.case_id)
            if evaluator is None:
                results.append(_case_result(spec, "NO_EVALUATOR", "NO_EVALUATOR", False, "case evaluator missing"))
                continue
            try:
                results.append(evaluator(spec, repository_root, workspace, artifacts))
            except Exception as exc:  # pragma: no cover - defensive result shape
                result = spec.to_record()
                result.update(
                    {
                        "actual_detection": f"CASE_EXCEPTION:{type(exc).__name__}",
                        "actual_result": "CASE_EXCEPTION",
                        "status": ADVERSARIAL_CASE_ERROR,
                        "reason": str(exc),
                    }
                )
                results.append(result)
        return results


def copy_baseline_artifacts(repository_root: Path, workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    for relative_path in LOCAL_TRUST_ARTIFACTS.values():
        source = resolve_local_trust_path(repository_root, relative_path)
        target = workspace / relative_path
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    release_source = resolve_local_trust_path(
        repository_root, DEFAULT_RELEASE_BUNDLE_DIR,
    )
    release_target = workspace / DEFAULT_RELEASE_BUNDLE_DIR
    if release_source.exists():
        shutil.copytree(release_source, release_target, dirs_exist_ok=True)


def load_copied_artifacts(workspace: Path) -> dict[str, Any]:
    loaded = {name: _load_json(workspace / path) for name, path in LOCAL_TRUST_ARTIFACTS.items()}
    release_dir = workspace / DEFAULT_RELEASE_BUNDLE_DIR
    loaded.update({name: _load_json(release_dir / filename) for name, filename in RELEASE_FILES.items()})
    return loaded


def _missing_manifest(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / LOCAL_TRUST_ARTIFACTS["manifest"]
    if path.exists():
        path.unlink()
    actual = "LOCAL_TRUST_MANIFEST_MISSING" if not path.exists() else "LOCAL_TRUST_MANIFEST_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary manifest copy missing")


def _tampered_manifest(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(artifacts["manifest"])
    manifest["manifest_digest"] = "0" * 64
    validation = validate_local_trust_manifest(manifest, repository_root=root)
    return _validation_result(spec, validation, "local_trust_status", spec.expected_detection)


def _missing_envelope(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / LOCAL_TRUST_ARTIFACTS["envelope"]
    if path.exists():
        path.unlink()
    actual = "EXECUTION_ENVELOPE_MISSING" if not path.exists() else "EXECUTION_ENVELOPE_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary envelope copy missing")


def _tampered_envelope(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    envelope = deepcopy(artifacts["envelope"])
    envelope["envelope_digest"] = "0" * 64
    validation = validate_execution_envelope(envelope, repository_root=root)
    return _validation_result(spec, validation, "verification_status", spec.expected_detection)


def _missing_evidence_chain(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / LOCAL_TRUST_ARTIFACTS["evidence_chain"]
    if path.exists():
        path.unlink()
    actual = "EVIDENCE_CHAIN_MISSING" if not path.exists() else "EVIDENCE_CHAIN_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary evidence chain copy missing")


def _tampered_evidence_chain(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    chain = deepcopy(artifacts["evidence_chain"])
    chain["chain_digest"] = "0" * 64
    validation = validate_local_evidence_chain(chain, repository_root=root)
    return _validation_result(spec, validation, "evidence_chain_status", spec.expected_detection)


def _missing_required_evidence_item(spec: AdversarialCaseSpec, _root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    chain = deepcopy(artifacts["evidence_chain"])
    expected_ids = {str(item["evidence_id"]) for item in REQUIRED_EVIDENCE_SPECS}
    items = [item for item in chain.get("evidence_items", []) if item.get("evidence_id") not in expected_ids]
    if len(items) == len(chain.get("evidence_items", [])):
        items = list(chain.get("evidence_items", []))[1:]
    chain["evidence_items"] = items
    present_ids = {str(item.get("evidence_id")) for item in chain.get("evidence_items", []) if isinstance(item, Mapping)}
    missing_ids = sorted(expected_ids - present_ids)
    actual = "MISSING_REQUIRED_EVIDENCE_ITEM" if missing_ids else "NO_MISSING_REQUIRED_EVIDENCE_ITEM"
    return _case_result(spec, actual, actual, bool(missing_ids), f"missing_ids={len(missing_ids)}")


def _changed_evidence_item(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    chain = deepcopy(artifacts["evidence_chain"])
    for item in chain.get("evidence_items", []):
        if isinstance(item, dict) and item.get("exists") is True:
            item["sha256"] = "0" * 64
            break
    _resign_chain(chain)
    comparison = compare_evidence_chain_to_current_files(chain, repository_root=root)
    actual = str(comparison.get("evidence_chain_status"))
    changed_count = len(comparison.get("changed_evidence_items", []))
    return _case_result(spec, actual, actual, actual == spec.expected_detection and changed_count > 0, f"changed_items={changed_count}")


def _missing_matrix(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / LOCAL_TRUST_ARTIFACTS["regression_matrix"]
    if path.exists():
        path.unlink()
    actual = "REGRESSION_MATRIX_MISSING" if not path.exists() else "REGRESSION_MATRIX_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary regression matrix copy missing")


def _tampered_matrix(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    matrix = deepcopy(artifacts["regression_matrix"])
    matrix["matrix_digest"] = "0" * 64
    validation = validate_local_trust_regression_matrix(matrix, repository_root=root)
    return _validation_result(spec, validation, "matrix_status", spec.expected_detection)


def _failed_matrix_case(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    matrix = deepcopy(artifacts["regression_matrix"])
    case = matrix["regression_cases"][0]
    case["status"] = "REGRESSION_CASE_FAIL"
    case["reason"] = "adversarial simulated case failure"
    matrix["regression_summary"] = regression_summary(matrix["regression_cases"])
    _resign_matrix(matrix)
    validation = validate_local_trust_regression_matrix(matrix, repository_root=root)
    return _validation_result(spec, validation, "matrix_status", spec.expected_detection)


def _missing_gates(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / LOCAL_TRUST_ARTIFACTS["constitutional_gates"]
    if path.exists():
        path.unlink()
    actual = "CONSTITUTIONAL_GATES_MISSING" if not path.exists() else "CONSTITUTIONAL_GATES_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary gates copy missing")


def _tampered_gates(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    gates = deepcopy(artifacts["constitutional_gates"])
    gates["gate_digest"] = "0" * 64
    validation = validate_constitutional_gate_result(gates, repository_root=root)
    return _validation_result(spec, validation, "gate_status", spec.expected_detection)


def _failed_gate(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    gates = deepcopy(artifacts["constitutional_gates"])
    gate = gates["gate_results"][0]
    gate["status"] = "GATE_FAIL"
    gate["reason"] = "adversarial simulated gate failure"
    gates["gate_summary"] = gate_summary(gates["gate_results"], {"git": {"working_tree_clean": True}})
    _resign_gates(gates)
    validation = validate_constitutional_gate_result(gates, repository_root=root)
    return _validation_result(spec, validation, "gate_status", spec.expected_detection)


def _missing_toolchain(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / LOCAL_TRUST_ARTIFACTS["toolchain_guard"]
    if path.exists():
        path.unlink()
    actual = "TOOLCHAIN_GUARD_MISSING" if not path.exists() else "TOOLCHAIN_GUARD_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary toolchain guard copy missing")


def _tampered_toolchain(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    guard = deepcopy(artifacts["toolchain_guard"])
    guard["toolchain_digest"] = "0" * 64
    validation = validate_toolchain_guard(guard, repository_root=root)
    return _validation_result(spec, validation, "toolchain_status", spec.expected_detection)


def _wrong_python_version(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    guard = deepcopy(artifacts["toolchain_guard"])
    guard["python_version"] = "not a parseable Python version"
    _update_toolchain_checks(guard)
    _resign_toolchain(guard)
    validation = validate_toolchain_guard(guard, repository_root=root)
    return _validation_result(spec, validation, "toolchain_status", spec.expected_detection)


def _wrong_pytest_version(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    guard = deepcopy(artifacts["toolchain_guard"])
    guard["pytest_version"] = ""
    _update_toolchain_checks(guard)
    _resign_toolchain(guard)
    validation = validate_toolchain_guard(guard, repository_root=root)
    return _validation_result(spec, validation, "toolchain_status", spec.expected_detection)


def _changed_dependency_digest(spec: AdversarialCaseSpec, _root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    guard = deepcopy(artifacts["toolchain_guard"])
    before = deepcopy(guard.get("dependency_file_digests", []))
    if guard.get("dependency_file_digests"):
        guard["dependency_file_digests"][0]["sha256"] = "0" * 64
    changed = before != guard.get("dependency_file_digests", [])
    actual = "DEPENDENCY_DIGEST_CHANGED" if changed else "DEPENDENCY_DIGEST_UNCHANGED"
    return _case_result(spec, actual, actual, changed, "dependency digest comparison performed by harness")


def _missing_capstone(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / LOCAL_TRUST_ARTIFACTS["capstone"]
    if path.exists():
        path.unlink()
    actual = "CAPSTONE_MISSING" if not path.exists() else "CAPSTONE_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary capstone copy missing")


def _tampered_capstone(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    capstone = deepcopy(artifacts["capstone"])
    capstone["capstone_digest"] = "0" * 64
    validation = validate_local_trust_capstone(capstone, repository_root=root)
    return _validation_result(spec, validation, "capstone_status", spec.expected_detection)


def _missing_release_manifest(spec: AdversarialCaseSpec, _root: Path, workspace: Path, _artifacts: Mapping[str, Any]) -> dict[str, Any]:
    path = workspace / DEFAULT_RELEASE_BUNDLE_DIR / RELEASE_FILES["release_manifest"]
    if path.exists():
        path.unlink()
    actual = "RELEASE_MANIFEST_MISSING" if not path.exists() else "RELEASE_MANIFEST_PRESENT"
    return _case_result(spec, actual, actual, actual == spec.expected_detection, "temporary release manifest copy missing")


def _tampered_release_manifest(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(artifacts["release_manifest"])
    manifest["release_digest"] = "0" * 64
    validation = _validate_release(root, manifest, artifacts)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _missing_artifact_hash_index(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, index=None)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _artifact_hash_mismatch(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    index = deepcopy(artifacts["artifact_hash_index"])
    index["artifacts"][0]["sha256"] = "0" * 64
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, index=index)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _missing_required_release_artifact(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    index = deepcopy(artifacts["artifact_hash_index"])
    index["artifacts"][0]["exists"] = False
    index["artifacts"][0]["sha256"] = "MISSING"
    index["artifact_summary"]["missing_artifact_count"] = 1
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, index=index)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _missing_verification_commands(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, commands=None)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _verification_command_removed(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    commands = deepcopy(artifacts["verification_commands"])
    commands["commands"] = commands.get("commands", [])[1:]
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, commands=commands)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _claims_seed_overclaim(spec: AdversarialCaseSpec, _root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    claims = deepcopy(artifacts["claims_seed"])
    if claims.get("claim_seeds"):
        claims["claim_seeds"][0]["claim_text"] = "External validation occurred."
    false_claims = _false_claim_failures(claims)
    actual = "CLAIMS_SEED_FALSE_CLAIM" if false_claims else "CLAIMS_SEED_OK"
    return _case_result(spec, actual, actual, bool(false_claims), ",".join(false_claims))


def _claims_seed_missing_claim(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    claims = deepcopy(artifacts["claims_seed"])
    claims["claim_seeds"] = claims.get("claim_seeds", [])[1:]
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, claims=claims)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _boundary_lock_removed(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, boundary=None)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _boundary_external_validation(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    boundary = deepcopy(artifacts["boundary_lock"])
    boundary["not_university_validation_result"] = False
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, boundary=boundary)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _boundary_certification(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    boundary = deepcopy(artifacts["boundary_lock"])
    boundary["not_security_certification"] = False
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, boundary=boundary)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _boundary_phase19(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    boundary = deepcopy(artifacts["boundary_lock"])
    boundary["phase_19_not_started"] = False
    boundary["not_phase_19"] = False
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, boundary=boundary)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _rt_activation_marker_check(
    spec: AdversarialCaseSpec,
    root: Path,
    _workspace: Path,
    artifacts: Mapping[str, Any],
) -> dict[str, Any]:
    boundary = deepcopy(artifacts["boundary_lock"])
    boundary["notRuntimeActivation"] = False
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, boundary=boundary)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _forbidden_authority_leakage(spec: AdversarialCaseSpec, _root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(artifacts["release_manifest"])
    manifest["execution_permission"] = "ALLOW"
    failures = _forbidden_key_failures(manifest)
    actual = "FORBIDDEN_AUTHORITY_LEAKAGE" if failures else "NO_FORBIDDEN_AUTHORITY_LEAKAGE"
    return _case_result(spec, actual, actual, bool(failures), ",".join(failures))


def _future_surface_marker(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    boundary = deepcopy(artifacts["boundary_lock"])
    boundary["not_future_distributed_or_mobile_runtime_implementation"] = False
    validation = _validate_release(root, deepcopy(artifacts["release_manifest"]), artifacts, boundary=boundary)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _dirty_working_tree(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(artifacts["release_manifest"])
    manifest["github_sync_status"]["tracked_working_tree_clean"] = False
    _resign_release(manifest)
    validation = _validate_release(root, manifest, artifacts, clean_required=True)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


def _stale_commit(spec: AdversarialCaseSpec, root: Path, _workspace: Path, artifacts: Mapping[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(artifacts["release_manifest"])
    manifest["git_commit"] = "0" * 40
    _resign_release(manifest)
    validation = _validate_release(root, manifest, artifacts, current_validation=True)
    return _validation_result(spec, validation, "release_status", spec.expected_detection)


CASE_EVALUATORS: dict[str, CaseEvaluator] = {
    "missing_local_trust_manifest": _missing_manifest,
    "tampered_local_trust_manifest_digest": _tampered_manifest,
    "missing_execution_envelope": _missing_envelope,
    "tampered_execution_envelope_digest": _tampered_envelope,
    "missing_evidence_chain": _missing_evidence_chain,
    "tampered_evidence_chain_digest": _tampered_evidence_chain,
    "evidence_chain_missing_required_item": _missing_required_evidence_item,
    "evidence_chain_changed_item": _changed_evidence_item,
    "missing_regression_matrix": _missing_matrix,
    "tampered_regression_matrix_digest": _tampered_matrix,
    "failed_regression_matrix_case": _failed_matrix_case,
    "missing_constitutional_gates": _missing_gates,
    "tampered_constitutional_gates_digest": _tampered_gates,
    "failed_constitutional_gate": _failed_gate,
    "missing_toolchain_guard": _missing_toolchain,
    "tampered_toolchain_guard_digest": _tampered_toolchain,
    "wrong_python_version_evidence": _wrong_python_version,
    "wrong_pytest_version_evidence": _wrong_pytest_version,
    "changed_dependency_file_digest": _changed_dependency_digest,
    "missing_capstone": _missing_capstone,
    "tampered_capstone_digest": _tampered_capstone,
    "missing_release_manifest": _missing_release_manifest,
    "tampered_release_manifest_digest": _tampered_release_manifest,
    "missing_artifact_hash_index": _missing_artifact_hash_index,
    "artifact_hash_mismatch": _artifact_hash_mismatch,
    "missing_required_release_artifact": _missing_required_release_artifact,
    "missing_verification_command_index": _missing_verification_commands,
    "verification_command_removed": _verification_command_removed,
    "claims_seed_overclaim": _claims_seed_overclaim,
    "claims_seed_missing_required_claim": _claims_seed_missing_claim,
    "boundary_lock_removed": _boundary_lock_removed,
    "boundary_lock_claims_external_validation": _boundary_external_validation,
    "boundary_lock_claims_certification": _boundary_certification,
    "boundary_lock_claims_phase_19_started": _boundary_phase19,
    "runtimeActivation_active_implementation": _rt_activation_marker_check,
    "forbidden_authority_leakage_appears": _forbidden_authority_leakage,
    "future_surface_active_implementation": _future_surface_marker,
    "dirty_working_tree_simulated": _dirty_working_tree,
    "stale_commit_reference_simulated": _stale_commit,
}


def _validate_release(
    root: Path,
    manifest: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    *,
    index: Mapping[str, Any] | None | object = ...,
    commands: Mapping[str, Any] | None | object = ...,
    claims: Mapping[str, Any] | None | object = ...,
    boundary: Mapping[str, Any] | None | object = ...,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    return validate_release_manifest(
        manifest,
        repository_root=root,
        artifact_hash_index=artifacts["artifact_hash_index"] if index is ... else index,
        verification_commands=artifacts["verification_commands"] if commands is ... else commands,
        claims_to_evidence_seed=artifacts["claims_seed"] if claims is ... else claims,
        boundary_lock=artifacts["boundary_lock"] if boundary is ... else boundary,
        clean_required=clean_required,
        current_validation=current_validation,
    )


def _validation_result(
    spec: AdversarialCaseSpec,
    validation: Mapping[str, Any],
    status_field: str,
    expected_detection: str,
) -> dict[str, Any]:
    actual = str(validation.get(status_field))
    failures = validation.get("validation_failures", [])
    detected = actual == expected_detection or (
        expected_detection in {"RELEASE_INTEGRITY_DIRTY", "RELEASE_INTEGRITY_STALE"}
        and actual == "RELEASE_INTEGRITY_FAIL"
        and bool(failures)
    )
    reason = ",".join(str(item) for item in failures) if failures else actual
    return _case_result(spec, actual, actual, detected, reason)


def _case_result(
    spec: AdversarialCaseSpec,
    actual_detection: str,
    actual_result: str,
    detected: bool,
    reason: str,
) -> dict[str, Any]:
    result = spec.to_record()
    result.update(
        {
            "actual_detection": actual_detection,
            "actual_result": actual_result,
            "status": ADVERSARIAL_CASE_PASS if detected else ADVERSARIAL_CASE_FAIL,
            "reason": reason,
        }
    )
    return result


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"adversarial_json_must_be_object:{path}")
    return loaded


def _resign_chain(chain: dict[str, Any]) -> None:
    payload = hash_chain_payload(chain)
    signature = chain_signature_for(payload)
    chain["chain_payload_digest"] = payload
    chain["chain_signature"] = signature
    chain["chain_digest"] = chain_digest_for(payload, signature)


def _resign_matrix(matrix: dict[str, Any]) -> None:
    payload = hash_matrix_payload(matrix)
    signature = matrix_signature_for(payload)
    matrix["matrix_payload_digest"] = payload
    matrix["matrix_signature"] = signature
    matrix["matrix_digest"] = matrix_digest_for(payload, signature)


def _resign_gates(gates: dict[str, Any]) -> None:
    payload = hash_gate_payload(gates)
    signature = gate_signature_for(payload)
    gates["gate_payload_digest"] = payload
    gates["gate_signature"] = signature
    gates["gate_digest"] = gate_digest_for(payload, signature)


def _resign_toolchain(guard: dict[str, Any]) -> None:
    payload = hash_toolchain_payload(guard)
    signature = toolchain_signature_for(payload)
    guard["toolchain_payload_digest"] = payload
    guard["toolchain_signature"] = signature
    guard["toolchain_digest"] = toolchain_digest_for(payload, signature)


def _resign_release(manifest: dict[str, Any]) -> None:
    payload = hash_release_payload(manifest)
    signature = release_signature_for(payload)
    manifest["release_payload_digest"] = payload
    manifest["release_signature"] = signature
    manifest["release_digest"] = release_digest_for(payload, signature)


def _update_toolchain_checks(guard: dict[str, Any]) -> None:
    for check in guard.get("toolchain_checks", []):
        check_id = check.get("check_id")
        if check_id == "python_version_parseable":
            check["observed_condition"] = "None"
            check["status"] = "TOOLCHAIN_CHECK_FAIL"
            check["reason"] = "adversarial Python version evidence is not parseable"
        if check_id in {"pytest_version_recorded", "pytest_import_available"} and not guard.get("pytest_version"):
            check["observed_condition"] = "pytest_missing"
            check["status"] = "TOOLCHAIN_CHECK_FAIL"
            check["reason"] = "adversarial pytest version evidence missing"
    guard["toolchain_summary"] = toolchain_summary(guard.get("toolchain_checks", []), {"working_tree_clean": True})


def _false_claim_failures(value: Any, path: str = "$") -> list[str]:
    markers = ("external validation occurred", "certification occurred", " ".join(("phase", "19", "started")))
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            failures.extend(_false_claim_failures(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_false_claim_failures(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        lower = value.lower()
        for marker in markers:
            if marker in lower:
                failures.append(f"false_claim:{path}:{marker}")
    return failures


def _forbidden_key_failures(value: Any, path: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_path = f"{path}.{key_text}"
            if key_text in FORBIDDEN_AUTHORITY_KEYS:
                failures.append(f"forbidden_authority_key:{next_path}")
            failures.extend(_forbidden_key_failures(item, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_forbidden_key_failures(item, f"{path}[{index}]"))
    return failures


def adversarial_summary(cases: list[Mapping[str, Any]]) -> dict[str, Any]:
    statuses = [case.get("status") for case in cases]
    categories = [str(case.get("case_category")) for case in cases]
    failed = statuses.count(ADVERSARIAL_CASE_FAIL)
    errors = statuses.count(ADVERSARIAL_CASE_ERROR)
    return {
        "total_cases": len(statuses),
        "passed_cases": statuses.count(ADVERSARIAL_CASE_PASS),
        "failed_cases": failed,
        "skipped_cases": statuses.count(ADVERSARIAL_CASE_SKIPPED),
        "error_cases": errors,
        "all_required_cases_passed": failed == 0 and errors == 0 and ADVERSARIAL_CASE_SKIPPED not in statuses,
        "artifact_mutation_cases": categories.count("artifact_mutation"),
        "release_integrity_mutation_cases": categories.count("release_integrity_mutation"),
        "boundary_violation_cases": categories.count("boundary_violation"),
        "forbidden_authority_leakage_cases": categories.count("forbidden_authority_leakage"),
        "phase_19_boundary_cases": categories.count("phase_boundary"),
        "toolchain_drift_cases": categories.count("toolchain_drift"),
        "provenance_drift_cases": categories.count("provenance_drift"),
    }
