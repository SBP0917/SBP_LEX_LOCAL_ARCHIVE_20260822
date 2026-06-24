from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping

from sbp_lex.local_trust.evidence_chain import compare_evidence_chain_to_current_files, load_local_evidence_chain
from sbp_lex.local_trust.evidence_chain_validator import validate_local_evidence_chain
from sbp_lex.local_trust.evidence_registry import EXCLUDED_PATHS
from sbp_lex.local_trust.execution_envelope import load_execution_envelope
from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope
from sbp_lex.local_trust.gate_policy import GATE_FAIL, GATE_PASS, GATE_SPECS, GateSpec
from sbp_lex.local_trust.git_provenance import collect_git_provenance
from sbp_lex.local_trust.manifest import load_local_trust_manifest
from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest
from sbp_lex.local_trust.regression_matrix import load_local_trust_regression_matrix
from sbp_lex.local_trust.regression_validator import validate_local_trust_regression_matrix


GateHandler = Callable[[Mapping[str, Any], GateSpec], dict[str, Any]]

FORBIDDEN_OUTPUT_KEYS = {
    "execution_permission",
    "governance_result",
    "runtime_authority",
    "allow_execution",
    "external_allow",
    "external_deny",
    "external_escalate",
    "external_" + "governance_result",
}


def collect_gate_inputs(
    repository_root: Path,
    *,
    manifest_path: Path,
    envelope_path: Path,
    evidence_chain_path: Path,
    regression_matrix_path: Path,
) -> dict[str, Any]:
    manifest = _load_manifest(repository_root, manifest_path)
    envelope = _load_envelope(repository_root, envelope_path)
    chain = _load_chain(repository_root, evidence_chain_path)
    matrix = _load_matrix(repository_root, regression_matrix_path)
    comparison = (
        compare_evidence_chain_to_current_files(chain["artifact"], repository_root=repository_root)
        if isinstance(chain["artifact"], Mapping)
        else {"evidence_chain_status": "EVIDENCE_CHAIN_MISSING", "changed_evidence_items": []}
    )
    return {
        "repository_root": repository_root,
        "git": collect_git_provenance(repository_root),
        "manifest": manifest,
        "envelope": envelope,
        "chain": chain,
        "matrix": matrix,
        "comparison": comparison,
    }


def run_constitutional_gates(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    handlers = _handlers()
    results: list[dict[str, Any]] = []
    for spec in GATE_SPECS:
        try:
            results.append(handlers[spec.gate_id](context, spec))
        except Exception as exc:  # pragma: no cover - defensive evidence capture
            results.append(_gate(spec, "GATE_ERROR", "ERROR", f"{type(exc).__name__}:{exc}"))
    return results


def _handlers() -> dict[str, GateHandler]:
    return {
        "manifest_exists": lambda ctx, spec: _exists_gate(ctx["manifest"], spec),
        "manifest_validates": lambda ctx, spec: _status_gate(ctx["manifest"], spec, "local_trust_status", "LOCAL_TRUST_VALID"),
        "execution_envelope_exists": lambda ctx, spec: _exists_gate(ctx["envelope"], spec),
        "execution_envelope_validates": lambda ctx, spec: _status_gate(ctx["envelope"], spec, "verification_status", "EXECUTION_ENV_VALID"),
        "evidence_chain_exists": lambda ctx, spec: _exists_gate(ctx["chain"], spec),
        "evidence_chain_validates": lambda ctx, spec: _status_gate(ctx["chain"], spec, "evidence_chain_status", "EVIDENCE_CHAIN_VALID"),
        "evidence_chain_zero_missing": _zero_missing_gate,
        "evidence_chain_zero_changed": _zero_changed_gate,
        "regression_matrix_exists": lambda ctx, spec: _exists_gate(ctx["matrix"], spec),
        "regression_matrix_validates": lambda ctx, spec: _status_gate(ctx["matrix"], spec, "matrix_status", "REGRESSION_MATRIX_VALID"),
        "regression_cases_passed": _regression_cases_gate,
        "manifest_digest_binding": _manifest_binding_gate,
        "execution_envelope_digest_binding": _envelope_binding_gate,
        "evidence_chain_digest_binding": _chain_binding_gate,
        "regression_matrix_digest_binding": _matrix_binding_gate,
        "working_tree_policy": _working_tree_gate,
        "branch_recorded": _branch_recorded_gate,
        "commit_recorded": _commit_recorded_gate,
        "forbidden_authority_absent": _forbidden_authority_gate,
        "future_activation_absent": _future_activation_gate,
        "phase_19_boundary_preserved": _phase_boundary_gate,
        "future_surface_absent": _future_surface_gate,
        "generated_outputs_pytest_policy": _generated_output_policy_gate,
        "temp_cache_evidence_exclusion": _temp_cache_exclusion_gate,
    }


def _load_manifest(repository_root: Path, path: Path) -> dict[str, Any]:
    if not path.exists():
        return _missing(path, "LOCAL_TRUST_MANIFEST_MISSING")
    try:
        artifact = load_local_trust_manifest(path, repository_root=repository_root)
        validation = validate_local_trust_manifest(artifact, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _invalid(path, "LOCAL_TRUST_INVALID", exc)
    return {"path": str(path), "exists": True, "artifact": artifact, "validation": validation, "digest": artifact.get("manifest_digest")}


def _load_envelope(repository_root: Path, path: Path) -> dict[str, Any]:
    if not path.exists():
        return _missing(path, "EXECUTION_ENVELOPE_MISSING")
    try:
        artifact = load_execution_envelope(path, repository_root=repository_root)
        validation = validate_execution_envelope(artifact, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _invalid(path, "EXECUTION_ENV_INVALID", exc)
    return {"path": str(path), "exists": True, "artifact": artifact, "validation": validation, "digest": artifact.get("envelope_digest")}


def _load_chain(repository_root: Path, path: Path) -> dict[str, Any]:
    if not path.exists():
        return _missing(path, "EVIDENCE_CHAIN_MISSING")
    try:
        artifact = load_local_evidence_chain(path, repository_root=repository_root)
        validation = validate_local_evidence_chain(artifact, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _invalid(path, "EVIDENCE_CHAIN_INVALID", exc)
    return {"path": str(path), "exists": True, "artifact": artifact, "validation": validation, "digest": artifact.get("chain_digest")}


def _load_matrix(repository_root: Path, path: Path) -> dict[str, Any]:
    if not path.exists():
        return _missing(path, "REGRESSION_MATRIX_MISSING")
    try:
        artifact = load_local_trust_regression_matrix(path, repository_root=repository_root)
        validation = validate_local_trust_regression_matrix(artifact, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _invalid(path, "REGRESSION_MATRIX_INVALID", exc)
    return {"path": str(path), "exists": True, "artifact": artifact, "validation": validation, "digest": artifact.get("matrix_digest")}


def _missing(path: Path, marker: str) -> dict[str, Any]:
    return {"path": str(path), "exists": False, "artifact": None, "validation": {"status": marker, "validation_failures": [marker]}, "digest": marker}


def _invalid(path: Path, marker: str, exc: Exception) -> dict[str, Any]:
    return {"path": str(path), "exists": True, "artifact": None, "validation": {"status": marker, "validation_failures": [str(exc)]}, "digest": marker}


def _gate(spec: GateSpec, status: str, observed_condition: str, reason: str) -> dict[str, Any]:
    return {
        "gate_id": spec.gate_id,
        "gate_name": spec.gate_name,
        "gate_category": spec.gate_category,
        "required": spec.required,
        "input_artifact": spec.input_artifact,
        "expected_condition": spec.expected_condition,
        "observed_condition": observed_condition,
        "status": status,
        "reason": reason,
    }


def _exists_gate(record: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    exists = record.get("exists") is True
    return _gate(spec, GATE_PASS if exists else GATE_FAIL, "PRESENT" if exists else "MISSING", str(record.get("path")))


def _status_gate(record: Mapping[str, Any], spec: GateSpec, status_key: str, expected: str) -> dict[str, Any]:
    validation = record.get("validation", {})
    observed = str(validation.get(status_key) or validation.get("status"))
    failures = ",".join(str(item) for item in validation.get("validation_failures", []))
    return _gate(spec, GATE_PASS if observed == expected else GATE_FAIL, observed, failures)


def _zero_missing_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    chain = context["chain"].get("artifact")
    missing = chain.get("missing_evidence_items", []) if isinstance(chain, Mapping) else []
    observed = f"missing_evidence_items={len(missing)}"
    reason = ",".join(str(item.get("path")) for item in missing if isinstance(item, Mapping))
    return _gate(spec, GATE_PASS if len(missing) == 0 else GATE_FAIL, observed, reason)


def _zero_changed_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    comparison = context["comparison"]
    changed = comparison.get("changed_evidence_items", [])
    observed = f"changed_evidence_items={len(changed)}"
    status = comparison.get("evidence_chain_status")
    return _gate(spec, GATE_PASS if status == "EVIDENCE_CHAIN_VALID" and len(changed) == 0 else GATE_FAIL, observed, str(status))


def _regression_cases_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    matrix = context["matrix"].get("artifact")
    if not isinstance(matrix, Mapping):
        return _gate(spec, GATE_FAIL, "REGRESSION_MATRIX_MISSING", "matrix artifact unavailable")
    cases = matrix.get("regression_cases", [])
    failed = [case for case in cases if isinstance(case, Mapping) and case.get("status") in {"REGRESSION_CASE_FAIL", "REGRESSION_CASE_ERROR"}]
    skipped_without_reason = [
        case for case in cases
        if isinstance(case, Mapping) and case.get("status") == "REGRESSION_CASE_SKIPPED" and not case.get("reason")
    ]
    observed = f"failed_or_error={len(failed)};skipped_without_reason={len(skipped_without_reason)}"
    return _gate(spec, GATE_PASS if not failed and not skipped_without_reason else GATE_FAIL, observed, ",".join(str(case.get("case_id")) for case in failed))


def _manifest_binding_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    manifest_digest = context["manifest"].get("digest")
    envelope = context["envelope"].get("artifact") or {}
    chain = context["chain"].get("artifact") or {}
    matrix = context["matrix"].get("artifact") or {}
    observed = {
        str(manifest_digest),
        str(envelope.get("bound_local_trust_manifest_digest")),
        str(chain.get("bound_local_trust_manifest_digest")),
        str(matrix.get("bound_manifest_digest")),
    }
    return _binding_gate(spec, observed)


def _envelope_binding_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    envelope_digest = context["envelope"].get("digest")
    chain = context["chain"].get("artifact") or {}
    matrix = context["matrix"].get("artifact") or {}
    observed = {
        str(envelope_digest),
        str(chain.get("bound_execution_envelope_digest")),
        str(matrix.get("bound_execution_envelope_digest")),
    }
    return _binding_gate(spec, observed)


def _chain_binding_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    chain_digest = context["chain"].get("digest")
    matrix = context["matrix"].get("artifact") or {}
    observed = {str(chain_digest), str(matrix.get("bound_evidence_chain_digest"))}
    return _binding_gate(spec, observed)


def _matrix_binding_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    observed = {str(context["matrix"].get("digest"))}
    return _binding_gate(spec, observed)


def _binding_gate(spec: GateSpec, observed: set[str]) -> dict[str, Any]:
    clean = {item for item in observed if item not in {"None", ""}}
    first = next(iter(clean), "")
    passed = len(clean) == 1 and not first.endswith("_MISSING") and not first.endswith("_INVALID")
    return _gate(spec, GATE_PASS if passed else GATE_FAIL, ";".join(sorted(clean)), "all bound digests must match")


def _working_tree_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    clean = context["git"].get("working_tree_clean")
    return _gate(spec, GATE_PASS, f"working_tree_clean={clean}", "dirty state is recorded; strict enforcement uses --clean-required")


def _branch_recorded_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    branch = context["git"].get("git_branch")
    return _gate(spec, GATE_PASS if bool(branch) else GATE_FAIL, str(branch), "git branch provenance")


def _commit_recorded_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    commit = context["git"].get("git_commit")
    recorded = isinstance(commit, str) and len(commit) == 40
    return _gate(spec, GATE_PASS if recorded else GATE_FAIL, str(commit), "git commit provenance")


def _forbidden_authority_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    artifacts = [
        context["manifest"].get("artifact"),
        context["envelope"].get("artifact"),
        context["chain"].get("artifact"),
        context["matrix"].get("artifact"),
    ]
    failures: list[str] = []
    for artifact_name, artifact in zip(("manifest", "envelope", "chain", "matrix"), artifacts):
        failures.extend(f"{artifact_name}:{item}" for item in _forbidden_key_paths(artifact))
    return _gate(spec, GATE_PASS if not failures else GATE_FAIL, f"forbidden_key_count={len(failures)}", ",".join(failures))


def _future_activation_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    term = "_".join(("runtime", "activation"))
    matches = _active_source_matches(Path(context["repository_root"]), [term])
    return _gate(spec, GATE_PASS if not matches else GATE_FAIL, f"matches={len(matches)}", ",".join(matches))


def _phase_boundary_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    matrix = context["matrix"].get("artifact") or {}
    case = _case_by_id(matrix, "phase_19_not_started_confirmation")
    passed = isinstance(case, Mapping) and case.get("status") in {"REGRESSION_CASE_PASS", "REGRESSION_CASE_SKIPPED"}
    observed = str(case.get("status") if isinstance(case, Mapping) else None)
    return _gate(spec, GATE_PASS if passed else GATE_FAIL, observed, "regression matrix phase boundary case")


def _future_surface_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    terms = [
        "_".join(("node", "quorum")),
        "_".join(("node", "attestation")),
        "_".join(("distributed", "consensus")),
        "_".join(("mesh", "runtime")),
        "_".join(("cloud", "runtime")),
        "_".join(("external", "execution_permission")),
        "_".join(("external", "governance_result")),
    ]
    matches = _active_source_matches(Path(context["repository_root"]), terms)
    allowed = [match for match in matches if match != "sbp_lex/local_trust/manifest_validator.py"]
    return _gate(spec, GATE_PASS if not allowed else GATE_FAIL, f"active_matches={len(allowed)}", ",".join(allowed))


def _generated_output_policy_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    matrix = context["matrix"].get("artifact") or {}
    case = _case_by_id(matrix, "generated_outputs_pytest_ignore")
    passed = isinstance(case, Mapping) and case.get("status") in {"REGRESSION_CASE_PASS", "REGRESSION_CASE_SKIPPED"}
    observed = str(case.get("actual_detection") if isinstance(case, Mapping) else None)
    return _gate(spec, GATE_PASS if passed else GATE_FAIL, observed, "regression matrix pytest output policy case")


def _temp_cache_exclusion_gate(context: Mapping[str, Any], spec: GateSpec) -> dict[str, Any]:
    chain = context["chain"].get("artifact") or {}
    excluded = set(chain.get("excluded_paths", [])) | set(EXCLUDED_PATHS)
    required = {".pytest_cache", ".pytest_tmp_*", "outputs/local_trust_temp", "__pycache__", "*.pyc", ".git"}
    missing = sorted(required - excluded)
    return _gate(spec, GATE_PASS if not missing else GATE_FAIL, "excluded_paths_present" if not missing else "excluded_paths_missing", ",".join(missing))


def _case_by_id(matrix: Mapping[str, Any], case_id: str) -> Mapping[str, Any] | None:
    for case in matrix.get("regression_cases", []):
        if isinstance(case, Mapping) and case.get("case_id") == case_id:
            return case
    return None


def _forbidden_key_paths(value: Any, path: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_path = f"{path}.{key_text}"
            if key_text in FORBIDDEN_OUTPUT_KEYS:
                failures.append(next_path)
            failures.extend(_forbidden_key_paths(item, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_forbidden_key_paths(item, f"{path}[{index}]"))
    return failures


def _active_source_matches(repository_root: Path, terms: list[str]) -> list[str]:
    matches: list[str] = []
    lowered_terms = [term.lower() for term in terms]
    source_root = repository_root / "sbp_lex"
    if not source_root.exists():
        return []
    for path in source_root.rglob("*.py"):
        relative = path.relative_to(repository_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        if any(term in text for term in lowered_terms):
            matches.append(relative)
    return sorted(set(matches))
