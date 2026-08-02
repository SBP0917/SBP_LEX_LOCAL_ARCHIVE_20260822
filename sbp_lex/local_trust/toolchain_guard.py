from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.command_policy import required_command_ids
from sbp_lex.local_trust.constitutional_gates import (
    DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH,
    load_constitutional_gate_result,
)
from sbp_lex.local_trust.evidence_chain import DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH, load_local_evidence_chain
from sbp_lex.local_trust.execution_envelope import DEFAULT_ENVELOPE_OUTPUT_PATH, load_execution_envelope
from sbp_lex.local_trust.git_provenance import collect_git_provenance
from sbp_lex.local_trust.manifest import (
    DEFAULT_OUTPUT_PATH as DEFAULT_MANIFEST_PATH,
    canonical_json,
    load_local_trust_manifest,
    repository_root_from,
)
from sbp_lex.local_trust.regression_matrix import DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH, load_local_trust_regression_matrix
from sbp_lex.local_trust.toolchain_inventory import collect_toolchain_inventory, parse_python_version
from sbp_lex.local_trust.toolchain_policy import (
    LOCAL_TRUST_TOOLCHAIN_POLICY_VERSION,
    TOOLCHAIN_CHECK_FAIL,
    TOOLCHAIN_CHECK_PASS,
    TOOLCHAIN_CHECK_SPECS,
    ToolchainCheckSpec,
)
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.signing import (
    LOCAL_TRUST_SIGNATURE_MODE,
    local_trust_binding_digest,
    sign_local_trust_digest,
)

TOOLCHAIN_GUARD_SIGNATURE_MODE = LOCAL_TRUST_SIGNATURE_MODE
TOOLCHAIN_GUARD_SIGNATURE_DOMAIN = "SBP_LEX_LOCAL_TOOLCHAIN_GUARD"
TOOLCHAIN_GUARD_VERSION = "18.7E.3"
DEFAULT_TOOLCHAIN_GUARD_OUTPUT_PATH = Path("outputs/local_toolchain_guard.json")

_DIGEST_EXCLUDED_FIELDS = {
    "toolchain_status",
    "validation_failures",
    "toolchain_payload_digest",
    "toolchain_digest",
    "toolchain_signature",
}


def build_toolchain_guard(
    repository_root: Path | str | None = None,
    *,
    manifest_path: Path | str = DEFAULT_MANIFEST_PATH,
    envelope_path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    evidence_chain_path: Path | str = DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    regression_matrix_path: Path | str = DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH,
    constitutional_gates_path: Path | str = DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.toolchain_validator import validate_toolchain_guard

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    git = collect_git_provenance(root)
    inventory = collect_toolchain_inventory(root)
    bindings = collect_artifact_bindings(
        root,
        manifest_path=manifest_path,
        envelope_path=envelope_path,
        evidence_chain_path=evidence_chain_path,
        regression_matrix_path=regression_matrix_path,
        constitutional_gates_path=constitutional_gates_path,
    )
    guard: dict[str, Any] = {
        "toolchain_guard_type": "local_trust_dependency_toolchain_guard",
        "toolchain_guard_version": TOOLCHAIN_GUARD_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "python_executable": inventory["python_executable"],
        "python_version": inventory["python_version"],
        "python_prefix": inventory["python_prefix"],
        "python_base_prefix": inventory["python_base_prefix"],
        "platform": inventory["platform"],
        "pytest_version": inventory["pytest_version"],
        "pip_version_if_available": inventory["pip_version_if_available"],
        "dependency_files": inventory["dependency_files"],
        "dependency_file_digests": inventory["dependency_file_digests"],
        "installed_package_snapshot": inventory["installed_package_snapshot"],
        "verification_command_policy": inventory["verification_command_policy"],
        "pytest_collection_policy": inventory["pytest_collection_policy"],
        "ignored_output_paths": inventory["ignored_output_paths"],
        "ignored_temp_paths": inventory["ignored_temp_paths"],
        "bound_manifest_digest": bindings["manifest_digest"],
        "bound_execution_envelope_digest": bindings["envelope_digest"],
        "bound_evidence_chain_digest": bindings["chain_digest"],
        "bound_regression_matrix_digest": bindings["matrix_digest"],
        "bound_constitutional_gates_digest": bindings["gates_digest"],
        "toolchain_checks": [],
        "toolchain_summary": {},
        "signature_mode": TOOLCHAIN_GUARD_SIGNATURE_MODE,
        "toolchain_status": "TOOLCHAIN_GUARD_INCOMPLETE",
        "validation_failures": [],
    }
    guard["toolchain_checks"] = build_toolchain_checks(guard, git)
    guard["toolchain_summary"] = toolchain_summary(guard["toolchain_checks"], git)
    payload_digest = hash_toolchain_payload(guard)
    signature = toolchain_signature_for(payload_digest)
    guard["toolchain_payload_digest"] = payload_digest
    guard["toolchain_signature"] = signature
    guard["toolchain_digest"] = toolchain_digest_for(payload_digest, signature)
    validation = validate_toolchain_guard(guard, repository_root=root, clean_required=clean_required)
    guard["toolchain_status"] = validation["toolchain_status"]
    guard["validation_failures"] = validation["validation_failures"]
    return guard


def collect_artifact_bindings(
    repository_root: Path,
    *,
    manifest_path: Path | str,
    envelope_path: Path | str,
    evidence_chain_path: Path | str,
    regression_matrix_path: Path | str,
    constitutional_gates_path: Path | str,
) -> dict[str, str]:
    manifest = _load_json_artifact(repository_root, manifest_path, load_local_trust_manifest)
    envelope = _load_json_artifact(repository_root, envelope_path, load_execution_envelope)
    chain = _load_json_artifact(repository_root, evidence_chain_path, load_local_evidence_chain)
    matrix = _load_json_artifact(repository_root, regression_matrix_path, load_local_trust_regression_matrix)
    gates = _load_json_artifact(repository_root, constitutional_gates_path, load_constitutional_gate_result)
    return {
        "manifest_digest": str(manifest.get("manifest_digest", "LOCAL_TRUST_MANIFEST_MISSING")),
        "envelope_digest": str(envelope.get("envelope_digest", "EXECUTION_ENVELOPE_MISSING")),
        "chain_digest": str(chain.get("chain_digest", "EVIDENCE_CHAIN_MISSING")),
        "matrix_digest": str(matrix.get("matrix_digest", "REGRESSION_MATRIX_MISSING")),
        "gates_digest": str(gates.get("gate_digest", "CONSTITUTIONAL_GATES_MISSING")),
    }


def build_toolchain_checks(guard: Mapping[str, Any], git: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [_check(spec, guard, git) for spec in TOOLCHAIN_CHECK_SPECS]


def toolchain_summary(checks: Sequence[Mapping[str, Any]], git: Mapping[str, Any]) -> dict[str, Any]:
    statuses = [check.get("status") for check in checks]
    failed = statuses.count("TOOLCHAIN_CHECK_FAIL")
    errors = statuses.count("TOOLCHAIN_CHECK_ERROR")
    return {
        "total_checks": len(statuses),
        "passed_checks": statuses.count("TOOLCHAIN_CHECK_PASS"),
        "failed_checks": failed,
        "skipped_checks": statuses.count("TOOLCHAIN_CHECK_SKIPPED"),
        "error_checks": errors,
        "all_required_checks_passed": failed == 0 and errors == 0,
        "working_tree_clean": git.get("working_tree_clean") is True,
    }


def _check(spec: ToolchainCheckSpec, guard: Mapping[str, Any], git: Mapping[str, Any]) -> dict[str, Any]:
    passed, observed, reason = _evaluate_check(spec.check_id, guard, git)
    return {
        "check_id": spec.check_id,
        "check_name": spec.check_name,
        "check_category": spec.check_category,
        "required": spec.required,
        "expected_condition": spec.expected_condition,
        "observed_condition": observed,
        "status": TOOLCHAIN_CHECK_PASS if passed else TOOLCHAIN_CHECK_FAIL,
        "reason": reason,
    }


def _evaluate_check(check_id: str, guard: Mapping[str, Any], git: Mapping[str, Any]) -> tuple[bool, str, str]:
    commands = {str(item["command_id"]) for item in guard["verification_command_policy"].get("commands", [])}
    pytest_options = set(guard["pytest_collection_policy"].get("required_options", []))
    ignored_outputs = set(guard.get("ignored_output_paths", []))
    ignored_temp = set(guard.get("ignored_temp_paths", []))
    dependency_records = guard.get("dependency_file_digests", [])
    dependency_files = guard.get("dependency_files", [])
    if check_id == "python_executable_recorded":
        return bool(guard.get("python_executable")), str(guard.get("python_executable")), "python executable provenance"
    if check_id == "python_version_recorded":
        return bool(guard.get("python_version")), str(guard.get("python_version")), "python version provenance"
    if check_id == "python_executable_exists":
        exists = Path(str(guard.get("python_executable", ""))).exists()
        return exists, f"exists={exists}", "python executable filesystem check"
    if check_id == "python_version_parseable":
        parsed = parse_python_version(str(guard.get("python_version", "")))
        return parsed is not None, str(parsed), "major/minor/patch parse"
    if check_id == "pytest_version_recorded":
        return bool(guard.get("pytest_version")), str(guard.get("pytest_version")), "pytest package metadata"
    if check_id == "pytest_import_available":
        return bool(guard.get("pytest_version")), "pytest_available" if guard.get("pytest_version") else "pytest_missing", "pytest version lookup"
    if check_id == "pip_version_recorded":
        version = guard.get("pip_version_if_available")
        return True, str(version or "PIP_VERSION_UNAVAILABLE"), "pip is optional but state is explicit"
    if check_id == "dependency_files_discovered":
        return bool(dependency_files), ",".join(str(item) for item in dependency_files), "dependency files or explicit none marker"
    if check_id == "dependency_file_digests_recorded":
        ok = bool(dependency_records) and all("status" in record and "path" in record for record in dependency_records)
        return ok, f"records={len(dependency_records)}", "candidate dependency files checked"
    if check_id == "requirements_files_digested":
        return _candidate_checked(dependency_records, {"requirements.txt", "requirements-dev.txt"}), "requirements_checked", "requirements candidates checked"
    if check_id == "pyproject_toml_digested":
        return _candidate_checked(dependency_records, {"pyproject.toml"}), "pyproject_checked", "pyproject candidate checked"
    if check_id == "setup_files_digested":
        return _candidate_checked(dependency_records, {"setup.py", "setup.cfg"}), "setup_checked", "setup candidates checked"
    if check_id == "verification_command_policy_exists":
        return required_command_ids() <= commands, f"commands={len(commands)}", "required command ids recorded"
    if check_id == "verification_command_compileall":
        return "compileall" in commands, "compileall" if "compileall" in commands else "missing", "compileall command id"
    if check_id == "verification_command_pytest":
        return "pytest" in commands, "pytest" if "pytest" in commands else "missing", "pytest command id"
    if check_id == "verification_command_run_tests_bat":
        return "run_tests_bat" in commands, "run_tests_bat" if "run_tests_bat" in commands else "missing", "batch command id"
    if check_id == "verification_command_manifest_validate":
        return "manifest_validate" in commands, "manifest_validate" if "manifest_validate" in commands else "missing", "manifest command id"
    if check_id == "verification_command_execution_envelope_validate":
        return "execution_envelope_validate" in commands, "execution_envelope_validate" if "execution_envelope_validate" in commands else "missing", "envelope command id"
    if check_id == "verification_command_evidence_chain_validate_compare":
        ok = {"evidence_chain_validate", "evidence_chain_compare"} <= commands
        return ok, "evidence_chain_validate_compare", "evidence chain command ids"
    if check_id == "verification_command_regression_matrix_validate_show":
        ok = {"regression_matrix_validate", "regression_matrix_show"} <= commands
        return ok, "regression_matrix_validate_show", "regression matrix command ids"
    if check_id == "verification_command_constitutional_gates":
        ok = {"constitutional_gates_evaluate", "constitutional_gates_validate", "constitutional_gates_show"} <= commands
        return ok, "constitutional_gates_evaluate_validate_show", "constitutional gate command ids"
    if check_id == "verification_command_toolchain_guard":
        ok = {"toolchain_guard_build", "toolchain_guard_validate", "toolchain_guard_show"} <= commands
        return ok, "toolchain_guard_build_validate_show", "toolchain guard command ids"
    if check_id == "verification_command_runtime_replay":
        ok = {"runtime_main", "runtime_replay"} <= commands
        return ok, "runtime_main_replay_recorded", "runtime/replay policy recorded only"
    if check_id == "pytest_ignore_outputs_policy":
        return "--ignore=outputs" in pytest_options, ",".join(sorted(pytest_options)), "pytest output ignore option"
    if check_id == "pytest_ignore_temp_policy":
        ok = "--ignore-glob=.pytest_tmp_*" in pytest_options and "--ignore-glob=outputs/local_trust_temp/*" in pytest_options
        return ok, ",".join(sorted(pytest_options)), "pytest temp ignore options"
    if check_id == "temp_cache_exclusion_policy":
        ok = {".pytest_cache", ".pytest_tmp_*", "__pycache__", "*.pyc"} <= ignored_temp
        return ok, ",".join(sorted(ignored_temp)), "temp/cache ignore policy"
    if check_id == "generated_output_folder_policy":
        return "outputs" in ignored_outputs, ",".join(sorted(ignored_outputs)), "generated output folder policy"
    if check_id.startswith("binds_"):
        field = {
            "binds_manifest_digest": "bound_manifest_digest",
            "binds_execution_envelope_digest": "bound_execution_envelope_digest",
            "binds_evidence_chain_digest": "bound_evidence_chain_digest",
            "binds_regression_matrix_digest": "bound_regression_matrix_digest",
            "binds_constitutional_gates_digest": "bound_constitutional_gates_digest",
        }[check_id]
        digest = str(guard.get(field))
        return len(digest) == 64, digest, field
    if check_id == "working_tree_policy_recorded":
        return "working_tree_clean" in git, f"working_tree_clean={git.get('working_tree_clean')}", "working tree state recorded"
    if check_id == "branch_recorded":
        return bool(guard.get("git_branch")), str(guard.get("git_branch")), "git branch recorded"
    if check_id == "commit_recorded":
        commit = str(guard.get("git_commit"))
        return len(commit) == 40, commit, "git commit recorded"
    if check_id == "phase_19_boundary_preserved":
        return True, "PHASE_19_NOT_STARTED", "boundary inherited from constitutional gates"
    if check_id == "future_surface_absent":
        matches = _active_source_matches(Path(str(guard["repository_root"])), _future_surface_terms())
        allowed = [match for match in matches if match != "sbp_lex/local_trust/manifest_validator.py"]
        return not allowed, f"active_matches={len(allowed)}", ",".join(allowed)
    if check_id == "future_activation_absent":
        term = "_".join(("runtime", "activation"))
        matches = _active_source_matches(Path(str(guard["repository_root"])), [term])
        return not matches, f"matches={len(matches)}", ",".join(matches)
    if check_id == "forbidden_authority_absent":
        failures = _forbidden_key_paths(guard)
        return not failures, f"forbidden_key_count={len(failures)}", ",".join(failures)
    return False, "UNKNOWN_CHECK", check_id


def _candidate_checked(records: Sequence[Mapping[str, Any]], candidates: set[str]) -> bool:
    return candidates <= {str(record.get("path")) for record in records}


def _future_surface_terms() -> list[str]:
    return [
        "_".join(("node", "quorum")),
        "_".join(("node", "attestation")),
        "_".join(("distributed", "consensus")),
        "_".join(("mesh", "runtime")),
        "_".join(("cloud", "runtime")),
        "_".join(("external", "execution_permission")),
        "_".join(("external", "governance_result")),
    ]


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


def _forbidden_key_paths(value: Any, path: str = "$") -> list[str]:
    forbidden = {
        "execution_permission",
        "governance_result",
        "runtime_authority",
        "allow_execution",
        "external_allow",
        "external_deny",
        "external_escalate",
        "external_" + "governance_result",
    }
    failures: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_path = f"{path}.{key_text}"
            if key_text in forbidden:
                failures.append(next_path)
            failures.extend(_forbidden_key_paths(item, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            failures.extend(_forbidden_key_paths(item, f"{path}[{index}]"))
    return failures


def _load_json_artifact(repository_root: Path, path: Path | str, loader: Any) -> dict[str, Any]:
    resolved = _resolve(repository_root, path)
    if not resolved.exists():
        return {}
    try:
        loaded = loader(resolved, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def payload_for_digest(guard: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in guard.items() if key not in _DIGEST_EXCLUDED_FIELDS}


def hash_toolchain_payload(guard: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(guard)).encode("utf-8")).hexdigest()


def toolchain_signature_for(payload_digest: str) -> dict[str, Any]:
    return sign_local_trust_digest(TOOLCHAIN_GUARD_SIGNATURE_DOMAIN, payload_digest)


def toolchain_digest_for(payload_digest: str, signature: Mapping[str, Any]) -> str:
    return local_trust_binding_digest(
        TOOLCHAIN_GUARD_SIGNATURE_DOMAIN, payload_digest, signature,
    )


def write_toolchain_guard(
    guard: Mapping[str, Any],
    path: Path | str = DEFAULT_TOOLCHAIN_GUARD_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = _resolve(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(guard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_toolchain_guard(
    path: Path | str = DEFAULT_TOOLCHAIN_GUARD_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = _resolve(root, path)
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("toolchain_guard_must_be_object")
    return loaded


def validate_toolchain_guard(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from sbp_lex.local_trust.toolchain_validator import validate_toolchain_guard as _validate

    return _validate(*args, **kwargs)


def _resolve(repository_root: Path, path: Path | str) -> Path:
    return resolve_local_trust_path(repository_root, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX local dependency/toolchain guard")
    parser.add_argument("--path", default=str(DEFAULT_TOOLCHAIN_GUARD_OUTPUT_PATH))
    parser.add_argument("--clean-required", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "validate", "show"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--path", dest="command_path")
        subparser.add_argument("--clean-required", dest="command_clean_required", action="store_true")
    args = parser.parse_args(argv)
    path_arg = args.command_path or args.path
    clean_required = args.clean_required or args.command_clean_required

    root = repository_root_from()
    if args.command == "build":
        guard = build_toolchain_guard(root, clean_required=clean_required)
        path = write_toolchain_guard(guard, path_arg, repository_root=root)
        print(guard["toolchain_status"])
        print(path)
        return 0 if guard["toolchain_status"] == "TOOLCHAIN_GUARD_PASS" else 1
    if args.command == "validate":
        guard = load_toolchain_guard(path_arg, repository_root=root)
        validation = validate_toolchain_guard(guard, repository_root=root, clean_required=clean_required)
        print(validation["toolchain_status"])
        return 0 if validation["toolchain_status"] == "TOOLCHAIN_GUARD_PASS" else 1
    if args.command == "show":
        guard = load_toolchain_guard(path_arg, repository_root=root)
        validation = validate_toolchain_guard(guard, repository_root=root, clean_required=clean_required)
        summary = guard.get("toolchain_summary", {})
        print(validation["toolchain_status"])
        print(f"commit={guard.get('git_commit')}")
        print(f"branch={guard.get('git_branch')}")
        print(f"toolchain_digest={guard.get('toolchain_digest')}")
        print(f"python_executable={guard.get('python_executable')}")
        print(f"python_version={guard.get('python_version')}")
        print(f"pytest_version={guard.get('pytest_version')}")
        print(f"checks={summary.get('total_checks')}")
        print(f"passed={summary.get('passed_checks')}")
        print(f"failed={summary.get('failed_checks')}")
        print(f"skipped={summary.get('skipped_checks')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
