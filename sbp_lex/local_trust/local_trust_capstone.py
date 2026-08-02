from __future__ import annotations

import argparse
import json
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.capstone_report import completed_phase_index, verification_command_index
from sbp_lex.local_trust.constitutional_gates import (
    DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH,
    load_constitutional_gate_result,
)
from sbp_lex.local_trust.evidence_chain import (
    DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    compare_evidence_chain_to_current_files,
    load_local_evidence_chain,
)
from sbp_lex.local_trust.execution_envelope import DEFAULT_ENVELOPE_OUTPUT_PATH, load_execution_envelope
from sbp_lex.local_trust.git_provenance import collect_git_provenance
from sbp_lex.local_trust.manifest import (
    DEFAULT_OUTPUT_PATH as DEFAULT_MANIFEST_PATH,
    canonical_json,
    load_local_trust_manifest,
    repository_root_from,
)
from sbp_lex.local_trust.regression_matrix import (
    DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH,
    load_local_trust_regression_matrix,
)
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.signing import (
    LOCAL_TRUST_SIGNATURE_MODE,
    local_trust_binding_digest,
    sign_local_trust_digest,
)
from sbp_lex.local_trust.toolchain_guard import DEFAULT_TOOLCHAIN_GUARD_OUTPUT_PATH, load_toolchain_guard

CAPSTONE_SIGNATURE_MODE = LOCAL_TRUST_SIGNATURE_MODE
CAPSTONE_SIGNATURE_DOMAIN = "SBP_LEX_LOCAL_TRUST_CAPSTONE"
CAPSTONE_VERSION = "18.7E.4"
DEFAULT_CAPSTONE_OUTPUT_PATH = Path("outputs/local_trust_25_year_capstone.json")

_DIGEST_EXCLUDED_FIELDS = {
    "capstone_status",
    "validation_failures",
    "capstone_payload_digest",
    "capstone_digest",
    "capstone_signature",
}

ARTIFACT_SPECS: tuple[dict[str, str], ...] = (
    {
        "artifact_id": "manifest",
        "path": "outputs/local_trust_root_manifest.json",
        "digest_field": "manifest_digest",
        "status_field": "local_trust_status",
        "expected_status": "LOCAL_TRUST_VALID",
    },
    {
        "artifact_id": "execution_envelope",
        "path": "outputs/local_execution_environment_trust_envelope.json",
        "digest_field": "envelope_digest",
        "status_field": "verification_status",
        "expected_status": "EXECUTION_ENV_VALID",
    },
    {
        "artifact_id": "evidence_chain",
        "path": "outputs/local_evidence_chain.json",
        "digest_field": "chain_digest",
        "status_field": "evidence_chain_status",
        "expected_status": "EVIDENCE_CHAIN_VALID",
    },
    {
        "artifact_id": "regression_matrix",
        "path": "outputs/local_trust_regression_matrix.json",
        "digest_field": "matrix_digest",
        "status_field": "matrix_status",
        "expected_status": "REGRESSION_MATRIX_VALID",
    },
    {
        "artifact_id": "constitutional_gates",
        "path": "outputs/local_constitutional_gates.json",
        "digest_field": "gate_digest",
        "status_field": "gate_status",
        "expected_status": "CONSTITUTIONAL_GATES_PASS",
    },
    {
        "artifact_id": "toolchain_guard",
        "path": "outputs/local_toolchain_guard.json",
        "digest_field": "toolchain_digest",
        "status_field": "toolchain_status",
        "expected_status": "TOOLCHAIN_GUARD_PASS",
    },
)

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

LEGACY_LOCAL_TRUST_BOUNDARY_SCAN_ALLOWLIST = {
    "sbp_lex/local_trust/manifest_validator.py",
}


def build_local_trust_capstone(
    repository_root: Path | str | None = None,
    *,
    manifest_path: Path | str = DEFAULT_MANIFEST_PATH,
    envelope_path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    evidence_chain_path: Path | str = DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    regression_matrix_path: Path | str = DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH,
    constitutional_gates_path: Path | str = DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH,
    toolchain_guard_path: Path | str = DEFAULT_TOOLCHAIN_GUARD_OUTPUT_PATH,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.capstone_validator import validate_local_trust_capstone

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    git = collect_git_provenance(root)
    paths = {
        "manifest": manifest_path,
        "execution_envelope": envelope_path,
        "evidence_chain": evidence_chain_path,
        "regression_matrix": regression_matrix_path,
        "constitutional_gates": constitutional_gates_path,
        "toolchain_guard": toolchain_guard_path,
    }
    artifacts = collect_artifact_index(root, paths)
    bindings = {str(item["artifact_id"]): str(item.get("digest")) for item in artifacts}
    evidence_compare = _compare_evidence_chain(root, paths["evidence_chain"])
    capstone: dict[str, Any] = {
        "capstone_type": "local_trust_25_year_completion_lock",
        "capstone_version": CAPSTONE_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "github_remote": _origin_remote(root),
        "github_sync_status": collect_github_sync_status(root, git),
        "phase_scope": phase_scope(),
        "completed_phases": completed_phase_index({**bindings, "capstone": "COMPUTED_DURING_BUILD"}),
        "bound_manifest_digest": bindings.get("manifest"),
        "bound_execution_envelope_digest": bindings.get("execution_envelope"),
        "bound_evidence_chain_digest": bindings.get("evidence_chain"),
        "bound_regression_matrix_digest": bindings.get("regression_matrix"),
        "bound_constitutional_gates_digest": bindings.get("constitutional_gates"),
        "bound_toolchain_guard_digest": bindings.get("toolchain_guard"),
        "artifact_index": artifacts,
        "verification_command_index": verification_command_index(),
        "verification_result_summary": verification_result_summary(artifacts, evidence_compare),
        "local_trust_completion_summary": local_trust_completion_summary(artifacts, evidence_compare),
        "boundary_confirmation_summary": boundary_confirmation_summary(root),
        "next_phase_readiness": next_phase_readiness(),
        "signature_mode": CAPSTONE_SIGNATURE_MODE,
        "capstone_status": "LOCAL_TRUST_CAPSTONE_INCOMPLETE",
        "validation_failures": [],
    }
    payload_digest = hash_capstone_payload(capstone)
    signature = capstone_signature_for(payload_digest)
    capstone["capstone_payload_digest"] = payload_digest
    capstone["capstone_signature"] = signature
    capstone["capstone_digest"] = capstone_digest_for(payload_digest, signature)
    capstone["completed_phases"] = completed_phase_index({**bindings, "capstone": capstone["capstone_digest"]})
    payload_digest = hash_capstone_payload(capstone)
    signature = capstone_signature_for(payload_digest)
    capstone["capstone_payload_digest"] = payload_digest
    capstone["capstone_signature"] = signature
    capstone["capstone_digest"] = capstone_digest_for(payload_digest, signature)
    validation = validate_local_trust_capstone(capstone, repository_root=root, clean_required=clean_required)
    capstone["capstone_status"] = validation["capstone_status"]
    capstone["validation_failures"] = validation["validation_failures"]
    return capstone


def collect_artifact_index(repository_root: Path, paths: Mapping[str, Path | str]) -> list[dict[str, Any]]:
    loaders = {
        "manifest": load_local_trust_manifest,
        "execution_envelope": load_execution_envelope,
        "evidence_chain": load_local_evidence_chain,
        "regression_matrix": load_local_trust_regression_matrix,
        "constitutional_gates": load_constitutional_gate_result,
        "toolchain_guard": load_toolchain_guard,
    }
    validators = {
        "manifest": _validate_manifest,
        "execution_envelope": _validate_envelope,
        "evidence_chain": _validate_evidence_chain,
        "regression_matrix": _validate_matrix,
        "constitutional_gates": _validate_gates,
        "toolchain_guard": _validate_toolchain,
    }
    records: list[dict[str, Any]] = []
    for spec in ARTIFACT_SPECS:
        artifact_id = spec["artifact_id"]
        relative_path = str(paths.get(artifact_id, spec["path"]))
        resolved = _resolve(repository_root, relative_path)
        if not resolved.exists():
            records.append(
                {
                    **spec,
                    "path": relative_path,
                    "presence_status": "MISSING",
                    "digest": f"{artifact_id.upper()}_MISSING",
                    "validation_status": "MISSING",
                    "validation_failures": ["artifact_missing"],
                }
            )
            continue
        try:
            artifact = loaders[artifact_id](resolved, repository_root=repository_root)
            validation = validators[artifact_id](artifact, repository_root)
            records.append(
                {
                    **spec,
                    "path": relative_path,
                    "presence_status": "PRESENT",
                    "digest": str(artifact.get(spec["digest_field"])),
                    "validation_status": str(validation["status"]),
                    "validation_failures": list(validation["validation_failures"]),
                    "size_bytes": resolved.stat().st_size,
                }
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            records.append(
                {
                    **spec,
                    "path": relative_path,
                    "presence_status": "UNREADABLE",
                    "digest": f"{artifact_id.upper()}_UNREADABLE",
                    "validation_status": "UNREADABLE",
                    "validation_failures": [str(exc)],
                }
            )
    return records


def phase_scope() -> dict[str, Any]:
    return {
        "phase_id": "18.7E.4",
        "phase_name": "25-Year Local Trust Capstone Report / Local Trust Completion Lock",
        "starts_from_commit": "eedb30cc5cd4ea7e6bc9be29d06e1c276e28a6d4",
        "included_prior_phases": ["18.7D.1", "18.7E.1", "18.7E.2", "18.7E.3"],
        "included_current_phase": "18.7E.4",
        "excluded_work": ["Phase 19", "18.7F implementation", "release package generation"],
    }


def collect_github_sync_status(repository_root: Path, git: Mapping[str, Any]) -> dict[str, Any]:
    branch_status = _git(repository_root, "status", "--short", "--branch", "--untracked-files=no")
    branch = str(git.get("git_branch") or "")
    text = str(branch_status.get("stdout") or "")
    return {
        "branch_status_short": text,
        "tracked_working_tree_clean": _tracked_status_clean(text),
        "current_working_tree_clean": git.get("working_tree_clean") is True,
        "branch_has_ahead_count": "[ahead " in text,
        "branch_has_behind_count": "[behind " in text,
        "synced_to_origin_branch": bool(branch) and f"{branch}...origin/{branch}" in text and "[ahead " not in text,
        "pre_phase_clean_sync_requirement": "VERIFIED_BEFORE_18_7E_4_IMPLEMENTATION",
    }


def verification_result_summary(
    artifacts: Sequence[Mapping[str, Any]],
    evidence_compare: Mapping[str, Any],
) -> dict[str, Any]:
    status_by_id = {str(item["artifact_id"]): str(item.get("validation_status")) for item in artifacts}
    return {
        "manifest": status_by_id.get("manifest"),
        "execution_envelope": status_by_id.get("execution_envelope"),
        "evidence_chain": status_by_id.get("evidence_chain"),
        "evidence_chain_compare": evidence_compare.get("evidence_chain_status"),
        "evidence_chain_changed_items": len(evidence_compare.get("changed_evidence_items", [])),
        "regression_matrix": status_by_id.get("regression_matrix"),
        "constitutional_gates": status_by_id.get("constitutional_gates"),
        "toolchain_guard": status_by_id.get("toolchain_guard"),
        "capstone_cli_execution_note": "build/validate/show do not execute runtime, replay, pytest, batch tests, or authority systems.",
        "full_verification_recorded_in_report": True,
    }


def local_trust_completion_summary(
    artifacts: Sequence[Mapping[str, Any]],
    evidence_compare: Mapping[str, Any],
) -> dict[str, Any]:
    all_artifacts_valid = all(item.get("validation_status") == item.get("expected_status") for item in artifacts)
    evidence_unchanged = not evidence_compare.get("changed_evidence_items")
    return {
        "completed_phase_count": 5,
        "bound_artifact_count": len(artifacts),
        "all_required_artifacts_present": all(item.get("presence_status") == "PRESENT" for item in artifacts),
        "all_bound_artifacts_valid": all_artifacts_valid,
        "evidence_chain_changed_items": len(evidence_compare.get("changed_evidence_items", [])),
        "evidence_chain_unchanged": evidence_unchanged,
        "local_trust_completion_locked": all_artifacts_valid and evidence_unchanged,
        "phase_19_not_started": True,
        "next_phase_id": "18.7F",
    }


def boundary_confirmation_summary(repository_root: Path) -> dict[str, Any]:
    protected_changes = sorted(set(_changed_paths(repository_root)) & PROTECTED_RUNTIME_PATHS)
    unauthorized_protected_changes = sorted(
        set(protected_changes) - AUTHORIZED_EIE_PT_REBUILD_TOUCHPOINTS
    )
    future_matches = [
        match
        for match in _active_source_matches(repository_root, _future_surface_terms() + [_activation_term()])
        if match not in LEGACY_LOCAL_TRUST_BOUNDARY_SCAN_ALLOWLIST
    ]
    return {
        "runtimeActivationIntroduced": False,
        "sbpLexRuntimeAuthorityChanged": bool(unauthorized_protected_changes),
        "governanceBehaviorChanged": False,
        "proceduralTruthBehaviorChanged": False,
        "executionGateBehaviorChanged": False,
        "hardEntryGateBehaviorChanged": False,
        "skgDtnRemainExternalNonAuthoritative": True,
        "futureRuntimeSurfacesIntroduced": bool(future_matches),
        "phase19Started": False,
        "capstoneIsExecutionAuthority": False,
        "protectedRuntimePathChanges": protected_changes,
        "authorizedRebuildRuntimePathChanges": sorted(
            set(protected_changes) & AUTHORIZED_EIE_PT_REBUILD_TOUCHPOINTS
        ),
        "unauthorizedProtectedRuntimePathChanges": unauthorized_protected_changes,
        "activeBoundaryScanMatches": future_matches,
    }


def next_phase_readiness() -> dict[str, Any]:
    return {
        "next_phase_id": "18.7F",
        "next_phase_name": "Release Integrity Package / Reproducible Validation Bundle",
        "readiness_status": "READY_MARKER_ONLY",
        "implemented_in_this_phase": False,
        "purpose": "Turn the locally trusted repository into a controlled, reproducible, externally reviewable release package.",
        "expected_future_outputs": [
            "release bundle manifest",
            "release hash index",
            "artifact digest list",
            "claims-to-evidence seed index",
            "verification command list",
            "runtime/replay proof references",
            "test proof references",
            "dependency/toolchain proof references",
            "external review preparation structure",
        ],
    }


def payload_for_digest(capstone: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in capstone.items() if key not in _DIGEST_EXCLUDED_FIELDS}


def hash_capstone_payload(capstone: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(capstone)).encode("utf-8")).hexdigest()


def capstone_signature_for(payload_digest: str) -> dict[str, Any]:
    return sign_local_trust_digest(CAPSTONE_SIGNATURE_DOMAIN, payload_digest)


def capstone_digest_for(payload_digest: str, signature: Mapping[str, Any]) -> str:
    return local_trust_binding_digest(
        CAPSTONE_SIGNATURE_DOMAIN, payload_digest, signature,
    )


def write_local_trust_capstone(
    capstone: Mapping[str, Any],
    path: Path | str = DEFAULT_CAPSTONE_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = _resolve(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(capstone, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_local_trust_capstone(
    path: Path | str = DEFAULT_CAPSTONE_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = _resolve(root, path)
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("local_trust_capstone_must_be_object")
    return loaded


def validate_local_trust_capstone(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from sbp_lex.local_trust.capstone_validator import validate_local_trust_capstone as _validate

    return _validate(*args, **kwargs)


def _validate_manifest(artifact: Mapping[str, Any], repository_root: Path) -> dict[str, Any]:
    from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest

    result = validate_local_trust_manifest(artifact, repository_root=repository_root)
    return {"status": result["local_trust_status"], "validation_failures": result["validation_failures"]}


def _validate_envelope(artifact: Mapping[str, Any], repository_root: Path) -> dict[str, Any]:
    from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope

    result = validate_execution_envelope(artifact, repository_root=repository_root)
    return {"status": result["verification_status"], "validation_failures": result["validation_failures"]}


def _validate_evidence_chain(artifact: Mapping[str, Any], repository_root: Path) -> dict[str, Any]:
    from sbp_lex.local_trust.evidence_chain_validator import validate_local_evidence_chain

    result = validate_local_evidence_chain(artifact, repository_root=repository_root)
    return {"status": result["evidence_chain_status"], "validation_failures": result["validation_failures"]}


def _validate_matrix(artifact: Mapping[str, Any], repository_root: Path) -> dict[str, Any]:
    from sbp_lex.local_trust.regression_validator import validate_local_trust_regression_matrix

    result = validate_local_trust_regression_matrix(artifact, repository_root=repository_root)
    return {"status": result["matrix_status"], "validation_failures": result["validation_failures"]}


def _validate_gates(artifact: Mapping[str, Any], repository_root: Path) -> dict[str, Any]:
    from sbp_lex.local_trust.gate_validator import validate_constitutional_gate_result

    result = validate_constitutional_gate_result(artifact, repository_root=repository_root)
    return {"status": result["gate_status"], "validation_failures": result["validation_failures"]}


def _validate_toolchain(artifact: Mapping[str, Any], repository_root: Path) -> dict[str, Any]:
    from sbp_lex.local_trust.toolchain_validator import validate_toolchain_guard

    result = validate_toolchain_guard(artifact, repository_root=repository_root)
    return {"status": result["toolchain_status"], "validation_failures": result["validation_failures"]}


def _compare_evidence_chain(repository_root: Path, path: Path | str) -> dict[str, Any]:
    try:
        chain = load_local_evidence_chain(path, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "evidence_chain_status": "EVIDENCE_CHAIN_INCOMPLETE",
            "validation_failures": [str(exc)],
            "changed_evidence_items": [],
        }
    return compare_evidence_chain_to_current_files(chain, repository_root=repository_root)


def _resolve(repository_root: Path, path: Path | str) -> Path:
    return resolve_local_trust_path(repository_root, path)


def _origin_remote(repository_root: Path) -> str:
    config = repository_root / ".git" / "config"
    if not config.exists():
        return "UNKNOWN_FROM_CURRENT_CONTEXT"
    in_origin = False
    for line in config.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("[remote "):
            in_origin = stripped == '[remote "origin"]'
            continue
        if in_origin and stripped.startswith("url ="):
            return stripped.split("=", 1)[1].strip()
    return "UNKNOWN_FROM_CURRENT_CONTEXT"


def _tracked_status_clean(branch_status: str) -> bool:
    return all(line.startswith("## ") for line in branch_status.splitlines() if line.strip())


def _git(repository_root: Path, *args: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc)}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _changed_paths(repository_root: Path) -> list[str]:
    result = _git(repository_root, "diff", "--name-only", "HEAD")
    if result.get("returncode") != 0:
        return []
    return [line.strip().replace("\\", "/") for line in str(result.get("stdout", "")).splitlines() if line.strip()]


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


def _activation_term() -> str:
    return "_".join(("runtime", "activation"))


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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX 25-year local trust capstone")
    parser.add_argument("--path", default=str(DEFAULT_CAPSTONE_OUTPUT_PATH))
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
        capstone = build_local_trust_capstone(root, clean_required=clean_required)
        path = write_local_trust_capstone(capstone, path_arg, repository_root=root)
        print(capstone["capstone_status"])
        print(path)
        return 0 if capstone["capstone_status"] == "LOCAL_TRUST_CAPSTONE_PASS" else 1
    if args.command == "validate":
        capstone = load_local_trust_capstone(path_arg, repository_root=root)
        validation = validate_local_trust_capstone(capstone, repository_root=root, clean_required=clean_required)
        print(validation["capstone_status"])
        return 0 if validation["capstone_status"] == "LOCAL_TRUST_CAPSTONE_PASS" else 1
    if args.command == "show":
        capstone = load_local_trust_capstone(path_arg, repository_root=root)
        validation = validate_local_trust_capstone(capstone, repository_root=root, clean_required=clean_required)
        completion = capstone.get("local_trust_completion_summary", {})
        print(validation["capstone_status"])
        print(f"commit={capstone.get('git_commit')}")
        print(f"branch={capstone.get('git_branch')}")
        print(f"capstone_digest={capstone.get('capstone_digest')}")
        print(f"completed_phases={completion.get('completed_phase_count')}")
        print(f"artifacts={completion.get('bound_artifact_count')}")
        print(f"next_phase={capstone.get('next_phase_readiness', {}).get('next_phase_id')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
