from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.evidence_chain import (
    DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    load_local_evidence_chain,
)
from sbp_lex.local_trust.evidence_chain_validator import validate_local_evidence_chain
from sbp_lex.local_trust.execution_envelope import (
    DEFAULT_ENVELOPE_OUTPUT_PATH,
    load_execution_envelope,
)
from sbp_lex.local_trust.execution_envelope_validator import validate_execution_envelope
from sbp_lex.local_trust.git_provenance import collect_git_provenance
from sbp_lex.local_trust.manifest import (
    DEFAULT_OUTPUT_PATH as DEFAULT_MANIFEST_PATH,
    canonical_json,
    load_local_trust_manifest,
    repository_root_from,
)
from sbp_lex.local_trust.manifest_validator import validate_local_trust_manifest
from sbp_lex.local_trust.regression_runner import run_regression_cases, skipped_regression_cases
from sbp_lex.local_trust.signing import (
    LOCAL_TRUST_SIGNATURE_MODE,
    local_trust_binding_digest,
    sign_local_trust_digest,
)
from sbp_lex.local_trust.paths import resolve_local_trust_path

REGRESSION_MATRIX_SIGNATURE_MODE = LOCAL_TRUST_SIGNATURE_MODE
REGRESSION_MATRIX_SIGNATURE_DOMAIN = "SBP_LEX_LOCAL_TRUST_REGRESSION_MATRIX"
REGRESSION_MATRIX_VERSION = "18.7E.1"
DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH = Path("outputs/local_trust_regression_matrix.json")

_DIGEST_EXCLUDED_FIELDS = {
    "matrix_status",
    "validation_failures",
    "matrix_payload_digest",
    "matrix_digest",
    "matrix_signature",
}


def build_local_trust_regression_matrix(
    repository_root: Path | str | None = None,
    *,
    manifest_path: Path | str = DEFAULT_MANIFEST_PATH,
    envelope_path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    evidence_chain_path: Path | str = DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    run_cases: bool = False,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.regression_validator import validate_local_trust_regression_matrix

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    git = collect_git_provenance(root)
    manifest_binding = bind_local_trust_manifest(root, manifest_path)
    envelope_binding = bind_execution_envelope(root, envelope_path)
    chain_binding = bind_local_evidence_chain(root, evidence_chain_path)
    manifest = manifest_binding.get("artifact") if isinstance(manifest_binding.get("artifact"), Mapping) else {}
    envelope = envelope_binding.get("artifact") if isinstance(envelope_binding.get("artifact"), Mapping) else {}
    chain = chain_binding.get("artifact") if isinstance(chain_binding.get("artifact"), Mapping) else {}
    cases = (
        run_regression_cases(root, manifest, envelope, chain)
        if run_cases and manifest and envelope and chain
        else skipped_regression_cases()
    )

    matrix: dict[str, Any] = {
        "matrix_type": "local_trust_regression_matrix",
        "matrix_version": REGRESSION_MATRIX_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "git_status_short": git.get("git_status_short", ""),
        "working_tree_clean": git.get("working_tree_clean") is True,
        "bound_manifest_digest": manifest_binding["digest"],
        "bound_execution_envelope_digest": envelope_binding["digest"],
        "bound_evidence_chain_digest": chain_binding["digest"],
        "regression_cases": cases,
        "regression_summary": regression_summary(cases),
        "signature_mode": REGRESSION_MATRIX_SIGNATURE_MODE,
        "matrix_status": "REGRESSION_MATRIX_INCOMPLETE",
        "validation_failures": [],
    }
    payload_digest = hash_matrix_payload(matrix)
    signature = matrix_signature_for(payload_digest)
    matrix["matrix_payload_digest"] = payload_digest
    matrix["matrix_signature"] = signature
    matrix["matrix_digest"] = matrix_digest_for(payload_digest, signature)
    validation = validate_local_trust_regression_matrix(matrix, repository_root=root, clean_required=clean_required)
    matrix["matrix_status"] = validation["matrix_status"]
    matrix["validation_failures"] = validation["validation_failures"]
    return matrix


def bind_local_trust_manifest(repository_root: Path, manifest_path: Path | str = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    path = _resolve(repository_root, manifest_path)
    if not path.exists():
        return {"digest": "LOCAL_TRUST_MANIFEST_MISSING", "status": "LOCAL_TRUST_MANIFEST_MISSING", "artifact": None}
    try:
        manifest = load_local_trust_manifest(path, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError):
        return {"digest": "LOCAL_TRUST_MANIFEST_INVALID", "status": "LOCAL_TRUST_MANIFEST_INVALID", "artifact": None}
    validation = validate_local_trust_manifest(manifest, repository_root=repository_root)
    if validation["local_trust_status"] != "LOCAL_TRUST_VALID":
        return {"digest": "LOCAL_TRUST_MANIFEST_INVALID", "status": "LOCAL_TRUST_MANIFEST_INVALID", "artifact": manifest}
    return {"digest": str(manifest["manifest_digest"]), "status": "LOCAL_TRUST_MANIFEST_BOUND", "artifact": manifest}


def bind_execution_envelope(repository_root: Path, envelope_path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH) -> dict[str, Any]:
    path = _resolve(repository_root, envelope_path)
    if not path.exists():
        return {"digest": "EXECUTION_ENVELOPE_MISSING", "status": "EXECUTION_ENVELOPE_MISSING", "artifact": None}
    try:
        envelope = load_execution_envelope(path, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError):
        return {"digest": "EXECUTION_ENVELOPE_INVALID", "status": "EXECUTION_ENVELOPE_INVALID", "artifact": None}
    validation = validate_execution_envelope(envelope, repository_root=repository_root)
    if validation["verification_status"] != "EXECUTION_ENV_VALID":
        return {"digest": "EXECUTION_ENVELOPE_INVALID", "status": "EXECUTION_ENVELOPE_INVALID", "artifact": envelope}
    return {"digest": str(envelope["envelope_digest"]), "status": "EXECUTION_ENVELOPE_BOUND", "artifact": envelope}


def bind_local_evidence_chain(
    repository_root: Path,
    evidence_chain_path: Path | str = DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
) -> dict[str, Any]:
    path = _resolve(repository_root, evidence_chain_path)
    if not path.exists():
        return {"digest": "EVIDENCE_CHAIN_MISSING", "status": "EVIDENCE_CHAIN_MISSING", "artifact": None}
    try:
        chain = load_local_evidence_chain(path, repository_root=repository_root)
    except (OSError, ValueError, json.JSONDecodeError):
        return {"digest": "EVIDENCE_CHAIN_INVALID", "status": "EVIDENCE_CHAIN_INVALID", "artifact": None}
    validation = validate_local_evidence_chain(chain, repository_root=repository_root)
    if validation["evidence_chain_status"] != "EVIDENCE_CHAIN_VALID":
        return {"digest": "EVIDENCE_CHAIN_INVALID", "status": "EVIDENCE_CHAIN_INVALID", "artifact": chain}
    return {"digest": str(chain["chain_digest"]), "status": "EVIDENCE_CHAIN_BOUND", "artifact": chain}


def regression_summary(cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    statuses = [case.get("status") for case in cases]
    failed = statuses.count("REGRESSION_CASE_FAIL")
    errors = statuses.count("REGRESSION_CASE_ERROR")
    return {
        "total_cases": len(statuses),
        "passed_cases": statuses.count("REGRESSION_CASE_PASS"),
        "failed_cases": failed,
        "skipped_cases": statuses.count("REGRESSION_CASE_SKIPPED"),
        "error_cases": errors,
        "all_cases_passed": failed == 0 and errors == 0 and "REGRESSION_CASE_SKIPPED" not in statuses,
    }


def payload_for_digest(matrix: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in matrix.items()
        if key not in _DIGEST_EXCLUDED_FIELDS
    }


def hash_matrix_payload(matrix: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(matrix)).encode("utf-8")).hexdigest()


def matrix_signature_for(payload_digest: str) -> dict[str, Any]:
    return sign_local_trust_digest(REGRESSION_MATRIX_SIGNATURE_DOMAIN, payload_digest)


def matrix_digest_for(payload_digest: str, signature: Mapping[str, Any]) -> str:
    return local_trust_binding_digest(
        REGRESSION_MATRIX_SIGNATURE_DOMAIN, payload_digest, signature,
    )


def write_local_trust_regression_matrix(
    matrix: Mapping[str, Any],
    path: Path | str = DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = _resolve(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_local_trust_regression_matrix(
    path: Path | str = DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = _resolve(root, path)
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("local_trust_regression_matrix_must_be_object")
    return loaded


def validate_local_trust_regression_matrix(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from sbp_lex.local_trust.regression_validator import validate_local_trust_regression_matrix as _validate

    return _validate(*args, **kwargs)


def _resolve(repository_root: Path, path: Path | str) -> Path:
    return resolve_local_trust_path(repository_root, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX local trust regression matrix")
    parser.add_argument("--path", default=str(DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH))
    parser.add_argument("--manifest-path", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--envelope-path", default=str(DEFAULT_ENVELOPE_OUTPUT_PATH))
    parser.add_argument("--evidence-chain-path", default=str(DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH))
    parser.add_argument("--clean-required", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "validate", "show", "run"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--path", dest="command_path")
        subparser.add_argument("--manifest-path", dest="command_manifest_path")
        subparser.add_argument("--envelope-path", dest="command_envelope_path")
        subparser.add_argument("--evidence-chain-path", dest="command_evidence_chain_path")
        subparser.add_argument("--clean-required", dest="command_clean_required", action="store_true")
    args = parser.parse_args(argv)
    path_arg = args.command_path or args.path
    manifest_path_arg = args.command_manifest_path or args.manifest_path
    envelope_path_arg = args.command_envelope_path or args.envelope_path
    evidence_chain_path_arg = args.command_evidence_chain_path or args.evidence_chain_path
    clean_required = args.clean_required or args.command_clean_required

    root = repository_root_from()
    if args.command in {"build", "run"}:
        matrix = build_local_trust_regression_matrix(
            root,
            manifest_path=manifest_path_arg,
            envelope_path=envelope_path_arg,
            evidence_chain_path=evidence_chain_path_arg,
            run_cases=args.command == "run",
            clean_required=clean_required,
        )
        path = write_local_trust_regression_matrix(matrix, path_arg, repository_root=root)
        print(matrix["matrix_status"])
        print(path)
        return 0 if matrix["matrix_status"] == "REGRESSION_MATRIX_VALID" else 1
    if args.command == "validate":
        matrix = load_local_trust_regression_matrix(path_arg, repository_root=root)
        validation = validate_local_trust_regression_matrix(matrix, repository_root=root, clean_required=clean_required)
        print(validation["matrix_status"])
        return 0 if validation["matrix_status"] == "REGRESSION_MATRIX_VALID" else 1
    if args.command == "show":
        matrix = load_local_trust_regression_matrix(path_arg, repository_root=root)
        validation = validate_local_trust_regression_matrix(matrix, repository_root=root, clean_required=clean_required)
        summary = matrix.get("regression_summary", {})
        print(validation["matrix_status"])
        print(f"commit={matrix.get('git_commit')}")
        print(f"branch={matrix.get('git_branch')}")
        print(f"matrix_digest={matrix.get('matrix_digest')}")
        print(f"bound_manifest_digest={matrix.get('bound_manifest_digest')}")
        print(f"bound_execution_envelope_digest={matrix.get('bound_execution_envelope_digest')}")
        print(f"bound_evidence_chain_digest={matrix.get('bound_evidence_chain_digest')}")
        print(f"cases={summary.get('total_cases')}")
        print(f"passed={summary.get('passed_cases')}")
        print(f"failed={summary.get('failed_cases')}")
        print(f"skipped={summary.get('skipped_cases')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
