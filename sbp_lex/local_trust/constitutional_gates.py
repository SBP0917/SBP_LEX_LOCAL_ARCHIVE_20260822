from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.evidence_chain import DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH
from sbp_lex.local_trust.execution_envelope import DEFAULT_ENVELOPE_OUTPUT_PATH
from sbp_lex.local_trust.gate_policy import LOCAL_TRUST_CONSTITUTIONAL_GATE_POLICY_VERSION
from sbp_lex.local_trust.gate_runner import collect_gate_inputs, run_constitutional_gates
from sbp_lex.local_trust.manifest import (
    DEFAULT_OUTPUT_PATH as DEFAULT_MANIFEST_PATH,
    canonical_json,
    repository_root_from,
)
from sbp_lex.local_trust.regression_matrix import DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH

CONSTITUTIONAL_GATE_SIGNATURE_MODE = "CONSTITUTIONAL_GATES_DETERMINISTIC_PLACEHOLDER"
CONSTITUTIONAL_GATE_VERSION = "18.7E.2"
DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH = Path("outputs/local_constitutional_gates.json")

_DIGEST_EXCLUDED_FIELDS = {
    "gate_status",
    "validation_failures",
    "gate_payload_digest",
    "gate_digest",
    "gate_signature",
}


def build_constitutional_gate_result(
    repository_root: Path | str | None = None,
    *,
    manifest_path: Path | str = DEFAULT_MANIFEST_PATH,
    envelope_path: Path | str = DEFAULT_ENVELOPE_OUTPUT_PATH,
    evidence_chain_path: Path | str = DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH,
    regression_matrix_path: Path | str = DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.gate_validator import validate_constitutional_gate_result

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    context = collect_gate_inputs(
        root,
        manifest_path=_resolve(root, manifest_path),
        envelope_path=_resolve(root, envelope_path),
        evidence_chain_path=_resolve(root, evidence_chain_path),
        regression_matrix_path=_resolve(root, regression_matrix_path),
    )
    gates = run_constitutional_gates(context)
    gate_result: dict[str, Any] = {
        "gate_result_type": "local_trust_constitutional_enforcement_gates",
        "gate_result_version": CONSTITUTIONAL_GATE_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": context["git"].get("git_commit"),
        "git_branch": context["git"].get("git_branch"),
        "bound_manifest_digest": context["manifest"].get("digest"),
        "bound_execution_envelope_digest": context["envelope"].get("digest"),
        "bound_evidence_chain_digest": context["chain"].get("digest"),
        "bound_regression_matrix_digest": context["matrix"].get("digest"),
        "gate_policy_version": LOCAL_TRUST_CONSTITUTIONAL_GATE_POLICY_VERSION,
        "gate_results": gates,
        "gate_summary": gate_summary(gates, context),
        "signature_mode": CONSTITUTIONAL_GATE_SIGNATURE_MODE,
        "gate_status": "CONSTITUTIONAL_GATES_INCOMPLETE",
        "validation_failures": [],
    }
    payload_digest = hash_gate_payload(gate_result)
    signature = gate_signature_for(payload_digest)
    gate_result["gate_payload_digest"] = payload_digest
    gate_result["gate_signature"] = signature
    gate_result["gate_digest"] = gate_digest_for(payload_digest, signature)
    validation = validate_constitutional_gate_result(gate_result, repository_root=root, clean_required=clean_required)
    gate_result["gate_status"] = validation["gate_status"]
    gate_result["validation_failures"] = validation["validation_failures"]
    return gate_result


def gate_summary(gates: Sequence[Mapping[str, Any]], context: Mapping[str, Any]) -> dict[str, Any]:
    statuses = [gate.get("status") for gate in gates]
    failed = statuses.count("GATE_FAIL")
    errors = statuses.count("GATE_ERROR")
    return {
        "total_gates": len(statuses),
        "passed_gates": statuses.count("GATE_PASS"),
        "failed_gates": failed,
        "skipped_gates": statuses.count("GATE_SKIPPED"),
        "error_gates": errors,
        "all_required_gates_passed": failed == 0 and errors == 0,
        "working_tree_clean": context["git"].get("working_tree_clean") is True,
    }


def payload_for_digest(gate_result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in gate_result.items()
        if key not in _DIGEST_EXCLUDED_FIELDS
    }


def hash_gate_payload(gate_result: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(gate_result)).encode("utf-8")).hexdigest()


def gate_signature_for(payload_digest: str) -> str:
    return sha256(f"{CONSTITUTIONAL_GATE_SIGNATURE_MODE}:{payload_digest}".encode("utf-8")).hexdigest()


def gate_digest_for(payload_digest: str, signature: str) -> str:
    return sha256(
        canonical_json(
            {
                "gate_payload_digest": payload_digest,
                "gate_signature": signature,
                "signature_mode": CONSTITUTIONAL_GATE_SIGNATURE_MODE,
            }
        ).encode("utf-8")
    ).hexdigest()


def write_constitutional_gate_result(
    gate_result: Mapping[str, Any],
    path: Path | str = DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = _resolve(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(gate_result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_constitutional_gate_result(
    path: Path | str = DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = _resolve(root, path)
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("constitutional_gate_result_must_be_object")
    return loaded


def validate_constitutional_gate_result(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from sbp_lex.local_trust.gate_validator import validate_constitutional_gate_result as _validate

    return _validate(*args, **kwargs)


def _resolve(repository_root: Path, path: Path | str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else repository_root / candidate


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX local constitutional enforcement gates")
    parser.add_argument("--path", default=str(DEFAULT_CONSTITUTIONAL_GATES_OUTPUT_PATH))
    parser.add_argument("--manifest-path", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--envelope-path", default=str(DEFAULT_ENVELOPE_OUTPUT_PATH))
    parser.add_argument("--evidence-chain-path", default=str(DEFAULT_EVIDENCE_CHAIN_OUTPUT_PATH))
    parser.add_argument("--regression-matrix-path", default=str(DEFAULT_REGRESSION_MATRIX_OUTPUT_PATH))
    parser.add_argument("--clean-required", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("evaluate", "validate", "show"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--path", dest="command_path")
        subparser.add_argument("--manifest-path", dest="command_manifest_path")
        subparser.add_argument("--envelope-path", dest="command_envelope_path")
        subparser.add_argument("--evidence-chain-path", dest="command_evidence_chain_path")
        subparser.add_argument("--regression-matrix-path", dest="command_regression_matrix_path")
        subparser.add_argument("--clean-required", dest="command_clean_required", action="store_true")
    args = parser.parse_args(argv)
    path_arg = args.command_path or args.path
    manifest_path_arg = args.command_manifest_path or args.manifest_path
    envelope_path_arg = args.command_envelope_path or args.envelope_path
    evidence_chain_path_arg = args.command_evidence_chain_path or args.evidence_chain_path
    regression_matrix_path_arg = args.command_regression_matrix_path or args.regression_matrix_path
    clean_required = args.clean_required or args.command_clean_required

    root = repository_root_from()
    if args.command == "evaluate":
        gate_result = build_constitutional_gate_result(
            root,
            manifest_path=manifest_path_arg,
            envelope_path=envelope_path_arg,
            evidence_chain_path=evidence_chain_path_arg,
            regression_matrix_path=regression_matrix_path_arg,
            clean_required=clean_required,
        )
        path = write_constitutional_gate_result(gate_result, path_arg, repository_root=root)
        print(gate_result["gate_status"])
        print(path)
        return 0 if gate_result["gate_status"] == "CONSTITUTIONAL_GATES_PASS" else 1
    if args.command == "validate":
        gate_result = load_constitutional_gate_result(path_arg, repository_root=root)
        validation = validate_constitutional_gate_result(gate_result, repository_root=root, clean_required=clean_required)
        print(validation["gate_status"])
        return 0 if validation["gate_status"] == "CONSTITUTIONAL_GATES_PASS" else 1
    if args.command == "show":
        gate_result = load_constitutional_gate_result(path_arg, repository_root=root)
        validation = validate_constitutional_gate_result(gate_result, repository_root=root, clean_required=clean_required)
        summary = gate_result.get("gate_summary", {})
        print(validation["gate_status"])
        print(f"commit={gate_result.get('git_commit')}")
        print(f"branch={gate_result.get('git_branch')}")
        print(f"gate_digest={gate_result.get('gate_digest')}")
        print(f"bound_manifest_digest={gate_result.get('bound_manifest_digest')}")
        print(f"bound_execution_envelope_digest={gate_result.get('bound_execution_envelope_digest')}")
        print(f"bound_evidence_chain_digest={gate_result.get('bound_evidence_chain_digest')}")
        print(f"bound_regression_matrix_digest={gate_result.get('bound_regression_matrix_digest')}")
        print(f"gates={summary.get('total_gates')}")
        print(f"passed={summary.get('passed_gates')}")
        print(f"failed={summary.get('failed_gates')}")
        print(f"skipped={summary.get('skipped_gates')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
