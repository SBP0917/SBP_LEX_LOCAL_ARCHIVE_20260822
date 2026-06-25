from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.adversarial_runner import adversarial_summary, run_adversarial_cases
from sbp_lex.local_trust.adversarial_validator import validate_adversarial_harness
from sbp_lex.local_trust.manifest import canonical_json, repository_root_from
from sbp_lex.local_trust.release_integrity import DEFAULT_RELEASE_BUNDLE_DIR, load_json
from sbp_lex.local_trust.release_manifest import collect_release_git_status

ADVERSARIAL_HARNESS_SIGNATURE_MODE = "ADVERSARIAL_NEGATIVE_HARNESS_DETERMINISTIC_PLACEHOLDER"
ADVERSARIAL_HARNESS_VERSION = "18.7G"
DEFAULT_ADVERSARIAL_OUTPUT_PATH = Path("outputs/adversarial_local_trust_negative_harness.json")

_DIGEST_EXCLUDED_FIELDS = {
    "adversarial_status",
    "validation_failures",
    "adversarial_payload_digest",
    "adversarial_digest",
    "adversarial_signature",
}


def build_adversarial_harness(
    repository_root: Path | str | None = None,
    *,
    clean_required: bool = False,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.adversarial_validator import ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    git = collect_release_git_status(root)
    bindings = collect_bound_digests(root)
    cases = run_adversarial_cases(root)
    harness: dict[str, Any] = {
        "adversarial_harness_type": "adversarial_local_trust_negative_test_harness",
        "adversarial_harness_version": ADVERSARIAL_HARNESS_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "github_remote": _origin_remote(root),
        "github_sync_status": git,
        "source_phase": "18.7G",
        "bound_manifest_digest": bindings["manifest"],
        "bound_execution_envelope_digest": bindings["execution_envelope"],
        "bound_evidence_chain_digest": bindings["evidence_chain"],
        "bound_regression_matrix_digest": bindings["regression_matrix"],
        "bound_constitutional_gates_digest": bindings["constitutional_gates"],
        "bound_toolchain_guard_digest": bindings["toolchain_guard"],
        "bound_capstone_digest": bindings["capstone"],
        "bound_release_integrity_digest": bindings["release_integrity"],
        "adversarial_case_results": cases,
        "adversarial_summary": adversarial_summary(cases),
        "boundary_confirmation_summary": boundary_confirmation_summary(),
        "next_phase_readiness": next_phase_readiness(),
        "signature_mode": ADVERSARIAL_HARNESS_SIGNATURE_MODE,
        "adversarial_status": ADVERSARIAL_NEGATIVE_HARNESS_INCOMPLETE,
        "validation_failures": [],
    }
    payload = hash_adversarial_payload(harness)
    signature = adversarial_signature_for(payload)
    harness["adversarial_payload_digest"] = payload
    harness["adversarial_signature"] = signature
    harness["adversarial_digest"] = adversarial_digest_for(payload, signature)
    validation = validate_adversarial_harness(harness, repository_root=root, clean_required=clean_required)
    harness["adversarial_status"] = validation["adversarial_status"]
    harness["validation_failures"] = validation["validation_failures"]
    return harness


def collect_bound_digests(repository_root: Path) -> dict[str, str]:
    return {
        "manifest": str(load_json(repository_root / "outputs/local_trust_root_manifest.json").get("manifest_digest")),
        "execution_envelope": str(
            load_json(repository_root / "outputs/local_execution_environment_trust_envelope.json").get("envelope_digest")
        ),
        "evidence_chain": str(load_json(repository_root / "outputs/local_evidence_chain.json").get("chain_digest")),
        "regression_matrix": str(
            load_json(repository_root / "outputs/local_trust_regression_matrix.json").get("matrix_digest")
        ),
        "constitutional_gates": str(load_json(repository_root / "outputs/local_constitutional_gates.json").get("gate_digest")),
        "toolchain_guard": str(load_json(repository_root / "outputs/local_toolchain_guard.json").get("toolchain_digest")),
        "capstone": str(load_json(repository_root / "outputs/local_trust_25_year_capstone.json").get("capstone_digest")),
        "release_integrity": str(
            load_json(repository_root / DEFAULT_RELEASE_BUNDLE_DIR / "RELEASE_MANIFEST.json").get("release_digest")
        ),
    }


def boundary_confirmation_summary() -> dict[str, Any]:
    return {
        "runtimeActivationIntroduced": False,
        "sbpLexRuntimeAuthorityChanged": False,
        "governanceBehaviorChanged": False,
        "proceduralTruthBehaviorChanged": False,
        "executionGateBehaviorChanged": False,
        "hardEntryGateBehaviorChanged": False,
        "skgDtnAuthorityAdded": False,
        "skgDtnExternalNonAuthoritative": True,
        "futureDistributedOrMobileRuntimeWorkIntroduced": False,
        "phase19Started": False,
        "externalValidationClaimed": False,
        "certificationClaimed": False,
    }


def next_phase_readiness() -> dict[str, Any]:
    return {
        "phase_id": "18.8",
        "phase_name": "Master Claims-to-Evidence Index / University Validation Dossier",
        "readiness_marker_only": True,
        "implemented_in_this_phase": False,
    }


def payload_for_digest(harness: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in harness.items() if key not in _DIGEST_EXCLUDED_FIELDS}


def hash_adversarial_payload(harness: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(harness)).encode("utf-8")).hexdigest()


def adversarial_signature_for(payload_digest: str) -> str:
    return sha256(f"{ADVERSARIAL_HARNESS_SIGNATURE_MODE}:{payload_digest}".encode("utf-8")).hexdigest()


def adversarial_digest_for(payload_digest: str, signature: str) -> str:
    return sha256(
        canonical_json(
            {
                "adversarial_payload_digest": payload_digest,
                "adversarial_signature": signature,
                "signature_mode": ADVERSARIAL_HARNESS_SIGNATURE_MODE,
            }
        ).encode("utf-8")
    ).hexdigest()


def write_adversarial_harness(
    harness: Mapping[str, Any],
    path: Path | str = DEFAULT_ADVERSARIAL_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> Path:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output = _resolve(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(harness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_adversarial_harness(
    path: Path | str = DEFAULT_ADVERSARIAL_OUTPUT_PATH,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    source = _resolve(root, path)
    with source.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("adversarial_harness_must_be_object")
    return loaded


def validate_adversarial_harness_file(
    repository_root: Path | str | None = None,
    *,
    path: Path | str = DEFAULT_ADVERSARIAL_OUTPUT_PATH,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    harness = load_adversarial_harness(path, repository_root=root)
    return validate_adversarial_harness(
        harness,
        repository_root=root,
        clean_required=clean_required,
        current_validation=current_validation,
    )


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


def _resolve(repository_root: Path, path: Path | str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else repository_root / candidate


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX adversarial local trust negative-test harness")
    parser.add_argument("--path", default=str(DEFAULT_ADVERSARIAL_OUTPUT_PATH))
    parser.add_argument("--clean-required", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("run", "validate", "show"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--path", dest="command_path")
        subparser.add_argument("--clean-required", dest="command_clean_required", action="store_true")
    args = parser.parse_args(argv)
    path_arg = args.command_path or args.path
    clean_required = args.clean_required or args.command_clean_required

    root = repository_root_from()
    if args.command == "run":
        harness = build_adversarial_harness(root, clean_required=clean_required)
        path = write_adversarial_harness(harness, path_arg, repository_root=root)
        print(harness["adversarial_status"])
        print(path)
        return 0 if harness["adversarial_status"] == "ADVERSARIAL_NEGATIVE_HARNESS_PASS" else 1
    if args.command == "validate":
        validation = validate_adversarial_harness_file(root, path=path_arg, clean_required=clean_required)
        print(validation["adversarial_status"])
        return 0 if validation["adversarial_status"] == "ADVERSARIAL_NEGATIVE_HARNESS_PASS" else 1
    if args.command == "show":
        harness = load_adversarial_harness(path_arg, repository_root=root)
        validation = validate_adversarial_harness_file(root, path=path_arg, clean_required=clean_required)
        summary = harness.get("adversarial_summary", {})
        print(validation["adversarial_status"])
        print(f"commit={harness.get('git_commit')}")
        print(f"branch={harness.get('git_branch')}")
        print(f"adversarial_digest={harness.get('adversarial_digest')}")
        print(f"cases={summary.get('total_cases')}")
        print(f"passed={summary.get('passed_cases')}")
        print(f"failed={summary.get('failed_cases')}")
        print(f"skipped={summary.get('skipped_cases')}")
        print(f"next_phase={harness.get('next_phase_readiness', {}).get('phase_id')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

