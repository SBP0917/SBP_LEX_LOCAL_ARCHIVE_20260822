from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.claims_seed import (
    boundary_and_scope_lock,
    claims_to_evidence_seed,
    release_readme_text,
    verification_commands_index,
)
from sbp_lex.local_trust.manifest import repository_root_from
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.release_hash_index import (
    ARTIFACT_HASH_INDEX_FILE,
    BOUNDARY_AND_SCOPE_LOCK_FILE,
    CLAIMS_TO_EVIDENCE_SEED_FILE,
    RELEASE_BUNDLE_DIR,
    RELEASE_MANIFEST_FILE,
    RELEASE_README_FILE,
    VERIFICATION_COMMANDS_FILE,
    build_artifact_hash_index,
)
from sbp_lex.local_trust.release_manifest import build_release_manifest
from sbp_lex.local_trust.release_validator import validate_release_manifest

DEFAULT_RELEASE_BUNDLE_DIR = RELEASE_BUNDLE_DIR


def build_release_integrity_bundle(
    repository_root: Path | str | None = None,
    *,
    output_dir: Path | str = DEFAULT_RELEASE_BUNDLE_DIR,
    clean_required: bool = False,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    reference_dir = Path(output_dir)
    bundle_dir = _resolve(root, output_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    commands = verification_commands_index()
    claims = claims_to_evidence_seed()
    boundary = boundary_and_scope_lock()
    _write_json(commands, bundle_dir / VERIFICATION_COMMANDS_FILE.name)
    _write_json(claims, bundle_dir / CLAIMS_TO_EVIDENCE_SEED_FILE.name)
    _write_json(boundary, bundle_dir / BOUNDARY_AND_SCOPE_LOCK_FILE.name)
    (bundle_dir / RELEASE_README_FILE.name).write_text(release_readme_text(), encoding="utf-8")

    artifact_index = build_artifact_hash_index(
        root,
        bundle_dir=bundle_dir,
        reference_dir=reference_dir,
    )
    _write_json(artifact_index, bundle_dir / ARTIFACT_HASH_INDEX_FILE.name)

    manifest = build_release_manifest(
        root,
        artifact_hash_index=artifact_index,
        verification_commands=commands,
        claims_to_evidence_seed=claims,
        boundary_lock=boundary,
        bundle_dir=bundle_dir,
        bundle_reference_dir=reference_dir,
    )
    validation = validate_release_manifest(
        manifest,
        repository_root=root,
        artifact_hash_index=artifact_index,
        verification_commands=commands,
        claims_to_evidence_seed=claims,
        boundary_lock=boundary,
        clean_required=clean_required,
    )
    manifest["release_status"] = validation["release_status"]
    manifest["validation_failures"] = validation["validation_failures"]
    _write_json(manifest, bundle_dir / RELEASE_MANIFEST_FILE.name)
    return {
        "release_status": manifest["release_status"],
        "release_digest": manifest["release_digest"],
        "bundle_dir": str(bundle_dir),
        "manifest": manifest,
        "artifact_hash_index": artifact_index,
        "verification_commands": commands,
        "claims_to_evidence_seed": claims,
        "boundary_lock": boundary,
    }


def validate_release_integrity_bundle(
    repository_root: Path | str | None = None,
    *,
    output_dir: Path | str = DEFAULT_RELEASE_BUNDLE_DIR,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    bundle_dir = _resolve(root, output_dir)
    manifest = load_json(bundle_dir / RELEASE_MANIFEST_FILE.name)
    artifact_index = load_json(bundle_dir / ARTIFACT_HASH_INDEX_FILE.name)
    commands = load_json(bundle_dir / VERIFICATION_COMMANDS_FILE.name)
    claims = load_json(bundle_dir / CLAIMS_TO_EVIDENCE_SEED_FILE.name)
    boundary = load_json(bundle_dir / BOUNDARY_AND_SCOPE_LOCK_FILE.name)
    return validate_release_manifest(
        manifest,
        repository_root=root,
        artifact_hash_index=artifact_index,
        verification_commands=commands,
        claims_to_evidence_seed=claims,
        boundary_lock=boundary,
        clean_required=clean_required,
        current_validation=current_validation,
    )


def load_release_manifest(
    repository_root: Path | str | None = None,
    *,
    output_dir: Path | str = DEFAULT_RELEASE_BUNDLE_DIR,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    return load_json(_resolve(root, output_dir) / RELEASE_MANIFEST_FILE.name)


def load_json(path: Path | str) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("release_integrity_json_must_be_object")
    return loaded


def _write_json(value: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve(repository_root: Path, path: Path | str) -> Path:
    return resolve_local_trust_path(repository_root, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX release integrity bundle")
    parser.add_argument("--path", default=str(DEFAULT_RELEASE_BUNDLE_DIR))
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
        result = build_release_integrity_bundle(root, output_dir=path_arg, clean_required=clean_required)
        print(result["release_status"])
        print(result["bundle_dir"])
        return 0 if result["release_status"] == "RELEASE_INTEGRITY_PASS" else 1
    if args.command == "validate":
        validation = validate_release_integrity_bundle(root, output_dir=path_arg, clean_required=clean_required)
        print(validation["release_status"])
        return 0 if validation["release_status"] == "RELEASE_INTEGRITY_PASS" else 1
    if args.command == "show":
        manifest = load_release_manifest(root, output_dir=path_arg)
        validation = validate_release_integrity_bundle(root, output_dir=path_arg, clean_required=clean_required)
        artifact_summary = manifest.get("artifact_hash_index_summary", {})
        command_summary = manifest.get("verification_command_summary", {})
        claim_summary = manifest.get("claim_seed_summary", {})
        print(validation["release_status"])
        print(f"commit={manifest.get('git_commit')}")
        print(f"branch={manifest.get('git_branch')}")
        print(f"release_digest={manifest.get('release_digest')}")
        print(f"artifacts={artifact_summary.get('artifact_count')}")
        print(f"required_artifacts={artifact_summary.get('required_artifact_count')}")
        print(f"missing_artifacts={artifact_summary.get('missing_artifact_count')}")
        print(f"verification_commands={command_summary.get('verification_command_count')}")
        print(f"claim_seeds={claim_summary.get('claim_seed_count')}")
        print(f"next_phase={manifest.get('boundary_lock_summary', {}).get('next_phase')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
