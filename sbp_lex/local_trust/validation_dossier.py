from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.claims_to_evidence import (
    master_claims_to_evidence_index,
    reviewer_verification_commands_index,
    scope_and_exclusions_lock,
    university_handoff_readme_text,
)
from sbp_lex.local_trust.dossier_manifest import (
    DEFAULT_DOSSIER_DIR,
    DOSSIER_MANIFEST_FILE,
    EVIDENCE_ARTIFACT_INDEX_FILE,
    MASTER_CLAIMS_FILE,
    REVIEWER_COMMANDS_FILE,
    SCOPE_AND_EXCLUSIONS_FILE,
    UNIVERSITY_HANDOFF_README_FILE,
    VALIDATION_QUESTIONS_FILE,
    build_dossier_manifest,
    build_evidence_artifact_index,
)
from sbp_lex.local_trust.dossier_validator import validate_dossier_manifest
from sbp_lex.local_trust.manifest import repository_root_from
from sbp_lex.local_trust.paths import resolve_local_trust_path
from sbp_lex.local_trust.release_integrity import load_json
from sbp_lex.local_trust.release_manifest import collect_release_git_status
from sbp_lex.local_trust.validation_questions import validation_questions_index


def build_validation_dossier(
    repository_root: Path | str | None = None,
    *,
    output_dir: Path | str = DEFAULT_DOSSIER_DIR,
    clean_required: bool = False,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    reference_dir = Path(output_dir)
    dossier_dir = _resolve(root, output_dir)
    dossier_dir.mkdir(parents=True, exist_ok=True)

    claims = master_claims_to_evidence_index()
    questions = validation_questions_index()
    scope_lock = scope_and_exclusions_lock()
    commands = reviewer_verification_commands_index()
    commit = collect_release_git_status(root).get("git_commit")

    _write_json(claims, dossier_dir / MASTER_CLAIMS_FILE.name)
    _write_json(questions, dossier_dir / VALIDATION_QUESTIONS_FILE.name)
    _write_json(scope_lock, dossier_dir / SCOPE_AND_EXCLUSIONS_FILE.name)
    _write_json(commands, dossier_dir / REVIEWER_COMMANDS_FILE.name)
    (dossier_dir / UNIVERSITY_HANDOFF_README_FILE.name).write_text(
        university_handoff_readme_text(str(commit or "UNKNOWN")),
        encoding="utf-8",
    )

    artifact_index = build_evidence_artifact_index(
        root,
        output_dir=dossier_dir,
        reference_dir=reference_dir,
    )
    _write_json(artifact_index, dossier_dir / EVIDENCE_ARTIFACT_INDEX_FILE.name)

    manifest = build_dossier_manifest(
        root,
        claims_index=claims,
        validation_questions=questions,
        evidence_artifact_index=artifact_index,
        scope_lock=scope_lock,
        reviewer_commands=commands,
        output_dir=dossier_dir,
        output_reference_dir=reference_dir,
    )
    validation = validate_dossier_manifest(
        manifest,
        repository_root=root,
        claims_index=claims,
        validation_questions=questions,
        evidence_artifact_index=artifact_index,
        scope_lock=scope_lock,
        reviewer_commands=commands,
        clean_required=clean_required,
    )
    manifest["dossier_status"] = validation["dossier_status"]
    manifest["validation_failures"] = validation["validation_failures"]
    _write_json(manifest, dossier_dir / DOSSIER_MANIFEST_FILE.name)
    return {
        "dossier_status": manifest["dossier_status"],
        "dossier_digest": manifest["dossier_digest"],
        "dossier_dir": str(dossier_dir),
        "manifest": manifest,
        "claims_index": claims,
        "validation_questions": questions,
        "evidence_artifact_index": artifact_index,
        "scope_lock": scope_lock,
        "reviewer_commands": commands,
    }


def validate_validation_dossier(
    repository_root: Path | str | None = None,
    *,
    output_dir: Path | str = DEFAULT_DOSSIER_DIR,
    clean_required: bool = False,
    current_validation: bool = False,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    dossier_dir = _resolve(root, output_dir)
    manifest = load_json(dossier_dir / DOSSIER_MANIFEST_FILE.name)
    claims = load_json(dossier_dir / MASTER_CLAIMS_FILE.name)
    questions = load_json(dossier_dir / VALIDATION_QUESTIONS_FILE.name)
    artifact_index = load_json(dossier_dir / EVIDENCE_ARTIFACT_INDEX_FILE.name)
    scope_lock = load_json(dossier_dir / SCOPE_AND_EXCLUSIONS_FILE.name)
    commands = load_json(dossier_dir / REVIEWER_COMMANDS_FILE.name)
    return validate_dossier_manifest(
        manifest,
        repository_root=root,
        claims_index=claims,
        validation_questions=questions,
        evidence_artifact_index=artifact_index,
        scope_lock=scope_lock,
        reviewer_commands=commands,
        clean_required=clean_required,
        current_validation=current_validation,
    )


def load_dossier_manifest(
    repository_root: Path | str | None = None,
    *,
    output_dir: Path | str = DEFAULT_DOSSIER_DIR,
) -> dict[str, Any]:
    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    return load_json(_resolve(root, output_dir) / DOSSIER_MANIFEST_FILE.name)


def _write_json(value: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve(repository_root: Path, path: Path | str) -> Path:
    return resolve_local_trust_path(repository_root, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SBP-LEX university validation dossier")
    parser.add_argument("--path", default=str(DEFAULT_DOSSIER_DIR))
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
        result = build_validation_dossier(root, output_dir=path_arg, clean_required=clean_required)
        print(result["dossier_status"])
        print(result["dossier_dir"])
        return 0 if result["dossier_status"] == "VALIDATION_DOSSIER_READY" else 1
    if args.command == "validate":
        validation = validate_validation_dossier(root, output_dir=path_arg, clean_required=clean_required)
        print(validation["dossier_status"])
        return 0 if validation["dossier_status"] == "VALIDATION_DOSSIER_READY" else 1
    if args.command == "show":
        manifest = load_dossier_manifest(root, output_dir=path_arg)
        validation = validate_validation_dossier(root, output_dir=path_arg, clean_required=clean_required)
        summary = manifest.get("dossier_summary", {})
        print(validation["dossier_status"])
        print(f"commit={manifest.get('git_commit')}")
        print(f"branch={manifest.get('git_branch')}")
        print(f"dossier_digest={manifest.get('dossier_digest')}")
        print(f"claims={summary.get('claim_count')}")
        print(f"validation_questions={summary.get('validation_question_count')}")
        print(f"evidence_artifacts={summary.get('evidence_artifact_count')}")
        print(f"reviewer_commands={summary.get('reviewer_command_count')}")
        print(f"next_phase={summary.get('next_phase')}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
