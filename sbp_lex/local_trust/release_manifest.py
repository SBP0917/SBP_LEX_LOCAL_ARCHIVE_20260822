from __future__ import annotations

import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.local_trust.local_trust_capstone import DEFAULT_CAPSTONE_OUTPUT_PATH, load_local_trust_capstone
from sbp_lex.local_trust.manifest import canonical_json, repository_root_from
from sbp_lex.local_trust.release_hash_index import (
    ARTIFACT_HASH_INDEX_FILE,
    BOUNDARY_AND_SCOPE_LOCK_FILE,
    CLAIMS_TO_EVIDENCE_SEED_FILE,
    RELEASE_README_FILE,
    VERIFICATION_COMMANDS_FILE,
    file_sha256,
)

RELEASE_INTEGRITY_SIGNATURE_MODE = "RELEASE_INTEGRITY_DETERMINISTIC_PLACEHOLDER"
RELEASE_MANIFEST_VERSION = "18.7F"

_DIGEST_EXCLUDED_FIELDS = {
    "release_status",
    "validation_failures",
    "release_payload_digest",
    "release_digest",
    "release_signature",
}


def build_release_manifest(
    repository_root: Path | str | None = None,
    *,
    artifact_hash_index: Mapping[str, Any],
    verification_commands: Mapping[str, Any],
    claims_to_evidence_seed: Mapping[str, Any],
    boundary_lock: Mapping[str, Any],
    capstone_path: Path | str = DEFAULT_CAPSTONE_OUTPUT_PATH,
    bundle_dir: Path | str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    from sbp_lex.local_trust.release_validator import validate_release_manifest

    root = Path(repository_root).resolve() if repository_root is not None else repository_root_from()
    output_dir = Path(bundle_dir) if bundle_dir is not None else ARTIFACT_HASH_INDEX_FILE.parent
    capstone = load_local_trust_capstone(capstone_path, repository_root=root)
    git = collect_release_git_status(root)
    manifest: dict[str, Any] = {
        "release_manifest_type": "release_integrity_reproducible_validation_bundle",
        "release_manifest_version": RELEASE_MANIFEST_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_root": str(root),
        "git_commit": git.get("git_commit"),
        "git_branch": git.get("git_branch"),
        "github_remote": _origin_remote(root),
        "github_sync_status": git,
        "release_scope": release_scope(),
        "source_phase": "18.7F",
        "completed_local_trust_phases": [
            phase.get("phase_id")
            for phase in capstone.get("completed_phases", [])
            if isinstance(phase, Mapping)
        ],
        "bound_manifest_digest": capstone.get("bound_manifest_digest"),
        "bound_execution_envelope_digest": capstone.get("bound_execution_envelope_digest"),
        "bound_evidence_chain_digest": capstone.get("bound_evidence_chain_digest"),
        "bound_regression_matrix_digest": capstone.get("bound_regression_matrix_digest"),
        "bound_constitutional_gates_digest": capstone.get("bound_constitutional_gates_digest"),
        "bound_toolchain_guard_digest": capstone.get("bound_toolchain_guard_digest"),
        "bound_capstone_digest": capstone.get("capstone_digest"),
        "release_artifacts": release_artifact_references(root, output_dir),
        "verification_commands_reference": bundle_file_reference(root, output_dir / VERIFICATION_COMMANDS_FILE.name),
        "claims_to_evidence_seed_reference": bundle_file_reference(root, output_dir / CLAIMS_TO_EVIDENCE_SEED_FILE.name),
        "boundary_lock_reference": bundle_file_reference(root, output_dir / BOUNDARY_AND_SCOPE_LOCK_FILE.name),
        "artifact_hash_index_reference": bundle_file_reference(root, output_dir / ARTIFACT_HASH_INDEX_FILE.name),
        "artifact_hash_index_summary": artifact_hash_index.get("artifact_summary", {}),
        "verification_command_summary": {
            "verification_command_count": len(verification_commands.get("commands", [])),
        },
        "claim_seed_summary": {
            "claim_seed_count": len(claims_to_evidence_seed.get("claim_seeds", [])),
        },
        "boundary_lock_summary": {
            "review_readiness_only": boundary_lock.get("review_readiness_only"),
            "phase_19_not_started": boundary_lock.get("phase_19_not_started"),
            "next_phase": boundary_lock.get("next_phase", {}).get("phase_id")
            if isinstance(boundary_lock.get("next_phase"), Mapping)
            else None,
        },
        "signature_mode": RELEASE_INTEGRITY_SIGNATURE_MODE,
        "release_status": "RELEASE_INTEGRITY_INCOMPLETE",
        "validation_failures": [],
    }
    payload_digest = hash_release_payload(manifest)
    signature = release_signature_for(payload_digest)
    manifest["release_payload_digest"] = payload_digest
    manifest["release_signature"] = signature
    manifest["release_digest"] = release_digest_for(payload_digest, signature)
    validation = validate_release_manifest(
        manifest,
        repository_root=root,
        artifact_hash_index=artifact_hash_index,
        verification_commands=verification_commands,
        claims_to_evidence_seed=claims_to_evidence_seed,
        boundary_lock=boundary_lock,
    )
    manifest["release_status"] = validation["release_status"]
    manifest["validation_failures"] = validation["validation_failures"]
    return manifest


def release_scope() -> dict[str, Any]:
    return {
        "phase_id": "18.7F",
        "phase_name": "Release Integrity Package / Reproducible Validation Bundle",
        "purpose": "Controlled, reproducible, externally reviewable validation package.",
        "review_readiness_only": True,
        "not_external_validation": True,
        "not_certification": True,
        "not_runtime_authority": True,
        "phase_19_not_started": True,
        "next_phase": "18.7G",
        "next_phase_implemented": False,
    }


def release_artifact_references(repository_root: Path, output_dir: Path) -> list[dict[str, Any]]:
    return [
        bundle_file_reference(repository_root, output_dir / ARTIFACT_HASH_INDEX_FILE.name),
        bundle_file_reference(repository_root, output_dir / VERIFICATION_COMMANDS_FILE.name),
        bundle_file_reference(repository_root, output_dir / CLAIMS_TO_EVIDENCE_SEED_FILE.name),
        bundle_file_reference(repository_root, output_dir / BOUNDARY_AND_SCOPE_LOCK_FILE.name),
        bundle_file_reference(repository_root, output_dir / RELEASE_README_FILE.name),
    ]


def bundle_file_reference(repository_root: Path, relative_path: Path) -> dict[str, Any]:
    path = relative_path if relative_path.is_absolute() else repository_root / relative_path
    exists = path.exists() and path.is_file()
    return {
        "path": relative_path.as_posix(),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
        "sha256": file_sha256(path) if exists else "MISSING",
    }


def collect_release_git_status(repository_root: Path) -> dict[str, Any]:
    branch = _git(repository_root, "branch", "--show-current")
    commit = _git(repository_root, "rev-parse", "HEAD")
    branch_status = _git(repository_root, "status", "--short", "--branch", "--untracked-files=no")
    short = _git(repository_root, "status", "--short")
    branch_name = branch.get("stdout") or None
    branch_text = branch_status.get("stdout", "")
    return {
        "git_branch": branch_name,
        "git_commit": commit.get("stdout") or None,
        "branch_status_short": branch_text,
        "tracked_working_tree_clean": _tracked_status_clean(branch_text),
        "working_tree_clean": short.get("stdout", "") == "",
        "branch_has_ahead_count": "[ahead " in branch_text,
        "branch_has_behind_count": "[behind " in branch_text,
        "synced_to_origin_branch": bool(branch_name)
        and f"{branch_name}...origin/{branch_name}" in branch_text
        and "[ahead " not in branch_text
        and "[behind " not in branch_text,
    }


def payload_for_digest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in manifest.items() if key not in _DIGEST_EXCLUDED_FIELDS}


def hash_release_payload(manifest: Mapping[str, Any]) -> str:
    return sha256(canonical_json(payload_for_digest(manifest)).encode("utf-8")).hexdigest()


def release_signature_for(payload_digest: str) -> str:
    return sha256(f"{RELEASE_INTEGRITY_SIGNATURE_MODE}:{payload_digest}".encode("utf-8")).hexdigest()


def release_digest_for(payload_digest: str, signature: str) -> str:
    return sha256(
        canonical_json(
            {
                "release_payload_digest": payload_digest,
                "release_signature": signature,
                "signature_mode": RELEASE_INTEGRITY_SIGNATURE_MODE,
            }
        ).encode("utf-8")
    ).hexdigest()


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
