from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from .common import (
    RecoveryError,
    atomic_json,
    atomic_write,
    canonical_bytes,
    exclusive_lock,
    fsync_directory,
    ensure_approved_destination,
    package_member_base,
    read_strict_json,
    remove_tree,
    resolve_beneath,
    scan_for_secrets,
    sha256_bytes,
)
from .inventory import validate_inventory
from .manifest import create_manifest, validate_manifest

FaultHook = Callable[[str], None]


def _fault(hook: FaultHook | None, point: str) -> None:
    if hook is not None:
        hook(point)


def create_backup(
    source_root: Path,
    inventory: Mapping[str, Any],
    destination: Path,
    *,
    repository_commit: str,
    measured_baseline_identifier: str,
    runtime_identity: str,
    generation: int,
    approved_backup_root: Path,
    creation_timestamp: str | None = None,
    predecessor_backup_identifier: str | None = None,
    fault_hook: FaultHook | None = None,
) -> dict[str, Any]:
    root = source_root.resolve()
    checked = validate_inventory(inventory)
    target = ensure_approved_destination(destination, approved_backup_root)
    if target.exists():
        raise RecoveryError("backup_destination_exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(f".{target.name}.backup.lock")
    stage = target.with_name(f".{target.name}.{uuid.uuid4().hex}.backup.tmp")
    with exclusive_lock(lock_path, collision_reason="concurrent_backup_publication"):
        try:
            stage.mkdir(parents=False)
            _fault(fault_hook, "backup_staging_created")
            copied: list[tuple[Path, Path, str, int]] = []
            for artefact in checked["artefacts"]:
                source = resolve_beneath(root, artefact["source_path"], label="source_path", must_exist=True)
                if source.is_symlink():
                    raise RecoveryError("backup_source_symlink")
                raw = source.read_bytes()
                scan_for_secrets(raw, logical_name=artefact["logical_name"])
                if sha256_bytes(raw) != artefact["current_digest"] or len(raw) != artefact["size_bytes"]:
                    raise RecoveryError("authoritative_state_changed_during_backup")
                member = resolve_beneath(
                    package_member_base(stage, artefact),
                    artefact["relative_recovery_path"],
                    label="package_member",
                )
                member.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(member, raw)
                copied.append((source, member, artefact["current_digest"], artefact["size_bytes"]))
                _fault(fault_hook, f"backup_member:{artefact['logical_name']}")
            for source, member, digest, size in copied:
                raw = member.read_bytes()
                if len(raw) != size or sha256_bytes(raw) != digest:
                    raise RecoveryError("backup_post_write_verification_failed")
                current = source.read_bytes()
                if len(current) != size or sha256_bytes(current) != digest:
                    raise RecoveryError("authoritative_state_changed_during_backup")
            manifest = create_manifest(
                checked,
                repository_commit=repository_commit,
                measured_baseline_identifier=measured_baseline_identifier,
                runtime_identity=runtime_identity,
                generation=generation,
                creation_timestamp=creation_timestamp,
                predecessor_backup_identifier=predecessor_backup_identifier,
            )
            atomic_json(stage / "manifest.json", manifest)
            payload = validate_manifest(manifest)
            atomic_write(stage / "COMPLETE", f"{payload['aggregate_digest']}\n".encode("ascii"))
            _fault(fault_hook, "backup_before_publication")
            validate_backup_package(stage)
            os.replace(stage, target)
            fsync_directory(target.parent)
            _fault(fault_hook, "backup_after_publication")
            return validate_backup_package(target)
        except RecoveryError:
            remove_tree(stage)
            raise
        except Exception as exc:
            remove_tree(stage)
            raise RecoveryError("backup_interrupted") from exc


def validate_backup_package(package_root: Path) -> dict[str, Any]:
    root = package_root.resolve()
    if root.is_symlink() or not root.is_dir():
        raise RecoveryError("backup_package_missing")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RecoveryError("backup_package_symlink")
    manifest_value = read_strict_json(root / "manifest.json", label="backup_manifest")
    payload = validate_manifest(manifest_value)
    completion = root / "COMPLETE"
    if completion.is_symlink() or not completion.is_file():
        raise RecoveryError("partial_backup")
    try:
        completion_digest = completion.read_text("ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise RecoveryError("partial_backup") from exc
    if completion_digest != payload["aggregate_digest"]:
        raise RecoveryError("backup_completion_invalid")
    expected_members = {"manifest.json", "COMPLETE"}
    for artefact in payload["artefact_inventory"]["artefacts"]:
        member = resolve_beneath(
            package_member_base(root, artefact),
            artefact["relative_recovery_path"],
            label="package_member",
            must_exist=True,
        )
        raw = member.read_bytes()
        scan_for_secrets(raw, logical_name=artefact["logical_name"])
        if len(raw) != artefact["size_bytes"] or sha256_bytes(raw) != artefact["current_digest"]:
            raise RecoveryError("backup_artefact_digest_mismatch")
        expected_members.add(member.relative_to(root).as_posix())
    actual_members = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual_members != expected_members:
        raise RecoveryError("unexpected_package_member")
    return payload
