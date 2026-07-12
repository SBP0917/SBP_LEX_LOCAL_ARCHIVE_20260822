from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .backup import validate_backup_package
from .common import (
    RecoveryError,
    atomic_json,
    bound_payload,
    canonical_bytes,
    ensure_approved_destination,
    exclusive_lock,
    fsync_directory,
    package_member_base,
    read_strict_json,
    remove_tree,
    resolve_beneath,
    sha256_bytes,
    validate_bound,
)
from .inventory import validate_artefact_content

POINTER_VERSION = "R1_DESKTOP_V1_AUTHORITATIVE_RESTORE_POINTER_V1"
FAILURE_VERSION = "R1_DESKTOP_V1_RESTORE_INOPERABILITY_V1"
FaultHook = Callable[[str], None]


def _fault(hook: FaultHook | None, point: str) -> None:
    if hook is not None:
        hook(point)


def _pointer_path(destination: Path) -> Path:
    return destination / "recovery.current.json"


def _failure_path(destination: Path) -> Path:
    return destination / "recovery.inoperable.json"


def _load_pointer(destination: Path) -> dict[str, Any] | None:
    path = _pointer_path(destination)
    if not path.exists():
        return None
    payload = validate_bound(read_strict_json(path, label="restore_pointer"), label="restore_pointer")
    if set(payload) != {
        "pointer_version", "desktop_scope", "backup_identifier", "generation",
        "repository_commit", "measured_baseline_identifier", "runtime_identity",
        "manifest_digest", "generation_path", "backup_history", "artefact_states",
    } or payload.get("pointer_version") != POINTER_VERSION:
        raise RecoveryError("restore_pointer_schema_invalid")
    return payload


def preflight_restore(
    package_root: Path,
    destination: Path,
    *,
    approved_destination_root: Path,
    expected_repository_commit: str,
    expected_measured_baseline_identifier: str,
    expected_runtime_identity: str,
    validation_root: Path | None = None,
) -> dict[str, Any]:
    target = ensure_approved_destination(destination, approved_destination_root)
    payload = validate_backup_package(package_root)
    if payload["repository_commit"] != expected_repository_commit:
        raise RecoveryError("repository_commit_mismatch")
    if payload["measured_baseline_identifier"] != expected_measured_baseline_identifier:
        raise RecoveryError("unknown_baseline_ancestor")
    if payload["runtime_identity"] != expected_runtime_identity:
        raise RecoveryError("runtime_identity_mismatch")
    current = _load_pointer(target) if target.exists() else None
    if current is None and target.exists() and any(target.iterdir()):
        raise RecoveryError("destination_not_empty")
    if current is None:
        if payload["generation"] != 1 or payload["predecessor_backup_identifier"] is not None:
            raise RecoveryError("baseline_lineage_fork")
    else:
        if payload["backup_identifier"] in current["backup_history"]:
            raise RecoveryError("replayed_backup_identifier")
        if payload["generation"] <= current["generation"]:
            raise RecoveryError("backup_generation_rollback")
        if payload["generation"] != current["generation"] + 1:
            raise RecoveryError("backup_generation_gap")
        if payload["predecessor_backup_identifier"] != current["backup_identifier"]:
            raise RecoveryError("broken_backup_ancestry")
        prior_states = current["artefact_states"]
        for artefact in payload["artefact_inventory"]["artefacts"]:
            prior = prior_states.get(artefact["logical_name"])
            if prior is None:
                continue
            if artefact["sequence"] < prior["sequence"]:
                raise RecoveryError("artefact_sequence_rollback")
            if artefact["sequence"] > prior["sequence"] and artefact["predecessor_identity"] != prior["digest"]:
                raise RecoveryError("artefact_predecessor_mismatch")
            if artefact["sequence"] == prior["sequence"] and artefact["current_digest"] != prior["digest"]:
                raise RecoveryError("mixed_generation_package")
    for artefact in payload["artefact_inventory"]["artefacts"]:
        member = resolve_beneath(
            package_member_base(package_root.resolve(), artefact),
            artefact["relative_recovery_path"],
            label="package_member",
            must_exist=True,
        )
        raw = member.read_bytes()
        validate_artefact_content(raw, artefact, validation_root=validation_root)
    return payload


def _run_fresh_process_checks(
    commands: Sequence[Sequence[str]], *, cwd: Path,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    cwd_text = str(cwd.resolve())
    environment = dict(os.environ)
    environment["SBP_LEX_RECOVERY_GENERATION_ROOT"] = cwd_text
    launch_cwd = cwd_text
    if os.name == "nt" and len(cwd_text) >= 240:
        launch_cwd = str(Path.cwd().resolve())
    for command in commands:
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise RecoveryError("fresh_process_command_invalid")
        try:
            completed = subprocess.run(
                list(command), cwd=launch_cwd, env=environment,
                check=False, capture_output=True, text=True,
                timeout=120, shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RecoveryError("fresh_process_validation_failed") from exc
        results.append({
            "command_digest": sha256_bytes("\x00".join(command).encode("utf-8")),
            "returncode": completed.returncode,
            "stdout_digest": sha256_bytes(completed.stdout.encode("utf-8")),
            "stderr_digest": sha256_bytes(completed.stderr.encode("utf-8")),
        })
        if completed.returncode != 0:
            raise RecoveryError("fresh_process_validation_failed")
    return results


def restore_backup(
    package_root: Path,
    destination: Path,
    *,
    approved_destination_root: Path,
    expected_repository_commit: str,
    expected_measured_baseline_identifier: str,
    expected_runtime_identity: str,
    validation_root: Path | None = None,
    fresh_process_commands: Sequence[Sequence[str]] = (),
    fault_hook: FaultHook | None = None,
) -> dict[str, Any]:
    target = ensure_approved_destination(destination, approved_destination_root)
    payload = preflight_restore(
        package_root,
        target,
        approved_destination_root=approved_destination_root,
        expected_repository_commit=expected_repository_commit,
        expected_measured_baseline_identifier=expected_measured_baseline_identifier,
        expected_runtime_identity=expected_runtime_identity,
        validation_root=validation_root,
    )
    lock = target.with_name(f".{target.name}.restore.lock")
    target.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(lock, collision_reason="second_authoritative_restore_writer"):
        current = _load_pointer(target) if target.exists() else None
        target.mkdir(parents=True, exist_ok=True)
        generations = target / ".recovery_generations"
        generations.mkdir(exist_ok=True)
        stage = target / f".restore.{uuid.uuid4().hex}.tmp"
        final = generations / payload["backup_identifier"]
        if final.exists():
            raise RecoveryError("replayed_backup_identifier")
        try:
            stage.mkdir()
            _fault(fault_hook, "restore_extraction_started")
            for artefact in payload["artefact_inventory"]["artefacts"]:
                source = resolve_beneath(
                    package_member_base(package_root.resolve(), artefact),
                    artefact["relative_recovery_path"],
                    label="package_member",
                    must_exist=True,
                )
                destination_member = resolve_beneath(
                    stage, artefact["relative_recovery_path"], label="restore_member",
                )
                destination_member.parent.mkdir(parents=True, exist_ok=True)
                raw = source.read_bytes()
                from .common import atomic_write

                atomic_write(destination_member, raw)
                _fault(fault_hook, f"restore_member:{artefact['logical_name']}")
            _fault(fault_hook, "restore_validation_started")
            for artefact in payload["artefact_inventory"]["artefacts"]:
                restored = resolve_beneath(stage, artefact["relative_recovery_path"], label="restore_member", must_exist=True)
                raw = restored.read_bytes()
                if len(raw) != artefact["size_bytes"] or sha256_bytes(raw) != artefact["current_digest"]:
                    raise RecoveryError("restored_artefact_digest_mismatch")
                validate_artefact_content(raw, artefact, validation_root=validation_root)
            _fault(fault_hook, "restore_before_authoritative_replacement")
            os.replace(stage, final)
            fsync_directory(generations)
            _fault(fault_hook, "restore_after_generation_publication")
            history = [] if current is None else list(current["backup_history"])
            history.append(payload["backup_identifier"])
            artefact_states = {
                item["logical_name"]: {
                    "sequence": item["sequence"],
                    "digest": item["current_digest"],
                    "authority_domain": item["authority_domain"],
                    "relative_recovery_path": item["relative_recovery_path"],
                }
                for item in payload["artefact_inventory"]["artefacts"]
            }
            pointer_payload = {
                "pointer_version": POINTER_VERSION,
                "desktop_scope": payload["desktop_scope"],
                "backup_identifier": payload["backup_identifier"],
                "generation": payload["generation"],
                "repository_commit": payload["repository_commit"],
                "measured_baseline_identifier": payload["measured_baseline_identifier"],
                "runtime_identity": payload["runtime_identity"],
                "manifest_digest": payload["aggregate_digest"],
                "generation_path": f".recovery_generations/{payload['backup_identifier']}",
                "backup_history": history,
                "artefact_states": artefact_states,
            }
            _fault(fault_hook, "restore_before_durability_flush")
            atomic_json(_pointer_path(target), bound_payload(pointer_payload))
            _fault(fault_hook, "restore_after_pointer_publication")
            _fault(fault_hook, "restore_after_durability_flush_before_fresh_startup")
            try:
                fresh_results = _run_fresh_process_checks(fresh_process_commands, cwd=final)
            except RecoveryError as exc:
                atomic_json(_failure_path(target), bound_payload({
                    "failure_version": FAILURE_VERSION,
                    "backup_identifier": payload["backup_identifier"],
                    "reason": exc.reason,
                }))
                raise
            _failure_path(target).unlink(missing_ok=True)
            result = validate_authoritative_restore(target, validation_root=validation_root)
            return {**result, "fresh_process_results": fresh_results}
        except RecoveryError:
            remove_tree(stage)
            raise
        except Exception as exc:
            remove_tree(stage)
            raise RecoveryError("restore_interrupted") from exc


def validate_authoritative_restore(
    destination: Path, *, validation_root: Path | None = None,
) -> dict[str, Any]:
    target = destination.resolve()
    if _failure_path(target).exists():
        failure = validate_bound(
            read_strict_json(_failure_path(target), label="restore_failure"),
            label="restore_failure",
        )
        raise RecoveryError(f"restore_persistently_inoperable:{failure.get('reason', 'unknown')}")
    pointer = _load_pointer(target)
    if pointer is None:
        raise RecoveryError("authoritative_restore_missing")
    generation = resolve_beneath(target, pointer["generation_path"], label="generation_path")
    if not generation.is_dir() or generation.is_symlink():
        raise RecoveryError("authoritative_generation_missing")
    states = pointer.get("artefact_states")
    if not isinstance(states, Mapping) or not states:
        raise RecoveryError("restore_pointer_states_invalid")
    for logical_name, state in states.items():
        if not isinstance(logical_name, str) or not isinstance(state, Mapping) or set(state) != {
            "sequence", "digest", "authority_domain", "relative_recovery_path"
        }:
            raise RecoveryError("restore_pointer_states_invalid")
        member = resolve_beneath(
            generation, state["relative_recovery_path"],
            label="authoritative_artefact", must_exist=True,
        )
        if sha256_bytes(member.read_bytes()) != state["digest"]:
            raise RecoveryError("authoritative_artefact_missing_or_substituted")
    expected_paths = {state["relative_recovery_path"] for state in states.values()}
    actual_paths = {
        path.relative_to(generation).as_posix()
        for path in generation.rglob("*") if path.is_file()
    }
    if actual_paths != expected_paths:
        raise RecoveryError("authoritative_generation_member_set_invalid")
    return {
        "status": "AUTHORITATIVE_RESTORE_VALID",
        "backup_identifier": pointer["backup_identifier"],
        "generation": pointer["generation"],
        "repository_commit": pointer["repository_commit"],
        "measured_baseline_identifier": pointer["measured_baseline_identifier"],
        "runtime_identity": pointer["runtime_identity"],
        "artefact_count": len(states),
    }
