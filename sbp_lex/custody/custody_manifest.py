from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Mapping, MutableSet

from sbp_lex.recovery.backup import validate_backup_package
from sbp_lex.recovery.common import ensure_approved_destination
from sbp_lex.security.pqc import generate_digest

from .common import CustodyError, DESKTOP_SCOPE, HEX40, HEX64, R3_VERSION, atomic_json, read_json, require_identifier, seal, tree_digest, unseal, utc_text

MANIFEST_NAME = "custody_manifest.json"
COMPLETE_NAME = "CUSTODY_COMPLETE"


def create_custody_manifest(
    backup_root: Path, *, custody_chain_identifier: str, sequence: int,
    export_timestamp: str, key_custody_manifest_digest: str,
    predecessor_custody_package_identifier: str | None = None,
) -> dict[str, Any]:
    backup = validate_backup_package(backup_root)
    require_identifier(custody_chain_identifier, "custody_chain_identifier_invalid")
    if sequence <= 0 or not HEX64.fullmatch(key_custody_manifest_digest):
        raise CustodyError("custody_manifest_input_invalid")
    if predecessor_custody_package_identifier is not None:
        require_identifier(predecessor_custody_package_identifier, "predecessor_custody_package_invalid")
    backup_digest = tree_digest(backup_root)
    seed = {"backup_identifier": backup["backup_identifier"], "backup_package_digest": backup_digest, "custody_chain_identifier": custody_chain_identifier, "sequence": sequence, "predecessor": predecessor_custody_package_identifier}
    package_identifier = f"R3_CUSTODY_{sequence:08d}_{generate_digest(seed)[:24].upper()}"
    payload = {
        "manifest_version": "R3_OFF_HOST_CUSTODY_MANIFEST_V1",
        "custody_version": R3_VERSION,
        "desktop_scope": DESKTOP_SCOPE,
        "custody_package_identifier": package_identifier,
        "custody_chain_identifier": custody_chain_identifier,
        "sequence": sequence,
        "export_timestamp": utc_text(export_timestamp),
        "predecessor_custody_package_identifier": predecessor_custody_package_identifier,
        "repository_commit": backup["repository_commit"],
        "measured_baseline_identifier": backup["measured_baseline_identifier"],
        "runtime_identity": backup["runtime_identity"],
        "backup_identifier": backup["backup_identifier"],
        "backup_generation": backup["generation"],
        "backup_manifest_digest": backup["aggregate_digest"],
        "backup_package_digest": backup_digest,
        "key_custody_manifest_digest": key_custody_manifest_digest,
        "custody_status": "SEALED_FOR_EXTERNAL_CUSTODY",
    }
    payload["custody_manifest_digest"] = generate_digest(payload)
    return seal(payload)


def validate_custody_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = unseal(value, label="custody_manifest")
    digest = payload.get("custody_manifest_digest")
    core = {key: item for key, item in payload.items() if key != "custody_manifest_digest"}
    if digest != generate_digest(core) or payload.get("manifest_version") != "R3_OFF_HOST_CUSTODY_MANIFEST_V1":
        raise CustodyError("custody_manifest_digest_invalid")
    if payload.get("desktop_scope") != DESKTOP_SCOPE or payload.get("custody_status") != "SEALED_FOR_EXTERNAL_CUSTODY":
        raise CustodyError("foreign_custody_package")
    for key in ("custody_package_identifier", "custody_chain_identifier", "backup_identifier"):
        require_identifier(payload.get(key), f"{key}_invalid")
    if not HEX40.fullmatch(str(payload.get("repository_commit", ""))) or not HEX64.fullmatch(str(payload.get("runtime_identity", ""))):
        raise CustodyError("custody_repository_binding_invalid")
    if not isinstance(payload.get("sequence"), int) or payload["sequence"] <= 0:
        raise CustodyError("custody_sequence_invalid")
    utc_text(str(payload.get("export_timestamp")))
    return payload


def export_custody_package(
    backup_root: Path, destination: Path, *, approved_export_root: Path,
    custody_chain_identifier: str, sequence: int, export_timestamp: str,
    key_custody_manifest_digest: str, predecessor_custody_package_identifier: str | None = None,
) -> dict[str, Any]:
    target = ensure_approved_destination(destination, approved_export_root)
    if target.exists(): raise CustodyError("custody_export_destination_exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = target.with_name(f".{target.name}.{uuid.uuid4().hex}.custody.tmp")
    try:
        stage.mkdir()
        shutil.copytree(backup_root, stage / "backup")
        manifest = create_custody_manifest(stage / "backup", custody_chain_identifier=custody_chain_identifier, sequence=sequence, export_timestamp=export_timestamp, key_custody_manifest_digest=key_custody_manifest_digest, predecessor_custody_package_identifier=predecessor_custody_package_identifier)
        atomic_json(stage / MANIFEST_NAME, manifest)
        payload = validate_custody_manifest(manifest)
        (stage / COMPLETE_NAME).write_text(payload["custody_manifest_digest"] + "\n", encoding="ascii")
        validate_custody_package(stage)
        os.replace(stage, target)
        return validate_custody_package(target)
    except CustodyError:
        shutil.rmtree(stage, ignore_errors=True); raise
    except Exception as exc:
        shutil.rmtree(stage, ignore_errors=True); raise CustodyError("custody_export_failed") from exc


def validate_custody_package(
    package_root: Path, *, expected_repository_commit: str | None = None,
    expected_measured_baseline_identifier: str | None = None,
    expected_runtime_identity: str | None = None, minimum_backup_generation: int | None = None,
    seen_package_identifiers: MutableSet[str] | None = None,
) -> dict[str, Any]:
    root = package_root.resolve()
    if root.is_symlink() or not root.is_dir(): raise CustodyError("custody_package_missing")
    if {item.name for item in root.iterdir()} != {"backup", MANIFEST_NAME, COMPLETE_NAME}:
        raise CustodyError("unexpected_custody_package_member")
    payload = validate_custody_manifest(read_json(root / MANIFEST_NAME, label="custody_manifest"))
    backup = validate_backup_package(root / "backup")
    if tree_digest(root / "backup") != payload["backup_package_digest"] or backup["aggregate_digest"] != payload["backup_manifest_digest"]:
        raise CustodyError("substituted_custody_package")
    if backup["backup_identifier"] != payload["backup_identifier"] or backup["generation"] != payload["backup_generation"]:
        raise CustodyError("backup_custody_binding_invalid")
    complete = root / COMPLETE_NAME
    if not complete.is_file() or complete.read_text("ascii").strip() != payload["custody_manifest_digest"]:
        raise CustodyError("corrupted_custody_package")
    comparisons = ((expected_repository_commit, "repository_commit", "foreign_repository_package"), (expected_measured_baseline_identifier, "measured_baseline_identifier", "stale_measured_baseline"), (expected_runtime_identity, "runtime_identity", "runtime_identity_mismatch"))
    for expected, key, reason in comparisons:
        if expected is not None and payload[key] != expected: raise CustodyError(reason)
    if minimum_backup_generation is not None and payload["backup_generation"] < minimum_backup_generation:
        raise CustodyError("stale_custody_package")
    if seen_package_identifiers is not None:
        identifier = payload["custody_package_identifier"]
        if identifier in seen_package_identifiers: raise CustodyError("replayed_custody_package")
        seen_package_identifiers.add(identifier)
    return payload
