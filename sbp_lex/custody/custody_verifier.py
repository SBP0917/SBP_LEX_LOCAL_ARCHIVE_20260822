from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, MutableSet, Sequence

from .common import CustodyError, unseal
from .custody_chain import validate_chain
from .custody_manifest import validate_custody_package
from .external_key_custody import validate_key_custody_manifest
from .recovery_media import validate_media_manifest


def verify_custody_continuity(
    package_root: Path, *, key_custody_manifest: Mapping[str, Any], media_manifest: Mapping[str, Any],
    custody_events: Sequence[Mapping[str, Any]], expected_repository_commit: str,
    expected_measured_baseline_identifier: str, expected_runtime_identity: str,
    expected_key_manifest_digest: str, seen_package_identifiers: MutableSet[str] | None = None,
    restore_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(key_custody_manifest, Mapping): raise CustodyError("key_custody_manifest_missing")
    if not isinstance(media_manifest, Mapping): raise CustodyError("recovery_media_missing")
    if not isinstance(custody_events, Sequence) or isinstance(custody_events, (str, bytes)): raise CustodyError("custody_chain_missing")
    keys = validate_key_custody_manifest(key_custody_manifest)
    if key_custody_manifest.get("payload_digest") != expected_key_manifest_digest:
        raise CustodyError("key_custody_manifest_binding_invalid")
    custody = validate_custody_package(package_root, expected_repository_commit=expected_repository_commit, expected_measured_baseline_identifier=expected_measured_baseline_identifier, expected_runtime_identity=expected_runtime_identity, seen_package_identifiers=seen_package_identifiers)
    if custody["key_custody_manifest_digest"] != expected_key_manifest_digest:
        raise CustodyError("key_custody_manifest_binding_invalid")
    media = validate_media_manifest(media_manifest, expected_package_identifier=custody["custody_package_identifier"], expected_manifest_digest=custody["custody_manifest_digest"], expected_checksum=custody["backup_package_digest"])
    chain = validate_chain(custody_events, expected_chain_identifier=custody["custody_chain_identifier"], expected_package_identifier=custody["custody_package_identifier"])
    actions = {item["action"] for item in chain}
    if not {"EXPORT", "RECEIPT", "MEDIA_CREATED", "VERIFIED"}.issubset(actions):
        raise CustodyError("custody_chain_incomplete")
    if restore_result is not None:
        required = {"restore_status": "PASS", "measured_startup_status": "MEASURED_STARTUP_APPROVED", "runtime_status": "PASS", "replay_status": "PASS"}
        if any(restore_result.get(key) != value for key, value in required.items()): raise CustodyError("post_restore_assurance_failed")
    return {"status": "R3_CUSTODY_ASSURANCE_PASS", "custody_package_identifier": custody["custody_package_identifier"], "custody_manifest_digest": custody["custody_manifest_digest"], "key_custody_identifier": keys["custody_identifier"], "media_identifier": media["media_identifier"], "custody_events": len(chain), "restore_evidence_supplied": restore_result is not None}
