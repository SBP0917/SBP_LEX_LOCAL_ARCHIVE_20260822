from __future__ import annotations

from typing import Any, Mapping, Sequence

from sbp_lex.security.pqc import generate_digest

from .common import CustodyError, R3_VERSION, require_identifier, seal, unseal, utc_text

MEDIA_STATUSES = frozenset({"ACTIVE", "FAILED", "RETIRED", "DESTROYED"})


def create_media_manifest(*, media_identifier: str, custody_package_identifier: str, custody_manifest_digest: str, package_checksum: str, copy_number: int, maximum_copies: int = 2) -> dict[str, Any]:
    require_identifier(media_identifier, "media_identifier_invalid"); require_identifier(custody_package_identifier, "custody_package_identifier_invalid")
    if not 1 <= copy_number <= maximum_copies <= 2 or len(custody_manifest_digest) != 64 or len(package_checksum) != 64:
        raise CustodyError("media_duplication_policy_invalid")
    payload = {"media_version": R3_VERSION, "media_identifier": media_identifier, "custody_package_identifier": custody_package_identifier, "custody_manifest_digest": custody_manifest_digest, "package_checksum": package_checksum, "copy_number": copy_number, "maximum_copies": maximum_copies, "media_class": "OFFLINE_READ_ONLY_RECOVERY_MEDIA", "status": "ACTIVE"}
    payload["media_digest"] = generate_digest(payload)
    return seal(payload)


def validate_media_manifest(value: Mapping[str, Any], *, expected_package_identifier: str, expected_manifest_digest: str, expected_checksum: str) -> dict[str, Any]:
    payload = unseal(value, label="media_manifest")
    digest = payload.get("media_digest"); core = {key: item for key, item in payload.items() if key != "media_digest"}
    if digest != generate_digest(core): raise CustodyError("media_digest_invalid")
    if payload.get("custody_package_identifier") != expected_package_identifier or payload.get("custody_manifest_digest") != expected_manifest_digest:
        raise CustodyError("media_custody_binding_invalid")
    if payload.get("package_checksum") != expected_checksum: raise CustodyError("corrupted_recovery_media")
    if payload.get("status") != "ACTIVE": raise CustodyError("recovery_media_unavailable")
    if not 1 <= payload.get("copy_number", 0) <= payload.get("maximum_copies", 0) <= 2: raise CustodyError("media_duplication_policy_invalid")
    return payload


def media_lifecycle_record(*, media_identifier: str, sequence: int, prior_status: str, new_status: str, occurred_at: str, reason: str, approvals: Sequence[str]) -> dict[str, Any]:
    require_identifier(media_identifier, "media_identifier_invalid")
    if prior_status not in MEDIA_STATUSES or new_status not in MEDIA_STATUSES or prior_status == new_status or sequence <= 0 or len(set(approvals)) < 2:
        raise CustodyError("media_lifecycle_invalid")
    allowed = {"ACTIVE": {"FAILED", "RETIRED"}, "FAILED": {"RETIRED", "DESTROYED"}, "RETIRED": {"DESTROYED"}, "DESTROYED": set()}
    if new_status not in allowed[prior_status]: raise CustodyError("media_lifecycle_transition_invalid")
    return seal({"record_version": R3_VERSION, "media_identifier": media_identifier, "sequence": sequence, "prior_status": prior_status, "new_status": new_status, "occurred_at": utc_text(occurred_at), "reason": reason, "approvals": sorted(set(approvals))})


def recovery_invocation(*, invocation_identifier: str, media_identifier: str, custody_package_identifier: str, requested_at: str, approvals: Sequence[str], purpose: str = "DESKTOP_V1_AUTHORISED_RECOVERY") -> dict[str, Any]:
    if len(set(approvals)) < 2: raise CustodyError("recovery_dual_control_required")
    payload = {"invocation_version": R3_VERSION, "invocation_identifier": require_identifier(invocation_identifier, "invocation_identifier_invalid"), "media_identifier": require_identifier(media_identifier, "media_identifier_invalid"), "custody_package_identifier": require_identifier(custody_package_identifier, "custody_package_identifier_invalid"), "requested_at": utc_text(requested_at), "approvals": sorted(set(approvals)), "purpose": purpose}
    payload["invocation_digest"] = generate_digest(payload)
    return seal(payload)
