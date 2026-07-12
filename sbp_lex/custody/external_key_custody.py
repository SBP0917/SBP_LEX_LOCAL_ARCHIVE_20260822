from __future__ import annotations

import base64
import json
from typing import Any, Mapping, Sequence

from sbp_lex.security.pqc import generate_digest

from .common import CustodyError, R3_VERSION, require_identifier, seal, unseal, utc_text

KEY_ROLES = frozenset({"EXTERNAL_SIGNING", "RECOVERY_ONLY"})
KEY_STATUSES = frozenset({"ACTIVE", "REVOKED", "RETIRED"})


def public_key_record(*, key_identifier: str, role: str, algorithm: str, public_key: str, sequence: int, status: str = "ACTIVE", predecessor_key_identifier: str | None = None) -> dict[str, Any]:
    require_identifier(key_identifier, "key_identifier_invalid")
    if role not in KEY_ROLES or status not in KEY_STATUSES or not isinstance(sequence, int) or sequence <= 0:
        raise CustodyError("key_record_invalid")
    try:
        decoded = base64.b64decode(public_key.encode("ascii"), validate=True)
    except Exception as exc:
        raise CustodyError("public_key_invalid") from exc
    if len(decoded) < 16 or "private" in public_key.lower():
        raise CustodyError("public_key_invalid")
    record = {
        "key_identifier": key_identifier, "role": role, "algorithm": algorithm,
        "public_key": public_key, "sequence": sequence, "status": status,
        "predecessor_key_identifier": predecessor_key_identifier,
    }
    record["record_digest"] = generate_digest(record)
    return record


def create_key_custody_manifest(*, custody_identifier: str, keys: Sequence[Mapping[str, Any]], control_authorities: Sequence[str], recovery_separated: bool = True) -> dict[str, Any]:
    require_identifier(custody_identifier, "key_custody_identifier_invalid")
    records = [json.loads(json.dumps(item)) for item in keys]
    identifiers = [item.get("key_identifier") for item in records]
    if len(records) < 2 or len(identifiers) != len(set(identifiers)):
        raise CustodyError("key_custody_keyset_invalid")
    if len(set(control_authorities)) < 2:
        raise CustodyError("dual_control_required")
    roles = {item.get("role") for item in records if item.get("status") == "ACTIVE"}
    if roles != KEY_ROLES or recovery_separated is not True:
        raise CustodyError("recovery_key_separation_required")
    for item in records:
        core = {key: value for key, value in item.items() if key != "record_digest"}
        if item.get("record_digest") != generate_digest(core):
            raise CustodyError("key_record_digest_invalid")
    payload = {
        "manifest_version": "R3_EXTERNAL_KEY_CUSTODY_MANIFEST_V1",
        "custody_identifier": custody_identifier,
        "keys": sorted(records, key=lambda item: item["key_identifier"]),
        "control_authorities": sorted(set(control_authorities)),
        "dual_control_required": True,
        "recovery_key_separated": True,
        "private_key_material_present": False,
    }
    payload["key_manifest_digest"] = generate_digest(payload)
    return seal(payload)


def validate_key_custody_manifest(value: Mapping[str, Any], *, revoked_key_identifiers: Sequence[str] = ()) -> dict[str, Any]:
    payload = unseal(value, label="key_custody_manifest")
    digest = payload.get("key_manifest_digest")
    core = {key: item for key, item in payload.items() if key != "key_manifest_digest"}
    if digest != generate_digest(core) or payload.get("private_key_material_present") is not False:
        raise CustodyError("key_custody_manifest_invalid")
    if len(set(payload.get("control_authorities", []))) < 2 or payload.get("dual_control_required") is not True:
        raise CustodyError("dual_control_required")
    active_roles: set[str] = set()
    seen: set[str] = set()
    for item in payload.get("keys", []):
        identifier = item.get("key_identifier")
        if identifier in seen:
            raise CustodyError("duplicate_key_identifier")
        seen.add(identifier)
        if identifier in revoked_key_identifiers or item.get("status") == "REVOKED":
            continue
        if item.get("status") == "ACTIVE": active_roles.add(str(item.get("role")))
    if active_roles != KEY_ROLES or payload.get("recovery_key_separated") is not True:
        raise CustodyError("recovery_key_separation_required")
    return payload


def signing_request(*, request_identifier: str, custody_identifier: str, key_identifier: str, payload_digest: str, purpose: str, approvals: Sequence[str]) -> dict[str, Any]:
    for value, reason in ((request_identifier, "signing_request_identifier_invalid"), (custody_identifier, "key_custody_identifier_invalid"), (key_identifier, "key_identifier_invalid")):
        require_identifier(value, reason)
    if len(payload_digest) != 64 or len(set(approvals)) < 2:
        raise CustodyError("signing_request_dual_control_invalid")
    payload = {"request_version": R3_VERSION, "request_identifier": request_identifier, "custody_identifier": custody_identifier, "key_identifier": key_identifier, "payload_digest": payload_digest, "purpose": purpose, "approvals": sorted(set(approvals))}
    payload["request_digest"] = generate_digest(payload)
    return seal(payload)


def signing_response(*, request: Mapping[str, Any], key_identifier: str, signature: str, algorithm: str) -> dict[str, Any]:
    checked = unseal(request, label="signing_request")
    if checked.get("key_identifier") != key_identifier:
        raise CustodyError("signing_response_key_mismatch")
    try: base64.b64decode(signature.encode("ascii"), validate=True)
    except Exception as exc: raise CustodyError("external_signature_invalid") from exc
    return seal({"response_version": R3_VERSION, "request_digest": checked["request_digest"], "key_identifier": key_identifier, "algorithm": algorithm, "external_signature": signature})


def validate_signing_response(response: Mapping[str, Any], request: Mapping[str, Any], key_manifest: Mapping[str, Any], *, revoked_key_identifiers: Sequence[str] = ()) -> dict[str, Any]:
    checked_request = unseal(request, label="signing_request")
    checked_response = unseal(response, label="signing_response")
    manifest = validate_key_custody_manifest(key_manifest, revoked_key_identifiers=revoked_key_identifiers)
    if checked_response.get("request_digest") != checked_request.get("request_digest"):
        raise CustodyError("signing_response_request_mismatch")
    key_id = checked_response.get("key_identifier")
    key = next((item for item in manifest["keys"] if item["key_identifier"] == key_id), None)
    if key is None or key_id in revoked_key_identifiers or key.get("status") != "ACTIVE":
        raise CustodyError("revoked_or_unknown_key")
    if key.get("role") != "EXTERNAL_SIGNING" or key.get("algorithm") != checked_response.get("algorithm"):
        raise CustodyError("signing_response_key_mismatch")
    return checked_response


def revocation_record(*, custody_identifier: str, key_identifier: str, sequence: int, effective_at: str, reason: str, approvals: Sequence[str]) -> dict[str, Any]:
    if len(set(approvals)) < 2 or sequence <= 0: raise CustodyError("dual_control_required")
    return seal({"record_version": R3_VERSION, "record_type": "KEY_REVOCATION", "custody_identifier": require_identifier(custody_identifier, "key_custody_identifier_invalid"), "key_identifier": require_identifier(key_identifier, "key_identifier_invalid"), "sequence": sequence, "effective_at": utc_text(effective_at), "reason": reason, "approvals": sorted(set(approvals))})


def rotation_record(*, custody_identifier: str, old_key_identifier: str, new_key_identifier: str, sequence: int, effective_at: str, approvals: Sequence[str]) -> dict[str, Any]:
    if old_key_identifier == new_key_identifier or len(set(approvals)) < 2 or sequence <= 0: raise CustodyError("key_rotation_invalid")
    return seal({"record_version": R3_VERSION, "record_type": "KEY_ROTATION", "custody_identifier": require_identifier(custody_identifier, "key_custody_identifier_invalid"), "old_key_identifier": require_identifier(old_key_identifier, "key_identifier_invalid"), "new_key_identifier": require_identifier(new_key_identifier, "key_identifier_invalid"), "sequence": sequence, "effective_at": utc_text(effective_at), "approvals": sorted(set(approvals))})
