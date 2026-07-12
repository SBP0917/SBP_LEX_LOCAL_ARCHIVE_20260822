from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from sbp_lex.security.pqc import generate_digest

from .common import CustodyError, R3_VERSION, require_identifier, seal, unseal, utc_text

CHAIN_ACTIONS = frozenset({"EXPORT", "TRANSFER", "RECEIPT", "MEDIA_CREATED", "VERIFIED", "RESTORE_AUTHORIZED", "INCIDENT", "RETIRED", "DESTROYED"})
ROLES = frozenset({"repository_operator", "custody_operator", "custody_administrator", "recovery_operator", "auditor"})


def create_event(
    *, chain_identifier: str, sequence: int, action: str, actor_role: str,
    package_identifier: str, occurred_at: str, previous_event_digest: str | None,
    receipt_digest: str | None = None, incident_code: str | None = None,
) -> dict[str, Any]:
    require_identifier(chain_identifier, "custody_chain_identifier_invalid")
    require_identifier(package_identifier, "custody_package_identifier_invalid")
    if not isinstance(sequence, int) or sequence <= 0 or action not in CHAIN_ACTIONS or actor_role not in ROLES:
        raise CustodyError("custody_event_invalid")
    if sequence == 1 and previous_event_digest is not None:
        raise CustodyError("custody_genesis_predecessor_invalid")
    if sequence > 1 and (not isinstance(previous_event_digest, str) or len(previous_event_digest) != 64):
        raise CustodyError("custody_predecessor_invalid")
    payload = {
        "event_version": R3_VERSION,
        "chain_identifier": chain_identifier,
        "sequence": sequence,
        "action": action,
        "actor_role": actor_role,
        "package_identifier": package_identifier,
        "occurred_at": utc_text(occurred_at),
        "previous_event_digest": previous_event_digest,
        "receipt_digest": receipt_digest,
        "incident_code": incident_code,
    }
    payload["event_digest"] = generate_digest(payload)
    return seal(payload)


def validate_chain(events: Sequence[Mapping[str, Any]], *, expected_chain_identifier: str, expected_package_identifier: str) -> list[dict[str, Any]]:
    if not events:
        raise CustodyError("custody_chain_missing")
    checked: list[dict[str, Any]] = []
    previous: str | None = None
    for index, value in enumerate(events, start=1):
        payload = unseal(value, label="custody_event")
        digest = payload.get("event_digest")
        core = {key: item for key, item in payload.items() if key != "event_digest"}
        if digest != generate_digest(core):
            raise CustodyError("custody_event_digest_invalid")
        if payload.get("sequence") != index or payload.get("previous_event_digest") != previous:
            raise CustodyError("broken_custody_chain")
        if payload.get("chain_identifier") != expected_chain_identifier or payload.get("package_identifier") != expected_package_identifier:
            raise CustodyError("unknown_custody_identifier")
        if payload.get("action") not in CHAIN_ACTIONS or payload.get("actor_role") not in ROLES:
            raise CustodyError("custody_event_invalid")
        utc_text(str(payload.get("occurred_at")))
        if payload["action"] == "RECEIPT" and not payload.get("receipt_digest"):
            raise CustodyError("incorrect_receipt")
        previous = str(digest); checked.append(json.loads(json.dumps(payload)))
    if checked[0]["action"] != "EXPORT":
        raise CustodyError("custody_chain_genesis_invalid")
    return checked
