from __future__ import annotations

from typing import Any, Mapping, Sequence


def check_revocations(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    revoked_ids = sorted(str(item.get("authority_id") or item.get("rule_id")) for item in records if item.get("revoked") is True)
    return {"revocation_clear": not revoked_ids, "revoked_ids": revoked_ids}

