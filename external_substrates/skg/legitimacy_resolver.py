from __future__ import annotations

from typing import Any, Mapping


def resolve_legitimacy(authority: Mapping[str, Any]) -> dict[str, Any]:
    status = str(authority.get("legitimacy_status") or "unresolved").lower()
    legitimate = status in {"legitimate", "verified", "attested"} and authority.get("revoked") is not True
    return {"authority_id": authority.get("authority_id"), "status": status, "legitimate": legitimate}

