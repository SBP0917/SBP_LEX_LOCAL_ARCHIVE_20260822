from __future__ import annotations

from typing import Any, Mapping, Sequence


def resolve_authority_chain(
    authorities: Sequence[Mapping[str, Any]],
    authority_id: str,
) -> dict[str, Any]:
    index = {str(item.get("authority_id")): dict(item) for item in authorities if item.get("authority_id")}
    chain: list[str] = []
    seen: set[str] = set()
    current = authority_id
    while current:
        if current in seen or current not in index:
            return {"authority_chain": chain, "resolved": False, "reason": "cycle_or_missing_authority"}
        entity = index[current]
        if entity.get("revoked") is True:
            return {"authority_chain": chain + [current], "resolved": False, "reason": "revoked_authority"}
        seen.add(current)
        chain.append(current)
        current = str(entity.get("parent_authority_id") or "")
    return {"authority_chain": chain, "resolved": bool(chain), "reason": "resolved" if chain else "empty_chain"}

