from __future__ import annotations

from typing import Any, Mapping, Sequence


def map_jurisdiction(authorities: Sequence[Mapping[str, Any]], jurisdiction: str) -> dict[str, Any]:
    matches = sorted(
        str(item["authority_id"])
        for item in authorities
        if item.get("jurisdiction") == jurisdiction and item.get("revoked") is not True
    )
    return {"requested_jurisdiction": jurisdiction, "matched_authority_ids": matches, "resolved": bool(matches)}

