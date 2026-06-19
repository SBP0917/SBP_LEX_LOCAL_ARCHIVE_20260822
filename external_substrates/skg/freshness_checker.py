from __future__ import annotations

from typing import Any, Mapping, Sequence


def check_source_freshness(sources: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    stale = sorted(str(item.get("source_id", "unknown")) for item in sources if item.get("freshness_valid") is not True)
    return {"freshness_valid": not stale and bool(sources), "stale_source_ids": stale}

