from __future__ import annotations

from typing import Any, Mapping, Sequence


def model_capabilities(capabilities: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted((dict(item) for item in capabilities), key=lambda item: str(item.get("capability_id", "")))
    unavailable = [str(item.get("capability_id")) for item in ordered if item.get("available") is not True]
    return {"capabilities": ordered, "available": not unavailable, "unavailable_capability_ids": unavailable}

