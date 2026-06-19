from __future__ import annotations

from typing import Any, Mapping, Sequence


def resolve_policy_conflicts(conflicts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted((dict(item) for item in conflicts), key=lambda item: str(item.get("conflict_id", "")))
    unresolved = [str(item.get("conflict_id")) for item in ordered if item.get("resolved") is not True]
    return {
        "conflict_ids": [str(item.get("conflict_id")) for item in ordered],
        "resolved": not unresolved,
        "unresolved_conflict_ids": unresolved,
    }

