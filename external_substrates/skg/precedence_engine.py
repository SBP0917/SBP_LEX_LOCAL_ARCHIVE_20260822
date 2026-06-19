from __future__ import annotations

from typing import Any, Mapping, Sequence


def resolve_precedence(rules: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    active = [dict(rule) for rule in rules if rule.get("revoked") is not True]
    ordered = sorted(active, key=lambda item: (-int(item.get("precedence", 0)), str(item.get("rule_id", ""))))
    duplicate_ranks = len({int(item.get("precedence", 0)) for item in ordered}) != len(ordered)
    return {
        "ordered_rule_ids": [str(item.get("rule_id")) for item in ordered],
        "resolved": bool(ordered) and not duplicate_ranks,
        "reason": "resolved" if ordered and not duplicate_ranks else "ambiguous_or_empty_precedence",
    }

