from __future__ import annotations

from typing import Any, Mapping, Sequence

from external_substrates.shared.freshness import parse_timestamp


def validate_rule_lineage(rules: Sequence[Mapping[str, Any]], *, now: str | None = None) -> dict[str, Any]:
    current = parse_timestamp(now) if now else None
    failures: list[str] = []
    ordered = sorted((dict(rule) for rule in rules), key=lambda item: (str(item.get("effective_at", "")), str(item.get("rule_id", ""))))
    for rule in ordered:
        effective = parse_timestamp(rule.get("effective_at"))
        expires = parse_timestamp(rule.get("expires_at")) if rule.get("expires_at") else None
        rule_id = str(rule.get("rule_id") or "unknown")
        if effective is None or rule.get("revoked") is True:
            failures.append(f"{rule_id}:invalid_or_revoked")
        elif current and (effective > current or (expires and expires < current)):
            failures.append(f"{rule_id}:stale_or_not_yet_effective")
    return {"rule_ids": [str(rule.get("rule_id")) for rule in ordered], "valid": not failures, "failures": failures}

