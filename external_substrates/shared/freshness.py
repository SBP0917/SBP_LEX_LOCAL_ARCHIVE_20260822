from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utc_timestamp(now: datetime | None = None) -> str:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_freshness(
    timestamp: Any,
    max_age_seconds: int | float,
    now: datetime | str | None = None,
) -> bool:
    parsed = parse_timestamp(timestamp)
    current = parse_timestamp(now) if now is not None else datetime.now(timezone.utc)
    try:
        max_age = float(max_age_seconds)
    except (TypeError, ValueError):
        return False
    if parsed is None or current is None or max_age < 0:
        return False
    age = (current - parsed).total_seconds()
    return 0 <= age <= max_age

