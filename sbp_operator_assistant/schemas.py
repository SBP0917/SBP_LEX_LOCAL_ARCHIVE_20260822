from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalise_tags(tags: Iterable[str] | None) -> list[str]:
    if tags is None:
        return []
    return sorted({str(tag).strip() for tag in tags if str(tag).strip()})


def archive_key(title_or_path: str) -> str:
    value = title_or_path.strip()
    if not value:
        return "#"
    first = value[0].upper()
    return first if first.isalnum() else "#"


def normalise_path(path: str | Path) -> str:
    return Path(path).expanduser().as_posix()
