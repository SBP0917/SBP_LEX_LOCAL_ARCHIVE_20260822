from __future__ import annotations

from hashlib import sha256
from pathlib import Path


def file_sha256(path: str | Path) -> str:
    target = Path(path)
    return sha256(target.read_bytes()).hexdigest()
