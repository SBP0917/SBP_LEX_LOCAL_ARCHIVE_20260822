from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FileManifestEntry:
    path: str
    present: bool
