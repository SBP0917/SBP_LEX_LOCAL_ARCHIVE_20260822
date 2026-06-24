from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable


def normalise_relative_path(path: str | Path) -> str:
    return Path(path).as_posix()


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_file_record(repository_root: Path, relative_path: str | Path) -> dict[str, Any]:
    normalised = normalise_relative_path(relative_path)
    path = repository_root / normalised
    if not path.exists():
        return {
            "path": normalised,
            "status": "MISSING",
            "sha256": None,
            "size_bytes": None,
        }
    if not path.is_file():
        return {
            "path": normalised,
            "status": "NOT_FILE",
            "sha256": None,
            "size_bytes": None,
        }
    return {
        "path": normalised,
        "status": "PRESENT",
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def collect_file_hashes(repository_root: Path, paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    return [digest_file_record(repository_root, path) for path in paths]
