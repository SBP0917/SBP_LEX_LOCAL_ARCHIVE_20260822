from __future__ import annotations

from pathlib import Path


def inventory_files(root: str | Path) -> list[str]:
    root_path = Path(root)
    if not root_path.exists():
        return []
    return sorted(str(path.relative_to(root_path)).replace("\\", "/") for path in root_path.rglob("*") if path.is_file())
