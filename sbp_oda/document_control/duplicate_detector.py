from __future__ import annotations


def find_duplicate_names(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for path in paths:
        name = path.rsplit("/", 1)[-1].lower()
        if name in seen:
            duplicates.add(name)
        seen.add(name)
    return sorted(duplicates)
