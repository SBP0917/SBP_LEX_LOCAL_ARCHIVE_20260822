from __future__ import annotations


def analyse_required_paths(required: list[str], actual: set[str]) -> list[str]:
    return sorted(path for path in required if path not in actual)
