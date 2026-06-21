from __future__ import annotations

from typing import Any, Mapping, Sequence


def model_dependencies(dependencies: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted((dict(item) for item in dependencies), key=lambda item: str(item.get("dependency_id", "")))
    missing = [str(item.get("dependency_id")) for item in ordered if item.get("available") is not True]
    return {"dependencies": ordered, "satisfied": not missing, "missing_dependency_ids": missing}

