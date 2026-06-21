from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


def model_pathway(pathway: Mapping[str, Any], constraints: Mapping[str, Any]) -> dict[str, Any]:
    pathway_record = deepcopy(dict(pathway))
    pathway_id = str(pathway_record.get("pathway_id") or "declared-pathway")
    prohibited = set(str(item) for item in constraints.get("prohibited_pathway_ids", []))
    return {
        "pathway_id": pathway_id,
        "objective": pathway_record.get("objective"),
        "declared_steps": list(pathway_record.get("steps", [])),
        "constraint_valid": pathway_id not in prohibited and constraints.get("valid") is True,
        "skg_constraints_applied": True,
    }

