from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


def ingest_context(context: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        raise ValueError("DTN context must be a mapping")
    return deepcopy(dict(context))

