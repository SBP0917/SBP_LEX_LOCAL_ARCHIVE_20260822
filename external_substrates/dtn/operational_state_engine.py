from __future__ import annotations

from typing import Any, Mapping


def model_operational_state(context: Mapping[str, Any]) -> dict[str, Any]:
    state = dict(context.get("operational_state", {}) or {})
    return {
        "status": str(state.get("status") or "declared"),
        "contained": state.get("contained") is True,
        "emergency_stop_available": state.get("emergency_stop_available") is True,
    }

