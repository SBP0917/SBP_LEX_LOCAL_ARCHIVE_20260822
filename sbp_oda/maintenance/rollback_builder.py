from __future__ import annotations


def build_rollback_plan(action_name: str) -> dict[str, str]:
    return {"action_name": action_name, "rollback_required": "true", "auto_apply": "false"}
