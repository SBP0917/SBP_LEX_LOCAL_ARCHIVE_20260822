from __future__ import annotations

from typing import Any, Mapping

PROHIBITED_AUTHORITY_KEYS = frozenset({
    "execution_permission",
    "execution_result",
    "execution_verified",
    "governance_result",
    "external_governance_result",
    "runtime_authority",
    "final_admissibility",
})
PROHIBITED_AUTHORITY_VALUES = frozenset(
    {"ALLOW", "DENY", "ESCALATE", "EXECUTE", "HALT"}
)


def contains_prohibited_authority(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            key in PROHIBITED_AUTHORITY_KEYS or contains_prohibited_authority(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(contains_prohibited_authority(item) for item in value)
    return (
        isinstance(value, str)
        and value.strip().upper() in PROHIBITED_AUTHORITY_VALUES
    )


def require_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
