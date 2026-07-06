from __future__ import annotations

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalise_severity(value: str) -> str:
    value = value.upper().strip()
    if value not in SEVERITY_ORDER:
        return "INFO"
    return value
