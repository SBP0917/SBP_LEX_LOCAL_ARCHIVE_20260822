from __future__ import annotations


def drift_status(expected: str, actual: str) -> str:
    return "DRIFT_DETECTED" if expected != actual else "NO_DRIFT"
