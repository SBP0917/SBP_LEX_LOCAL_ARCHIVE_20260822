from __future__ import annotations


def build_failure_reason(finding_id: str, message: str) -> str:
    return f"{finding_id}: {message}"
