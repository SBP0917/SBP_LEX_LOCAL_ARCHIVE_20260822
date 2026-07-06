from __future__ import annotations


def classify_issue(finding_id: str) -> str:
    if "config" in finding_id:
        return "CONFIGURATION"
    if "repo" in finding_id or "main_py" in finding_id:
        return "REPOSITORY"
    return "GENERAL_SUPPORT"
