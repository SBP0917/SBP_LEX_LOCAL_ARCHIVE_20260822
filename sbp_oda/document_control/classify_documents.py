from __future__ import annotations


def classify_document(path: str) -> str:
    lowered = path.lower()
    if "blueprint" in lowered:
        return "BLUEPRINT_REFERENCE"
    if "report" in lowered:
        return "REPORT_EVIDENCE"
    return "SUPPORT_DOCUMENT"
