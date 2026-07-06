from __future__ import annotations


def is_superseded_label(label: str) -> bool:
    return "superseded" in label.lower() or "archive" in label.lower()
