from __future__ import annotations


def build_diagnostic_report(findings: list[dict[str, object]]) -> dict[str, object]:
    return {"report_type": "ODA_DIAGNOSTIC_REPORT", "findings": findings}
