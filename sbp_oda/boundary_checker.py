from __future__ import annotations

from pathlib import Path

from sbp_oda.status import FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS, ODAStatus


RUNTIME_AUTHORITY_PATH_MARKERS = (
    "sbp_lex/pipeline/",
    "sbp_lex/governance/",
    "sbp_lex/execution/",
    "sbp_lex/security/",
    "sbp_lex/authority_first/",
    "sbp_lex/audit/",
    "sbp_lex/shared/",
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(errors="ignore")


def run_boundary_check(runtime_root: str | Path = ".") -> dict[str, object]:
    root = Path(runtime_root)
    findings: list[dict[str, object]] = []

    main_py = root / "main.py"
    if main_py.exists() and "sbp_oda" in _read(main_py):
        findings.append({"finding": "sbp_oda_imported_in_main", "path": "main.py", "severity": "CRITICAL"})

    sbp_lex = root / "sbp_lex"
    if sbp_lex.exists():
        for path in sbp_lex.rglob("*.py"):
            if "sbp_oda" in _read(path):
                findings.append({"finding": "sbp_oda_imported_in_sbp_lex", "path": str(path.relative_to(root)), "severity": "CRITICAL"})

    status_values = {status.value for status in ODAStatus}
    forbidden_statuses = sorted(status_values.intersection(FORBIDDEN_RUNTIME_AUTHORITY_OUTPUTS))
    if forbidden_statuses:
        findings.append({"finding": "runtime_decision_terms_used_as_oda_status", "values": forbidden_statuses, "severity": "CRITICAL"})

    oda_root = root / "sbp_oda"
    if oda_root.exists():
        for path in oda_root.rglob("*.py"):
            if path.name == "boundary_checker.py":
                continue
            text = _read(path)
            rel = str(path.relative_to(root))
            if "remote_shell_allowed=True" in text or '"remote_shell_allowed": True' in text:
                findings.append({"finding": "remote_shell_allowed_true", "path": rel, "severity": "CRITICAL"})
            if "auto_apply_allowed=True" in text or '"auto_apply_allowed": True' in text:
                findings.append({"finding": "auto_apply_allowed_true", "path": rel, "severity": "HIGH"})
            if "HARNESS_OK" in text and "receive_signed_package" in text:
                findings.append({"finding": "signed_package_receipt_claims_success", "path": rel, "severity": "CRITICAL"})
            normalized = text.replace("\\", "/")
            mutating_source = any(term in text for term in ("write_text(", "open(", "unlink(", "rename(", "replace(", "shutil.move", "shutil.rmtree"))
            for marker in RUNTIME_AUTHORITY_PATH_MARKERS:
                if marker in normalized and mutating_source:
                    findings.append({"finding": "oda_may_modify_runtime_authority_path", "path": rel, "marker": marker, "severity": "CRITICAL"})

    status = ODAStatus.HARNESS_OK if not findings else ODAStatus.HARNESS_BLOCKED_CANONICAL_BOUNDARY
    return {
        "status": status.value,
        "finding_count": len(findings),
        "findings": findings,
        "runtime_authority": "NONE",
    }
