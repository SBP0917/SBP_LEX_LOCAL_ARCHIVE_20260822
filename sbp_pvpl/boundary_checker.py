from __future__ import annotations

from pathlib import Path

from sbp_pvpl.constants import BLOCKCHAIN_PUBLICATION_ALLOWED, CLOUD_PUBLICATION_ALLOWED, EXTERNAL_PUBLICATION_TARGET, LEDGER_ACTIVE, PUBLICATION_ACTIVE
from sbp_pvpl.status import FORBIDDEN_RUNTIME_DECISIONS, PVPLStatus


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(errors="ignore")


def run_boundary_check(runtime_root: str | Path = ".") -> dict[str, object]:
    root = Path(runtime_root)
    findings: list[dict[str, object]] = []
    main_py = root / "main.py"
    if main_py.exists() and "sbp_pvpl" in _read(main_py):
        findings.append({"finding": "sbp_pvpl_imported_in_main", "path": "main.py", "severity": "CRITICAL"})
    sbp_lex = root / "sbp_lex"
    if sbp_lex.exists():
        for path in sbp_lex.rglob("*.py"):
            if "sbp_pvpl" in _read(path):
                findings.append({"finding": "sbp_pvpl_imported_in_sbp_lex", "path": str(path.relative_to(root)), "severity": "CRITICAL"})
    status_values = {status.value for status in PVPLStatus}
    forbidden = sorted(status_values.intersection(FORBIDDEN_RUNTIME_DECISIONS))
    if forbidden:
        findings.append({"finding": "runtime_decision_terms_used_as_pvpl_status", "values": forbidden, "severity": "CRITICAL"})
    if PUBLICATION_ACTIVE is not False:
        findings.append({"finding": "publication_active_default_true", "severity": "CRITICAL"})
    if BLOCKCHAIN_PUBLICATION_ALLOWED is not False:
        findings.append({"finding": "blockchain_active_default_true", "severity": "CRITICAL"})
    if LEDGER_ACTIVE is not False:
        findings.append({"finding": "ledger_active_default_true", "severity": "CRITICAL"})
    if CLOUD_PUBLICATION_ALLOWED is not False:
        findings.append({"finding": "cloud_active_default_true", "severity": "CRITICAL"})
    if EXTERNAL_PUBLICATION_TARGET != "NONE":
        findings.append({"finding": "external_publication_target_not_none", "severity": "CRITICAL"})
    pvpl_root = root / "sbp_pvpl"
    if pvpl_root.exists():
        for path in pvpl_root.rglob("*.py"):
            if path.name == "boundary_checker.py":
                continue
            text = _read(path)
            rel = str(path.relative_to(root))
            mutating_source = any(term in text for term in ("write_text(", "open(", "unlink(", "rename(", "replace(", "shutil.move", "shutil.rmtree"))
            if mutating_source and "sbp_lex/audit" in text.replace("\\", "/"):
                findings.append({"finding": "pvpl_may_modify_audit_authority_file", "path": rel, "severity": "CRITICAL"})
    status = PVPLStatus.PROOF_OK if not findings else PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY
    return {"status": status.value, "finding_count": len(findings), "findings": findings, "runtime_authority": "NONE"}
