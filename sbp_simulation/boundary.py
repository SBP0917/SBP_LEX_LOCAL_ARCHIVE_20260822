from __future__ import annotations

from pathlib import Path

from sbp_simulation.status import FORBIDDEN_SIMULATION_STATUSES, SimulationStatus


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(errors="ignore")


def run_boundary_check(runtime_root: str | Path = ".") -> dict[str, object]:
    root = Path(runtime_root)
    findings: list[dict[str, object]] = []
    main_py = root / "main.py"
    if main_py.exists() and "sbp_simulation" in _read(main_py):
        findings.append({"finding": "sbp_simulation_imported_in_main", "path": "main.py", "severity": "CRITICAL"})
    sbp_lex = root / "sbp_lex"
    if sbp_lex.exists():
        for path in sbp_lex.rglob("*.py"):
            if "sbp_simulation" in _read(path):
                findings.append({"finding": "sbp_simulation_imported_in_sbp_lex", "path": str(path.relative_to(root)), "severity": "CRITICAL"})
    if {status.value for status in SimulationStatus}.intersection(FORBIDDEN_SIMULATION_STATUSES):
        findings.append({"finding": "runtime_decision_used_as_simulation_status", "severity": "CRITICAL"})
    sim_root = root / "sbp_simulation"
    if sim_root.exists():
        for path in sim_root.rglob("*.py"):
            if path.name in {"boundary.py", "command_policy.py", "failure_matrix.py"}:
                continue
            text = _read(path)
            rel = str(path.relative_to(root))
            if any(term in text for term in ("git clean", "git reset", "git push", "rmdir", "blockchain", "cloud publication")):
                findings.append({"finding": "blocked_command_literal_present", "path": rel, "severity": "MEDIUM"})
            if "sbp_lex/" in text.replace("\\", "/") and any(term in text for term in ("write_text(", "open(", "unlink(", "rename(", "replace(")):
                findings.append({"finding": "simulation_may_modify_runtime_authority_file", "path": rel, "severity": "CRITICAL"})
    status = SimulationStatus.SIM_OK if not findings else SimulationStatus.SIM_BLOCKED
    return {"status": status.value, "finding_count": len(findings), "findings": findings}
