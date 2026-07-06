from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

from sbp_oda.repo_control.branch_status import capture_branch_status
from sbp_oda.repo_control.commit_evidence import capture_commit_evidence
from sbp_oda.status import ODAStatus


EXPECTED_PRESENT_FILES = ("main.py", "requirements.txt", "README.md", "START_HERE.md")
OPTIONAL_REPORTS = (
    "reports/ODA_V1_SKELETON_IMPLEMENTATION_REPORT.md",
    "reports/PVPL_V1_SKELETON_IMPLEMENTATION_REPORT.md",
    "reports/PQC_01_REAL_PROVIDER_CONTRACT_REPORT.md",
)


def _git_status_lines(runtime_root: Path) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "status", "--short"],
            cwd=runtime_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    return [line for line in completed.stdout.splitlines() if line.strip()]


def scan_local_deployment(runtime_root: str | Path = ".") -> dict[str, object]:
    root = Path(runtime_root).resolve()
    branch = capture_branch_status(root)
    commit = capture_commit_evidence(root)
    status_lines = _git_status_lines(root)
    untracked = [line for line in status_lines if line.startswith("??")]
    tracked_modified = [line for line in status_lines if line and not line.startswith("??")]
    expected_presence = {name: (root / name).exists() for name in EXPECTED_PRESENT_FILES}
    optional_reports = {name: (root / name).exists() for name in OPTIONAL_REPORTS}
    missing_required = [name for name, exists in expected_presence.items() if not exists]
    status = ODAStatus.HARNESS_OK
    if not root.exists() or missing_required:
        status = ODAStatus.HARNESS_INVALID_DEPLOYMENT_STATE
    elif branch.get("dirty"):
        status = ODAStatus.HARNESS_WARNING

    return {
        "status": status.value,
        "repository_root": str(root),
        "repository_root_exists": root.exists(),
        "current_working_directory": str(Path.cwd().resolve()),
        "current_branch": branch.get("branch"),
        "current_commit_hash": commit.get("commit_hash"),
        "git_status_short": branch.get("status_short", ""),
        "dirty_tree": bool(branch.get("dirty")),
        "git_branch_captured": bool(branch.get("captured")),
        "git_commit_captured": bool(commit.get("captured")),
        "git_error": branch.get("error") or commit.get("error") or "",
        "untracked_file_count": len(untracked),
        "tracked_modified_file_count": len(tracked_modified),
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "expected_files": expected_presence,
        "main_py_exists": expected_presence["main.py"],
        "requirements_txt_exists": expected_presence["requirements.txt"],
        "readme_exists": expected_presence["README.md"],
        "start_here_exists": expected_presence["START_HERE.md"],
        "expected_oda_package_exists": (root / "sbp_oda").is_dir(),
        "expected_pvpl_package_exists_if_present": (root / "sbp_pvpl").is_dir(),
        "expected_pqc_provider_test_exists_if_present": (root / "tests/test_pqc_01_provider_contract.py").exists(),
        "expected_report_paths": optional_reports,
    }
