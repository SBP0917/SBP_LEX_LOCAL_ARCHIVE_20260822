from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


def collect_git_provenance(repository_root: Path) -> dict[str, Any]:
    branch = _git(repository_root, "branch", "--show-current")
    commit = _git(repository_root, "rev-parse", "HEAD")
    status_short = _git(repository_root, "status", "--short")
    return {
        "git_branch": branch.get("stdout") or None,
        "git_commit": commit.get("stdout") or None,
        "git_status_short": status_short.get("stdout") or "",
        "working_tree_clean": status_short.get("stdout", "") == "",
        "git_errors": [
            result["stderr"]
            for result in (branch, commit, status_short)
            if result.get("returncode") != 0 or result.get("stderr")
        ],
    }


def current_git_commit(repository_root: Path) -> str | None:
    result = _git(repository_root, "rev-parse", "HEAD")
    return result.get("stdout") or None


def _git(repository_root: Path, *args: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc)}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
