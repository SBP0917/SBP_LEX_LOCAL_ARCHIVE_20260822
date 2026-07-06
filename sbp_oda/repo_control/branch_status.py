from __future__ import annotations

import subprocess
from pathlib import Path


def capture_branch_status(runtime_root: str | Path = ".") -> dict[str, object]:
    root = Path(runtime_root)
    try:
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        status = subprocess.run(
            ["git", "status", "--short"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"branch": None, "dirty": None, "status_short": "", "captured": False, "error": str(exc)}

    if branch.returncode != 0:
        return {
            "branch": None,
            "dirty": None,
            "status_short": "",
            "captured": False,
            "error": (branch.stderr or branch.stdout).strip(),
        }
    if status.returncode != 0:
        return {
            "branch": branch.stdout.strip() or None,
            "dirty": None,
            "status_short": "",
            "captured": False,
            "error": (status.stderr or status.stdout).strip(),
        }

    status_short = status.stdout.strip()
    return {
        "branch": branch.stdout.strip() or None,
        "dirty": bool(status_short),
        "status_short": status_short,
        "captured": True,
        "error": "",
    }
