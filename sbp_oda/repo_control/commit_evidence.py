from __future__ import annotations

import subprocess
from pathlib import Path


def capture_commit_evidence(runtime_root: str | Path = ".") -> dict[str, object]:
    root = Path(runtime_root)
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"commit_hash": None, "captured": False, "error": str(exc)}

    if completed.returncode != 0:
        return {
            "commit_hash": None,
            "captured": False,
            "error": (completed.stderr or completed.stdout).strip(),
        }

    return {"commit_hash": completed.stdout.strip(), "captured": True, "error": ""}
