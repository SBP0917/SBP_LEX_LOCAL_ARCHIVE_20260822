from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from sbp_lex.local_trust.file_digest import sha256_file


def collect_python_provenance() -> dict[str, Any]:
    executable = Path(sys.executable)
    digest = sha256_file(executable) if executable.exists() and executable.is_file() else None
    return {
        "python_executable": str(executable),
        "python_version": sys.version.replace("\n", " "),
        "python_runtime_digest_if_available": digest,
    }
