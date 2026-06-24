from __future__ import annotations

from pathlib import Path
from typing import Any

from sbp_lex.local_trust.execution_envelope import build_execution_environment_envelope


def capture_verification_environment(repository_root: Path | str | None = None) -> dict[str, Any]:
    return build_execution_environment_envelope(repository_root, capture=True)
