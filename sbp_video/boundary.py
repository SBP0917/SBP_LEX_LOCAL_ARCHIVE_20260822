from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from sbp_video.constants import RUNTIME_AUTHORITY


FORBIDDEN_RUNTIME_NAMES = frozenset({
    "CANONICAL_RUNTIME",
    "CanonicalRuntime",
    "run_pipeline",
    "execution_gate",
    "governance_admissibility",
})


def run_boundary_check(repository_root: str | Path = ".") -> dict[str, Any]:
    package = Path(repository_root).resolve() / "sbp_video"
    findings: list[dict[str, str]] = []
    for path in sorted(package.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as error:
            findings.append({"file": str(path), "finding": f"syntax_error:{error.lineno}"})
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "sbp_lex" or alias.name.startswith("sbp_lex."):
                        findings.append({"file": str(path), "finding": f"runtime_import:{alias.name}"})
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "sbp_lex" or module.startswith("sbp_lex."):
                    findings.append({"file": str(path), "finding": f"runtime_import:{module}"})
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_RUNTIME_NAMES:
                findings.append({"file": str(path), "finding": f"runtime_name:{node.id}"})
    return {
        "status": "VIDEO_BOUNDARY_OK" if not findings else "VIDEO_BOUNDARY_BLOCKED",
        "finding_count": len(findings),
        "findings": findings,
        "runtime_authority": RUNTIME_AUTHORITY,
        "canonical_runtime_mutation": False,
        "integration_access": "detached_snapshot_read_only",
    }
