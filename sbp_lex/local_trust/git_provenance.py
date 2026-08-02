from __future__ import annotations

import re
import subprocess
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


MAX_GENERATED_EVIDENCE_DESCENDANT_COMMITS = 32
GENERATED_EVIDENCE_EXACT_PATHS = frozenset(
    {
        "outputs/adversarial_local_trust_negative_harness.json",
        "outputs/local_constitutional_gates.json",
        "outputs/local_evidence_chain.json",
        "outputs/local_execution_environment_trust_envelope.json",
        "outputs/local_toolchain_guard.json",
        "outputs/local_trust_25_year_capstone.json",
        "outputs/local_trust_regression_matrix.json",
        "outputs/local_trust_root_manifest.json",
        "outputs/phq_formal_architecture_assurance.json",
        "outputs/r1_recovery_drill.json",
        "outputs/recovery_critical_inventory.json",
        "outputs/r2_deterministic_build_manifest.json",
        "outputs/r2_offline_verification.json",
        "outputs/r2_software_bill_of_materials.json",
        "outputs/r3_operational_custody_assurance.json",
    }
)
GENERATED_EVIDENCE_PATH_PREFIXES = (
    "outputs/release_integrity_bundle/",
    "outputs/university_validation_dossier/",
    "validation_package/",
)
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


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


def generated_evidence_path_allowed(path: str) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    candidate = PurePosixPath(path)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != path
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        return False
    return (
        path in GENERATED_EVIDENCE_EXACT_PATHS
        or any(path.startswith(prefix) for prefix in GENERATED_EVIDENCE_PATH_PREFIXES)
    )


def generated_evidence_lineage_is_bounded(
    repository_root: Path,
    recorded_commit: str,
    *,
    current_commit: str | None = None,
) -> bool:
    """Accept only a linear, evidence-only descendant of a recorded source.

    Generated evidence cannot contain the hash of the commit that later records
    that same evidence. This permits the unavoidable recording commit(s) while
    rejecting merges, rewritten ancestry, source changes, empty commits, path
    lookalikes, and unbounded evidence-only history.
    """

    if _HEX40.fullmatch(recorded_commit) is None:
        return False
    actual_current = current_git_commit(repository_root)
    selected_current = current_commit or actual_current
    if (
        actual_current is None
        or selected_current != actual_current
        or _HEX40.fullmatch(selected_current) is None
    ):
        return False
    if recorded_commit == selected_current:
        return True
    if not _git_succeeded(
        repository_root,
        "merge-base",
        "--is-ancestor",
        recorded_commit,
        selected_current,
    ):
        return False
    lineage_result = _git(
        repository_root,
        "rev-list",
        "--reverse",
        "--ancestry-path",
        f"{recorded_commit}..{selected_current}",
    )
    if not _result_succeeded(lineage_result):
        return False
    lineage = [
        line
        for line in str(lineage_result.get("stdout", "")).splitlines()
        if line
    ]
    if (
        not lineage
        or len(lineage) > MAX_GENERATED_EVIDENCE_DESCENDANT_COMMITS
        or lineage[-1] != selected_current
        or any(_HEX40.fullmatch(commit) is None for commit in lineage)
    ):
        return False

    previous = recorded_commit
    for commit in lineage:
        parent_result = _git(
            repository_root,
            "rev-list",
            "--parents",
            "-n",
            "1",
            commit,
        )
        if not _result_succeeded(parent_result):
            return False
        ancestry = str(parent_result.get("stdout", "")).split()
        if len(ancestry) != 2 or ancestry != [commit, previous]:
            return False
        changed_paths = _changed_paths(repository_root, commit)
        if (
            changed_paths is None
            or not changed_paths
            or any(
                not generated_evidence_path_allowed(path)
                for path in changed_paths
            )
        ):
            return False
        previous = commit
    return previous == selected_current


def _changed_paths(
    repository_root: Path,
    commit: str,
) -> tuple[str, ...] | None:
    try:
        completed = subprocess.run(
            [
                "git",
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "--no-renames",
                "-z",
                commit,
            ],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=False,
        )
    except OSError:
        return None
    if completed.returncode != 0 or completed.stderr:
        return None
    try:
        decoded = completed.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return tuple(path for path in decoded.split("\0") if path)


def _result_succeeded(result: dict[str, Any]) -> bool:
    return (
        result.get("returncode") == 0
        and not result.get("stderr")
    )


def _git_succeeded(repository_root: Path, *args: str) -> bool:
    return _result_succeeded(_git(repository_root, *args))


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
