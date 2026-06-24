from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Any, Mapping, Sequence


COMMAND_PASS = "COMMAND_PASS"
COMMAND_FAIL = "COMMAND_FAIL"
COMMAND_NOT_RUN = "COMMAND_NOT_RUN"
COMMAND_SKIPPED = "COMMAND_SKIPPED"
COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
COMMAND_ERROR = "COMMAND_ERROR"

OUTPUT_EXCERPT_LIMIT = 1200
DEFAULT_COMMAND_TIMEOUT_SECONDS = 180

SUPPORTED_COMMANDS: tuple[dict[str, Any], ...] = (
    {
        "command_id": "compileall",
        "command_text": "python -m compileall -q .",
        "command_args": ["python", "-m", "compileall", "-q", "."],
        "python_command": True,
    },
    {
        "command_id": "pytest",
        "command_text": "python -m pytest -q",
        "command_args": ["python", "-m", "pytest", "-q"],
        "python_command": True,
    },
    {
        "command_id": "run_tests_bat",
        "command_text": "scripts\\run_tests.bat",
        "command_args": ["cmd", "/c", "scripts\\run_tests.bat"],
        "python_command": False,
    },
    {
        "command_id": "runtime_main",
        "command_text": "python main.py",
        "command_args": ["python", "main.py"],
        "python_command": True,
    },
    {
        "command_id": "runtime_replay",
        "command_text": "python main.py replay",
        "command_args": ["python", "main.py", "replay"],
        "python_command": True,
    },
    {
        "command_id": "git_diff_check",
        "command_text": "git diff --check",
        "command_args": ["git", "diff", "--check"],
        "python_command": False,
    },
    {
        "command_id": "git_status_short",
        "command_text": "git status --short",
        "command_args": ["git", "status", "--short"],
        "python_command": False,
    },
)


def command_skeletons(repository_root: Path) -> list[dict[str, Any]]:
    return [
        {
            "command_id": command["command_id"],
            "command_text": command["command_text"],
            "command_args": list(command["command_args"]),
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "exit_code": None,
            "stdout_digest": None,
            "stderr_digest": None,
            "stdout_excerpt": "",
            "stderr_excerpt": "",
            "working_directory": str(repository_root),
            "python_executable_if_python_command": sys.executable if command["python_command"] else None,
            "command_status": COMMAND_NOT_RUN,
        }
        for command in SUPPORTED_COMMANDS
    ]


def capture_supported_commands(
    repository_root: Path,
    *,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    command_definitions: Sequence[Mapping[str, Any]] = SUPPORTED_COMMANDS,
) -> list[dict[str, Any]]:
    return [
        capture_command(command, repository_root, timeout_seconds=timeout_seconds)
        for command in command_definitions
    ]


def capture_command(
    command: Mapping[str, Any],
    repository_root: Path,
    *,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    started_at = _timestamp()
    started = monotonic()
    args = _resolved_args(command)
    try:
        completed = subprocess.run(
            args,
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=_safe_execution_environment(repository_root),
        )
        finished_at = _timestamp()
        return _command_record(
            command,
            repository_root,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=_duration_ms(started),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            command_status=COMMAND_PASS if completed.returncode == 0 else COMMAND_FAIL,
        )
    except subprocess.TimeoutExpired as exc:
        return _command_record(
            command,
            repository_root,
            started_at=started_at,
            finished_at=_timestamp(),
            duration_ms=_duration_ms(started),
            exit_code=None,
            stdout=_decode_output(exc.stdout),
            stderr=_decode_output(exc.stderr),
            command_status=COMMAND_TIMEOUT,
        )
    except OSError as exc:
        return _command_record(
            command,
            repository_root,
            started_at=started_at,
            finished_at=_timestamp(),
            duration_ms=_duration_ms(started),
            exit_code=None,
            stdout="",
            stderr=str(exc),
            command_status=COMMAND_ERROR,
        )


def summarize_runtime_result(command_results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    record = _record_by_id(command_results, "runtime_main")
    summary = _base_summary(record)
    parsed = _parse_json_stdout(record)
    if isinstance(parsed, Mapping):
        summary.update(
            {
                "decision": parsed.get("decision"),
                "execution_result": parsed.get("execution_result"),
                "pipeline_mode": parsed.get("pipeline_mode"),
                "convergence_matched": parsed.get("convergence_matched"),
                "token_failures": parsed.get("token_failures"),
            }
        )
    return summary


def summarize_replay_result(command_results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    record = _record_by_id(command_results, "runtime_replay")
    summary = _base_summary(record)
    parsed = _parse_json_stdout(record)
    if isinstance(parsed, Mapping):
        summary.update(
            {
                "replay_count": parsed.get("replay_count"),
                "matched": parsed.get("matched"),
                "mismatches": parsed.get("mismatches"),
            }
        )
    return summary


def digest_text(value: str) -> str:
    return sha256(value.encode("utf-8", errors="replace")).hexdigest()


def bounded_excerpt(value: str, *, limit: int = OUTPUT_EXCERPT_LIMIT) -> str:
    if len(value) <= limit:
        return value
    half = max(1, (limit - len("\n...[truncated]...\n")) // 2)
    return f"{value[:half]}\n...[truncated]...\n{value[-half:]}"


def path_digest_or_summary() -> dict[str, Any]:
    path_value = os.environ.get("PATH", "")
    parts = [part for part in path_value.split(os.pathsep) if part]
    return {
        "path_digest": digest_text(path_value),
        "path_entry_count": len(parts),
        "path_first_entries": parts[:3],
    }


def shell_type_if_available() -> str:
    return os.environ.get("COMSPEC") or os.environ.get("SHELL") or "UNKNOWN"


def _command_record(
    command: Mapping[str, Any],
    repository_root: Path,
    *,
    started_at: str | None,
    finished_at: str | None,
    duration_ms: int | None,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    command_status: str,
) -> dict[str, Any]:
    return {
        "command_id": command["command_id"],
        "command_text": command["command_text"],
        "command_args": list(command["command_args"]),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "stdout_digest": digest_text(stdout),
        "stderr_digest": digest_text(stderr),
        "stdout_excerpt": bounded_excerpt(stdout),
        "stderr_excerpt": bounded_excerpt(stderr),
        "working_directory": str(repository_root),
        "python_executable_if_python_command": sys.executable if command.get("python_command") else None,
        "command_status": command_status,
    }


def _resolved_args(command: Mapping[str, Any]) -> list[str]:
    args = list(command["command_args"])
    if command.get("python_command"):
        return [sys.executable, *args[1:]]
    return args


def _safe_execution_environment(repository_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    python_dir = str(Path(sys.executable).resolve().parent)
    temp_root = repository_root.parent / ".sbp_lex_local_trust_temp"
    temp_root.mkdir(parents=True, exist_ok=True)
    environment["PATH"] = python_dir + os.pathsep + environment.get("PATH", "")
    environment["TMP"] = str(temp_root)
    environment["TEMP"] = str(temp_root)
    environment["PYTEST_ADDOPTS"] = _merged_pytest_addopts(environment.get("PYTEST_ADDOPTS", ""))
    return environment


def _merged_pytest_addopts(existing: str) -> str:
    ignore_outputs = "--ignore=outputs"
    if ignore_outputs in existing.split():
        return existing
    return f"{existing} {ignore_outputs}".strip()


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _duration_ms(started: float) -> int:
    return int(round((monotonic() - started) * 1000))


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _record_by_id(command_results: Sequence[Mapping[str, Any]], command_id: str) -> Mapping[str, Any] | None:
    for record in command_results:
        if record.get("command_id") == command_id:
            return record
    return None


def _base_summary(record: Mapping[str, Any] | None) -> dict[str, Any]:
    if record is None:
        return {
            "command_status": COMMAND_NOT_RUN,
            "exit_code": None,
            "stdout_digest": None,
            "stderr_digest": None,
        }
    return {
        "command_status": record.get("command_status"),
        "exit_code": record.get("exit_code"),
        "stdout_digest": record.get("stdout_digest"),
        "stderr_digest": record.get("stderr_digest"),
    }


def _parse_json_stdout(record: Mapping[str, Any] | None) -> Any:
    if record is None:
        return None
    text = str(record.get("stdout_excerpt") or "")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
