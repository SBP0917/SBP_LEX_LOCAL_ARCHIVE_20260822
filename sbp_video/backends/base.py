from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shutil
import subprocess
from typing import Any

from sbp_video.errors import ToolUnavailableError


@dataclass(frozen=True)
class ToolInfo:
    name: str
    available: bool
    executable: str | None
    version: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RenderPlan:
    manifest_digest: str
    build_directory: str
    canonical_manifest: str
    blender_script: str
    frames_pattern: str
    output_file: str
    blender_command: tuple[str, ...]
    ffmpeg_command: tuple[str, ...] | None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["blender_command"] = list(self.blender_command)
        value["ffmpeg_command"] = list(self.ffmpeg_command) if self.ffmpeg_command else None
        return value


def find_executable(name: str, explicit: str | Path | None = None) -> str | None:
    if explicit is not None:
        candidate = Path(explicit).expanduser().resolve()
        return str(candidate) if candidate.is_file() else None
    return shutil.which(name)


def require_executable(name: str, explicit: str | Path | None = None) -> str:
    executable = find_executable(name, explicit)
    if executable is None:
        raise ToolUnavailableError(f"local tool is unavailable: {name}")
    return executable


def inspect_tool(name: str, explicit: str | Path | None = None) -> ToolInfo:
    executable = find_executable(name, explicit)
    if executable is None:
        return ToolInfo(name=name, available=False, executable=None, version=None)
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        first_line = (completed.stdout or completed.stderr).splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError, IndexError):
        first_line = None
    return ToolInfo(name=name, available=True, executable=executable, version=first_line)
