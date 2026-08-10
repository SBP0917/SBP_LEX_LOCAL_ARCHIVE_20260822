from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
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
        candidate = Path(os.path.expandvars(str(explicit))).expanduser().resolve()
        return str(candidate) if candidate.is_file() else None

    env_name = {
        "blender": "SBP_VIDEO_BLENDER_PATH",
        "ffmpeg": "SBP_VIDEO_FFMPEG_PATH",
    }.get(name.lower())
    if env_name and os.environ.get(env_name):
        candidate = Path(os.path.expandvars(os.environ[env_name])).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())

    discovered = shutil.which(name)
    if discovered:
        return str(Path(discovered).resolve())

    executable_name = f"{name}.exe" if os.name == "nt" else name
    package_root = Path(__file__).resolve().parents[2]
    candidates = [
        package_root / "tools" / name / executable_name,
        package_root / "tools" / executable_name,
        Path(sys.executable).resolve().parent / "tools" / name / executable_name,
    ]
    if os.name == "nt":
        local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
        program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
        candidates.extend(
            [
                local_app_data / "Microsoft" / "WinGet" / "Links" / executable_name,
                Path("C:/ffmpeg/bin") / executable_name,
            ]
        )
        if name.lower() == "blender":
            candidates.extend(
                sorted(
                    (program_files / "Blender Foundation").glob("Blender */blender.exe"),
                    reverse=True,
                )
            )
        elif name.lower() == "ffmpeg":
            packages = local_app_data / "Microsoft" / "WinGet" / "Packages"
            candidates.extend(sorted(packages.glob("Gyan.FFmpeg_*/ffmpeg-*/bin/ffmpeg.exe"), reverse=True))

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


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
