from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from typing import Any

from sbp_video.assets import AssetCache, resolve_manifest_assets
from sbp_video.backends.base import RenderPlan, find_executable, inspect_tool, require_executable
from sbp_video.backends.blender import BlenderBackend
from sbp_video.backends.ffmpeg import FFmpegBackend
from sbp_video.constants import RUNTIME_AUTHORITY
from sbp_video.errors import RenderError
from sbp_video.manifest import SceneManifest


@dataclass(frozen=True)
class RenderResult:
    status: str
    manifest_digest: str
    build_directory: str
    output_file: str
    frames_rendered: bool
    encoded: bool
    runtime_authority: str = RUNTIME_AUTHORITY
    canonical_runtime_mutation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VideoPipeline:
    """Local orchestration layer for compile, Blender render, and FFmpeg export."""

    def __init__(
        self,
        *,
        project_root: str | Path = ".",
        asset_cache: str | Path | None = None,
        blender: str | Path | None = None,
        ffmpeg: str | Path | None = None,
    ) -> None:
        self.project_root = Path(project_root).expanduser().resolve()
        configured_cache = asset_cache or os.environ.get("SBP_VIDEO_ASSET_CACHE")
        self.asset_cache = AssetCache(configured_cache) if configured_cache is not None else None
        self.blender_explicit = blender or os.environ.get("SBP_VIDEO_BLENDER_PATH")
        self.ffmpeg_explicit = ffmpeg or os.environ.get("SBP_VIDEO_FFMPEG_PATH")

    def tool_status(self) -> dict[str, Any]:
        return {
            "application": "SBP Video Studio",
            "tools": {
                "blender": inspect_tool("blender", self.blender_explicit).to_dict(),
                "ffmpeg": inspect_tool("ffmpeg", self.ffmpeg_explicit).to_dict(),
            },
            "runtime_authority": RUNTIME_AUTHORITY,
            "canonical_runtime_mutation": False,
        }

    def _resolve_assets(self, manifest: SceneManifest) -> dict[str, Path]:
        data = manifest.to_dict()
        if not data["assets"]:
            return {}
        return resolve_manifest_assets(
            data["assets"],
            project_root=self.project_root,
            cache=self.asset_cache,
        )

    def compile(self, manifest: SceneManifest, build_directory: str | Path) -> RenderPlan:
        data = manifest.to_dict()
        build_dir = Path(build_directory).expanduser().resolve()
        build_dir.mkdir(parents=True, exist_ok=True)
        asset_paths = self._resolve_assets(manifest)
        blender_executable = find_executable("blender", self.blender_explicit) or "blender"
        ffmpeg_executable = (
            find_executable("ffmpeg", self.ffmpeg_explicit) or "ffmpeg"
            if data["output"]["format"] not in {"png_sequence", "exr_sequence"}
            else find_executable("ffmpeg", self.ffmpeg_explicit) or "ffmpeg"
        )
        blender = BlenderBackend(blender_executable)
        canonical_path, script_path = blender.compile(
            manifest,
            build_directory=build_dir,
            asset_paths=asset_paths,
        )
        frame_extension = ".exr" if data["output"]["format"] == "exr_sequence" else ".png"
        frames_pattern = build_dir / "frames" / f"frame_%04d{frame_extension}"
        output_file = frames_pattern if data["output"]["format"] in {"png_sequence", "exr_sequence"} else build_dir / "output" / Path(data["output"]["filename"]).name
        output_file.parent.mkdir(parents=True, exist_ok=True)
        blender_command = blender.command(script_path, build_dir, render=True)
        ffmpeg_command = FFmpegBackend(ffmpeg_executable).build_command(
            data,
            frames_pattern=frames_pattern,
            output_file=output_file,
            asset_paths=asset_paths,
        )
        plan = RenderPlan(
            manifest_digest=manifest.digest,
            build_directory=str(build_dir),
            canonical_manifest=str(canonical_path),
            blender_script=str(script_path),
            frames_pattern=str(frames_pattern),
            output_file=str(output_file),
            blender_command=tuple(blender_command),
            ffmpeg_command=tuple(ffmpeg_command) if ffmpeg_command else None,
        )
        (build_dir / "render-plan.json").write_text(
            json.dumps(
                {
                    **plan.to_dict(),
                    "runtime_authority": RUNTIME_AUTHORITY,
                    "canonical_runtime_mutation": False,
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        return plan

    def render(self, manifest: SceneManifest, build_directory: str | Path) -> RenderResult:
        plan = self.compile(manifest, build_directory)
        blender_path = require_executable("blender", self.blender_explicit)
        blender_command = [blender_path, *plan.blender_command[1:]]
        BlenderBackend(blender_path).execute(blender_command)
        frames_pattern = Path(plan.frames_pattern)
        frame_glob = frames_pattern.name.replace("%04d", "*")
        if not list(frames_pattern.parent.glob(frame_glob)):
            raise RenderError("Blender completed without producing the expected frame sequence")
        encoded = False
        if plan.ffmpeg_command is not None:
            ffmpeg_path = require_executable("ffmpeg", self.ffmpeg_explicit)
            ffmpeg_command = [ffmpeg_path, *plan.ffmpeg_command[1:]]
            FFmpegBackend(ffmpeg_path).encode(ffmpeg_command)
            encoded = True
        return RenderResult(
            status="RENDER_COMPLETE",
            manifest_digest=manifest.digest,
            build_directory=plan.build_directory,
            output_file=plan.output_file,
            frames_rendered=True,
            encoded=encoded,
        )
