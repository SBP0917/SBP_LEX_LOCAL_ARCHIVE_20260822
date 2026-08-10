from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any, Mapping

from sbp_video.errors import RenderError


class FFmpegBackend:
    """Build and optionally execute deterministic frame/audio encoding commands."""

    def __init__(self, executable: str = "ffmpeg") -> None:
        self.executable = executable

    def build_command(
        self,
        manifest: Mapping[str, Any],
        *,
        frames_pattern: str | Path,
        output_file: str | Path,
        asset_paths: Mapping[str, Path] | None = None,
    ) -> list[str] | None:
        output = manifest["output"]
        if output["format"] in {"png_sequence", "exr_sequence"}:
            return None
        render = manifest["render"]
        command = [
            self.executable,
            "-y",
            "-framerate",
            str(render["fps"]),
            "-i",
            str(frames_pattern),
        ]
        asset_paths = asset_paths or {}
        audio_tracks = manifest["audio"]["tracks"]
        for track in audio_tracks:
            if track.get("loop"):
                command.extend(["-stream_loop", "-1"])
            command.extend(["-i", str(asset_paths[track["asset_id"]])])

        if audio_tracks:
            filter_parts: list[str] = []
            audio_labels: list[str] = []
            for index, track in enumerate(audio_tracks, start=1):
                delay = max(0, round(float(track.get("start", 0)) * 1000))
                gain = float(track.get("gain_db", 0))
                label = f"a{index}"
                filter_parts.append(f"[{index}:a]adelay={delay}:all=1,volume={gain}dB[{label}]")
                audio_labels.append(f"[{label}]")
            if len(audio_labels) == 1:
                filter_parts.append(f"{audio_labels[0]}anull[aout]")
            else:
                filter_parts.append("".join(audio_labels) + f"amix=inputs={len(audio_labels)}:normalize=0[aout]")
            command.extend(["-filter_complex", ";".join(filter_parts), "-map", "0:v:0", "-map", "[aout]"])
        else:
            command.extend(["-map", "0:v:0"])

        duration = str(manifest["render"]["duration_seconds"])
        command.extend([
            "-t",
            duration,
            "-c:v",
            str(output.get("video_codec", "libx264")),
            "-crf",
            str(output.get("quality", 18)),
            "-pix_fmt",
            "yuv420p",
        ])
        if audio_tracks:
            command.extend(["-c:a", str(output.get("audio_codec", "aac")), "-ar", str(manifest["audio"]["sample_rate"])])
        if output["format"] == "mp4":
            command.extend(["-movflags", "+faststart"])
        command.append(str(output_file))
        return command

    def encode(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            detail = completed.stderr[-4000:] if completed.stderr else "no stderr"
            raise RenderError(f"FFmpeg encoding failed ({completed.returncode}): {detail}")
        return completed
