from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbp_video.assets import AssetCache, AssetError, resolve_manifest_assets
from sbp_video.backends.ffmpeg import FFmpegBackend
from sbp_video.backends.blender import BlenderBackend
from sbp_video.errors import RenderError
from sbp_video.editor import ProjectEditor
from sbp_video.pipeline import VideoPipeline
from sbp_video.samples import general_scene


def test_asset_cache_is_content_addressed_and_verified(tmp_path: Path) -> None:
    source = tmp_path / "tone.wav"
    source.write_bytes(b"RIFF-test-audio-hook")
    cache = AssetCache(tmp_path / "cache")
    first = cache.import_file(source, asset_id="tone")
    second = cache.import_file(source, asset_id="tone-copy")
    assert first.sha256 == second.sha256
    assert cache.resolve(first.to_manifest_entry()).read_bytes() == source.read_bytes()


def test_asset_cache_rejects_kind_extension_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "image.png"
    source.write_bytes(b"not-a-real-image")
    with pytest.raises(AssetError):
        AssetCache(tmp_path / "cache").import_file(source, kind="audio")


def test_relative_asset_resolution_cannot_escape_project(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.wav"
    outside.write_bytes(b"audio")
    with pytest.raises(AssetError):
        resolve_manifest_assets(
            [{"id": "outside", "kind": "audio", "uri": "../outside.wav"}],
            project_root=project,
        )


def test_pipeline_compiles_canonical_manifest_blender_script_and_plan(tmp_path: Path) -> None:
    manifest = general_scene()
    plan = VideoPipeline(project_root=tmp_path).compile(manifest, tmp_path / "build")
    assert Path(plan.canonical_manifest).read_text(encoding="utf-8").strip() == manifest.to_canonical_json()
    script = Path(plan.blender_script).read_text(encoding="utf-8")
    assert "import bpy" in script
    assert "bpy.ops.render.render(animation=True)" in script
    assert manifest.digest == json.loads((tmp_path / "build" / "render-plan.json").read_text(encoding="utf-8"))["manifest_digest"]
    compile(Path(plan.blender_script).read_text(encoding="utf-8"), plan.blender_script, "exec")


def test_ffmpeg_command_contains_audio_delay_gain_and_mapping(tmp_path: Path) -> None:
    source = tmp_path / "tone.wav"
    source.write_bytes(b"RIFF-test")
    cache = AssetCache(tmp_path / "cache")
    record = cache.import_file(source, asset_id="tone")
    editor = ProjectEditor.new("Audio Hook", duration_seconds=4)
    editor.add_asset(record).add_audio_track("music", asset_id="tone", start=1.25, gain_db=-3.0)
    manifest = editor.manifest().to_dict()
    command = FFmpegBackend("ffmpeg").build_command(
        manifest,
        frames_pattern=tmp_path / "frames" / "frame_%04d.png",
        output_file=tmp_path / "video.mp4",
        asset_paths={"tone": cache.resolve(record.to_manifest_entry())},
    )
    assert command is not None
    filter_graph = command[command.index("-filter_complex") + 1]
    assert "adelay=1250:all=1" in filter_graph
    assert "volume=-3.0dB" in filter_graph
    assert "[aout]" in command


def test_blender_backend_treats_script_traceback_as_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class Completed:
        returncode = 0
        stdout = "Traceback (most recent call last):\nTypeError: backend mismatch"
        stderr = ""

    monkeypatch.setattr("sbp_video.backends.blender.subprocess.run", lambda *args, **kwargs: Completed())
    with pytest.raises(RenderError, match="backend mismatch"):
        BlenderBackend("blender").execute(["blender"])
