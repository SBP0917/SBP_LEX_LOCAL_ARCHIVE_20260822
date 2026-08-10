from __future__ import annotations

import json
from pathlib import Path

from sbp_video.cli import build_parser, main
from sbp_video.manifest import SceneManifest
from sbp_video.samples import write_samples


def test_sample_writer_creates_two_general_and_three_cockpit_scenes(tmp_path: Path) -> None:
    files = write_samples(tmp_path)
    scene_paths = [Path(path) for key, path in files.items() if key != "cockpit-snapshot"]
    assert len(scene_paths) == 5
    for path in scene_paths:
        assert SceneManifest.load(path).to_dict()["metadata"]["runtime_authority"] == "NONE"


def test_cli_new_validate_inspect_and_compile(tmp_path: Path, capsys: object) -> None:
    manifest_path = tmp_path / "new.scene.json"
    assert main(["new", str(manifest_path), "--name", "CLI Scene", "--width", "640", "--height", "360"]) == 0
    assert main(["validate", str(manifest_path)]) == 0
    assert main(["inspect", str(manifest_path)]) == 0
    assert main(["compile", str(manifest_path), "--build-dir", str(tmp_path / "build")]) == 0
    assert (tmp_path / "build" / "render-plan.json").exists()


def test_schema_document_identifies_scene_v1() -> None:
    schema_path = Path(__file__).resolve().parents[2] / "sbp_video" / "schemas" / "scene-manifest-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == "sbp-video-scene/v1"
    assert schema["properties"]["metadata"]["properties"]["runtime_authority"]["const"] == "NONE"


def test_desktop_command_is_available_without_launching_ui() -> None:
    args = build_parser().parse_args(["desktop"])
    assert args.command == "desktop"
    assert args.manifest is None
