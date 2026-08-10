from __future__ import annotations

import base64
import json
from pathlib import Path
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from sbp_video.backends.base import find_executable
from sbp_video.errors import WorkspaceError
from sbp_video.samples import render_smoke_scene, sample_snapshot
from sbp_video.service import create_server
from sbp_video.workspace import VideoWorkspace


def _request(url: str, path: str, body: dict[str, object] | None = None) -> tuple[int, dict[str, object]]:
    request = Request(
        url + path,
        data=None if body is None else json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Origin": "http://127.0.0.1:8000"},
        method="GET" if body is None else "POST",
    )
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_workspace_confines_projects_builds_assets_and_compiles(tmp_path: Path) -> None:
    workspace = VideoWorkspace(tmp_path / "workspace")
    manifest = workspace.save_manifest(render_smoke_scene().to_dict())
    assert workspace.load_project(manifest.to_dict()["project"]["id"]).digest == manifest.digest
    plan = workspace.compile(manifest.to_dict())
    assert Path(plan["build_directory"]).is_relative_to(workspace.root)
    assert Path(plan["canonical_manifest"]).is_file()
    assert workspace.status()["canonical_runtime_mutation"] is False
    with pytest.raises(WorkspaceError):
        workspace.load_project("../escape")


def test_new_projects_do_not_overwrite_an_existing_same_name_project(tmp_path: Path) -> None:
    workspace = VideoWorkspace(tmp_path / "workspace")
    first = workspace.new_project("Repeated Name")
    second = workspace.new_project("Repeated Name")
    assert first.to_dict()["project"]["id"] == "Repeated-Name"
    assert second.to_dict()["project"]["id"] == "Repeated-Name-2"
    assert len(workspace.list_projects()) == 2


def test_workspace_imports_base64_asset_into_content_addressed_cache(tmp_path: Path) -> None:
    workspace = VideoWorkspace(tmp_path / "workspace")
    manifest = workspace.new_project("Asset Scene")
    result = workspace.import_asset(
        filename="tone.wav",
        data_base64=base64.b64encode(b"RIFF-local-hook").decode("ascii"),
        project_id=manifest.to_dict()["project"]["id"],
        asset_id="tone",
    )
    assert result["asset"]["uri"].startswith("asset://")
    assert result["manifest"]["assets"][0]["id"] == "tone"
    with pytest.raises(WorkspaceError):
        workspace.import_asset(filename="../outside.wav", data_base64="UklGRg==")


def test_tool_discovery_honours_durable_environment_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    blender = tmp_path / "blender.exe"
    ffmpeg = tmp_path / "ffmpeg.exe"
    blender.write_bytes(b"tool")
    ffmpeg.write_bytes(b"tool")
    monkeypatch.setenv("SBP_VIDEO_BLENDER_PATH", str(blender))
    monkeypatch.setenv("SBP_VIDEO_FFMPEG_PATH", str(ffmpeg))
    assert find_executable("blender") == str(blender.resolve())
    assert find_executable("ffmpeg") == str(ffmpeg.resolve())


def test_loopback_service_exposes_projects_and_read_only_cockpit_adapter(tmp_path: Path) -> None:
    workspace = VideoWorkspace(tmp_path / "workspace")
    server = create_server("127.0.0.1", 0, workspace)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status, health = _request(url, "/health")
        assert status == 200
        assert health["ok"] is True
        assert health["runtime_authority"] == "NONE"

        status, created = _request(url, "/new", {"name": "Service Scene", "width": 640, "height": 360})
        assert status == 201
        assert created["manifest"]["render"]["resolution"]["width"] == 640

        status, cockpit = _request(
            url,
            "/cockpit",
            {"snapshot": sample_snapshot(), "layer": "full-speed"},
        )
        assert status == 201
        metadata = cockpit["manifest"]["metadata"]
        assert metadata["integration_access"] == "read_only"
        assert metadata["canonical_runtime_mutation"] is False

        status, projects = _request(url, "/projects")
        assert status == 200
        assert len(projects["projects"]) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_service_refuses_non_loopback_bind(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="only binds to loopback"):
        create_server("0.0.0.0", 0, VideoWorkspace(tmp_path / "workspace"))


def test_service_rejects_non_loopback_browser_origin(tmp_path: Path) -> None:
    server = create_server("127.0.0.1", 0, VideoWorkspace(tmp_path / "workspace"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    request = Request(
        url + "/new",
        data=json.dumps({"name": "Blocked"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Origin": "https://example.invalid"},
        method="POST",
    )
    try:
        with pytest.raises(HTTPError) as failure:
            urlopen(request, timeout=5)
        assert failure.value.code == 403
        failure.value.close()
        assert workspace_projects(server) == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def workspace_projects(server: object) -> list[dict[str, object]]:
    return server.workspace.list_projects()  # type: ignore[attr-defined,no-any-return]
