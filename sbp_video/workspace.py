from __future__ import annotations

import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Mapping

from sbp_video.assets import AssetCache
from sbp_video.cockpit import CockpitVisualizationAdapter
from sbp_video.errors import WorkspaceBusyError, WorkspaceError
from sbp_video.manifest import SceneManifest, default_manifest, validate_manifest
from sbp_video.pipeline import VideoPipeline
from sbp_video.samples import write_samples


_PROJECT_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}")
_MAX_ASSET_BYTES = 64 * 1024 * 1024


def default_workspace_root() -> Path:
    configured = os.environ.get("SBP_VIDEO_WORKSPACE")
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "SBP-LEX" / "VideoStudio"
    data_home = os.environ.get("XDG_DATA_HOME")
    if data_home:
        return Path(data_home).expanduser() / "sbp-lex" / "video-studio"
    return Path.home() / ".local" / "share" / "sbp-lex" / "video-studio"


def _project_id(value: object) -> str:
    candidate = str(value or "")
    if not _PROJECT_ID.fullmatch(candidate):
        raise WorkspaceError(f"invalid project id: {candidate or '<empty>'}")
    return candidate


class VideoWorkspace:
    """Confined local project, asset, build, and render orchestration surface."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        blender: str | Path | None = None,
        ffmpeg: str | Path | None = None,
    ) -> None:
        self.root = Path(root or default_workspace_root()).expanduser().resolve()
        self.projects = self.root / "projects"
        self.builds = self.root / "builds"
        self.asset_cache_path = self.root / "asset-cache"
        self.imports = self.root / "imports"
        for directory in (self.projects, self.builds, self.asset_cache_path, self.imports):
            directory.mkdir(parents=True, exist_ok=True)
        self.asset_cache = AssetCache(self.asset_cache_path)
        self.pipeline = VideoPipeline(
            project_root=self.projects,
            asset_cache=self.asset_cache_path,
            blender=blender,
            ffmpeg=ffmpeg,
        )
        self._render_lock = threading.Lock()

    def _manifest_path(self, project_id: str) -> Path:
        return self.projects / f"{_project_id(project_id)}.scene.json"

    def _build_directory(self, manifest: SceneManifest) -> Path:
        project_id = _project_id(manifest.to_dict()["project"]["id"])
        return self.builds / project_id / manifest.digest[:16]

    def status(self) -> dict[str, Any]:
        return {
            **self.pipeline.tool_status(),
            "workspace": str(self.root),
            "project_count": len(self.list_projects()),
            "service_authority": "LOCAL_VISUALIZATION_ONLY",
        }

    def list_projects(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for path in sorted(self.projects.glob("*.scene.json")):
            try:
                manifest = SceneManifest.load(path)
            except (OSError, ValueError):
                continue
            data = manifest.to_dict()
            result.append(
                {
                    "id": data["project"]["id"],
                    "name": data["project"]["name"],
                    "duration_seconds": data["render"]["duration_seconds"],
                    "fps": data["render"]["fps"],
                    "manifest_digest": manifest.digest,
                }
            )
        return result

    def new_project(
        self,
        name: str = "Untitled Scene",
        *,
        duration_seconds: float = 10.0,
        fps: int = 30,
        width: int = 1920,
        height: int = 1080,
    ) -> SceneManifest:
        data = default_manifest(str(name or "Untitled Scene"))
        data["render"].update(
            {
                "duration_seconds": duration_seconds,
                "fps": fps,
                "resolution": {"width": width, "height": height, "percentage": 100},
            }
        )
        return self.save_manifest(data)

    def load_project(self, project_id: str) -> SceneManifest:
        path = self._manifest_path(project_id)
        if not path.is_file():
            raise WorkspaceError(f"project does not exist: {project_id}")
        return SceneManifest.load(path)

    def save_manifest(self, data: Mapping[str, Any]) -> SceneManifest:
        manifest = SceneManifest.from_dict(data)
        project_id = _project_id(manifest.to_dict()["project"]["id"])
        target = self._manifest_path(project_id)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(manifest.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)
        return manifest

    @staticmethod
    def validate(data: Mapping[str, Any]) -> list[str]:
        return validate_manifest(data)

    def compile(self, data: Mapping[str, Any]) -> dict[str, Any]:
        manifest = self.save_manifest(data)
        plan = self.pipeline.compile(manifest, self._build_directory(manifest))
        return plan.to_dict()

    def render(self, data: Mapping[str, Any]) -> dict[str, Any]:
        if not self._render_lock.acquire(blocking=False):
            raise WorkspaceBusyError("a local render is already in progress")
        try:
            manifest = self.save_manifest(data)
            return self.pipeline.render(manifest, self._build_directory(manifest)).to_dict()
        finally:
            self._render_lock.release()

    def cockpit_scene(
        self,
        snapshot: Mapping[str, Any],
        *,
        layer: str,
        scenario: Mapping[str, Any] | None = None,
    ) -> SceneManifest:
        manifest = CockpitVisualizationAdapter().build_scene(snapshot, layer=layer, scenario=scenario)
        return self.save_manifest(manifest.to_dict())

    def create_samples(self) -> dict[str, str]:
        return write_samples(self.projects)

    def import_asset(
        self,
        *,
        filename: str,
        data_base64: str,
        kind: str | None = None,
        asset_id: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        safe_name = Path(filename).name
        if not safe_name or safe_name != filename or safe_name in {".", ".."}:
            raise WorkspaceError("asset filename must be a portable basename")
        try:
            payload = base64.b64decode(data_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise WorkspaceError("asset payload is not valid base64") from exc
        if not payload or len(payload) > _MAX_ASSET_BYTES:
            raise WorkspaceError("asset payload is empty or exceeds 64 MiB")
        with tempfile.TemporaryDirectory(dir=self.imports) as temporary:
            source = Path(temporary) / safe_name
            source.write_bytes(payload)
            record = self.asset_cache.import_file(source, kind=kind, asset_id=asset_id)
        entry = record.to_manifest_entry()
        if project_id:
            manifest = self.load_project(project_id)
            data = manifest.to_dict()
            data["assets"] = [asset for asset in data["assets"] if asset["id"] != record.id]
            data["assets"].append(deepcopy(entry))
            manifest = self.save_manifest(data)
            return {"asset": entry, "manifest": manifest.to_dict(), "manifest_digest": manifest.digest}
        return {"asset": entry}

    def artifact(self, project_id: str, digest: str, filename: str) -> Path:
        project = _project_id(project_id)
        if not re.fullmatch(r"[0-9a-f]{16}", digest):
            raise WorkspaceError("invalid build digest")
        safe_name = Path(filename).name
        if safe_name != filename or safe_name in {"", ".", ".."}:
            raise WorkspaceError("invalid artifact filename")
        build = (self.builds / project / digest).resolve()
        target = (build / "output" / safe_name).resolve()
        if not target.is_relative_to(build) or not target.is_file():
            raise WorkspaceError("artifact does not exist")
        return target
