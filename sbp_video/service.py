from __future__ import annotations

import ipaddress
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from sbp_video.constants import RUNTIME_AUTHORITY
from sbp_video.errors import VideoStudioError, WorkspaceBusyError
from sbp_video.workspace import VideoWorkspace


MAX_REQUEST_BYTES = 90 * 1024 * 1024


def _loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _allowed_origin(origin: str | None) -> str | None:
    if not origin:
        return None
    parsed = urlparse(origin)
    if parsed.scheme in {"http", "https"} and parsed.hostname and _loopback_host(parsed.hostname):
        return origin
    return None


def _payload(value: Mapping[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        **dict(value or {}),
        **extra,
        "runtime_authority": RUNTIME_AUTHORITY,
        "canonical_runtime_mutation": False,
    }


class VideoStudioHandler(BaseHTTPRequestHandler):
    server_version = "SBPVideoStudio/0.2"

    @property
    def workspace(self) -> VideoWorkspace:
        return self.server.workspace  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        return

    def _headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        origin = _allowed_origin(self.headers.get("Origin"))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()

    def _json(self, status: int, value: Mapping[str, Any]) -> None:
        body = (json.dumps(_payload(value), sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type.lower():
            raise ValueError("content type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body is empty or too large")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_OPTIONS(self) -> None:
        origin = _allowed_origin(self.headers.get("Origin"))
        if self.headers.get("Origin") and not origin:
            return self._json(403, {"status": "ERROR", "error": "origin_not_allowed"})
        self.send_response(204)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def do_GET(self) -> None:
        if self.headers.get("Origin") and not _allowed_origin(self.headers.get("Origin")):
            return self._json(403, {"status": "ERROR", "error": "origin_not_allowed"})
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path == "/health":
                return self._json(200, {"ok": True, "service": "SBP Video Studio", **self.workspace.status()})
            if parsed.path == "/projects":
                return self._json(200, {"status": "OK", "projects": self.workspace.list_projects()})
            if parsed.path == "/project":
                manifest = self.workspace.load_project(query.get("id", [""])[0])
                return self._json(200, {"status": "OK", "manifest": manifest.to_dict(), "manifest_digest": manifest.digest})
            if parsed.path == "/artifact":
                target = self.workspace.artifact(
                    query.get("project", [""])[0],
                    query.get("digest", [""])[0],
                    query.get("filename", [""])[0],
                )
                body = target.read_bytes()
                content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
                self._headers(200, content_type, len(body))
                self.wfile.write(body)
                return
            return self._json(404, {"status": "ERROR", "error": "not_found"})
        except (VideoStudioError, OSError, ValueError) as exc:
            return self._json(404, {"status": "ERROR", "error": str(exc)})

    def do_POST(self) -> None:
        if self.headers.get("Origin") and not _allowed_origin(self.headers.get("Origin")):
            return self._json(403, {"status": "ERROR", "error": "origin_not_allowed"})
        parsed = urlparse(self.path)
        try:
            body = self._read_json()
            if parsed.path == "/new":
                manifest = self.workspace.new_project(
                    str(body.get("name", "Untitled Scene")),
                    duration_seconds=float(body.get("duration_seconds", 10.0)),
                    fps=int(body.get("fps", 30)),
                    width=int(body.get("width", 1920)),
                    height=int(body.get("height", 1080)),
                )
                return self._json(201, {"status": "SCENE_CREATED", "manifest": manifest.to_dict(), "manifest_digest": manifest.digest})
            if parsed.path == "/validate":
                errors = self.workspace.validate(body.get("manifest", {}))
                return self._json(200, {"status": "VALID" if not errors else "INVALID", "errors": errors})
            if parsed.path == "/save":
                manifest = self.workspace.save_manifest(body.get("manifest", {}))
                return self._json(200, {"status": "SCENE_SAVED", "manifest": manifest.to_dict(), "manifest_digest": manifest.digest})
            if parsed.path == "/compile":
                return self._json(200, {"status": "SCENE_COMPILED", "plan": self.workspace.compile(body.get("manifest", {}))})
            if parsed.path == "/render":
                return self._json(200, {"status": "RENDER_COMPLETE", "result": self.workspace.render(body.get("manifest", {}))})
            if parsed.path == "/cockpit":
                manifest = self.workspace.cockpit_scene(
                    body.get("snapshot", {}),
                    layer=str(body.get("layer", "rehearsal")),
                    scenario=body.get("scenario") if isinstance(body.get("scenario"), dict) else None,
                )
                return self._json(201, {"status": "COCKPIT_SCENE_CREATED", "manifest": manifest.to_dict(), "manifest_digest": manifest.digest})
            if parsed.path == "/samples":
                return self._json(201, {"status": "SAMPLES_CREATED", "files": self.workspace.create_samples()})
            if parsed.path == "/asset-import":
                result = self.workspace.import_asset(
                    filename=str(body.get("filename", "")),
                    data_base64=str(body.get("data_base64", "")),
                    kind=str(body["kind"]) if body.get("kind") else None,
                    asset_id=str(body["asset_id"]) if body.get("asset_id") else None,
                    project_id=str(body["project_id"]) if body.get("project_id") else None,
                )
                return self._json(201, {"status": "ASSET_IMPORTED", **result})
            return self._json(404, {"status": "ERROR", "error": "not_found"})
        except WorkspaceBusyError as exc:
            return self._json(409, {"status": "BUSY", "error": str(exc)})
        except (VideoStudioError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._json(400, {"status": "ERROR", "error": str(exc)})


class VideoStudioServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], workspace: VideoWorkspace) -> None:
        self.workspace = workspace
        super().__init__(address, VideoStudioHandler)


def create_server(host: str, port: int, workspace: VideoWorkspace) -> VideoStudioServer:
    if not _loopback_host(host):
        raise ValueError(f"Video Studio only binds to loopback, not {host}")
    return VideoStudioServer((host, port), workspace)


def run_service(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    workspace: str | None = None,
    blender: str | None = None,
    ffmpeg: str | None = None,
) -> None:
    video_workspace = VideoWorkspace(workspace, blender=blender, ffmpeg=ffmpeg)
    server = create_server(host, port, video_workspace)
    print(f"SBP Video Studio listening on http://{host}:{port}")
    print(f"Workspace: {video_workspace.root}")
    server.serve_forever()
