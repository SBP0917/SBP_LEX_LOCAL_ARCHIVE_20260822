from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from sbp_video.assets import AssetCache
from sbp_video.boundary import run_boundary_check
from sbp_video.cockpit import CockpitVisualizationAdapter, PresentationLayer
from sbp_video.constants import APP_NAME, APP_VERSION, RUNTIME_AUTHORITY
from sbp_video.editor import ProjectEditor
from sbp_video.errors import VideoStudioError
from sbp_video.manifest import SceneManifest, validate_manifest
from sbp_video.pipeline import VideoPipeline
from sbp_video.samples import write_samples


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str))


def _pipeline(args: argparse.Namespace) -> VideoPipeline:
    return VideoPipeline(
        project_root=getattr(args, "project_root", "."),
        asset_cache=getattr(args, "asset_cache", None),
        blender=getattr(args, "blender", None),
        ffmpeg=getattr(args, "ffmpeg", None),
    )


def _add_pipeline_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-root", default=".", help="Root used for relative asset URIs")
    parser.add_argument("--asset-cache", help="Content-addressed local asset cache")
    parser.add_argument("--blender", help="Explicit Blender executable path")
    parser.add_argument("--ffmpeg", help="Explicit FFmpeg executable path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sbp-video", description=f"{APP_NAME} {APP_VERSION} — local-first scene and video construction")
    subparsers = parser.add_subparsers(dest="command", required=True)

    new = subparsers.add_parser("new", help="Create an empty scene manifest")
    new.add_argument("output")
    new.add_argument("--name", default="Untitled Scene")
    new.add_argument("--duration", type=float, default=10.0)
    new.add_argument("--fps", type=int, default=30)
    new.add_argument("--width", type=int, default=1920)
    new.add_argument("--height", type=int, default=1080)

    validate = subparsers.add_parser("validate", help="Validate a scene manifest")
    validate.add_argument("manifest")

    inspect = subparsers.add_parser("inspect", help="Show a scene summary and digest")
    inspect.add_argument("manifest")

    compile_parser = subparsers.add_parser("compile", help="Compile a scene to Blender script and render plan")
    compile_parser.add_argument("manifest")
    compile_parser.add_argument("--build-dir", required=True)
    _add_pipeline_arguments(compile_parser)

    render = subparsers.add_parser("render", help="Render frames with Blender and encode with FFmpeg")
    render.add_argument("manifest")
    render.add_argument("--build-dir", required=True)
    _add_pipeline_arguments(render)

    tools = subparsers.add_parser("tools", help="Inspect local Blender and FFmpeg availability")
    _add_pipeline_arguments(tools)

    samples = subparsers.add_parser("samples", help="Generate general and cockpit sample scenes")
    samples.add_argument("output_directory")

    cockpit = subparsers.add_parser("cockpit", help="Adapt a detached SBP-LEX JSON snapshot into a read-only visualization")
    cockpit.add_argument("snapshot")
    cockpit.add_argument("output")
    cockpit.add_argument("--layer", choices=[item.value for item in PresentationLayer], required=True)
    cockpit.add_argument("--scenario", help="Constructed-scenario JSON (required for meaningful scenario mode)")

    asset = subparsers.add_parser("asset-import", help="Import a file into the local content-addressed cache")
    asset.add_argument("source")
    asset.add_argument("--cache", required=True)
    asset.add_argument("--kind")
    asset.add_argument("--id")

    boundary = subparsers.add_parser("boundary-check", help="Verify isolation from SBP-LEX runtime authority")
    boundary.add_argument("--repository-root", default=".")
    desktop = subparsers.add_parser("desktop", help="Launch the local scene editor")
    desktop.add_argument("manifest", nargs="?", help="Optional scene manifest to open")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "new":
            editor = ProjectEditor.new(
                args.name,
                duration_seconds=args.duration,
                fps=args.fps,
                width=args.width,
                height=args.height,
            )
            path = editor.save(args.output)
            _print({"status": "SCENE_CREATED", "path": str(path), "manifest_digest": editor.manifest().digest, "runtime_authority": RUNTIME_AUTHORITY})
            return 0
        if args.command == "validate":
            raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            errors = validate_manifest(raw)
            _print({"status": "VALID" if not errors else "INVALID", "errors": errors, "runtime_authority": RUNTIME_AUTHORITY})
            return 0 if not errors else 1
        if args.command == "inspect":
            manifest = SceneManifest.load(args.manifest)
            data = manifest.to_dict()
            scene = data["scene"]
            _print({
                "status": "VALID",
                "project": data["project"],
                "manifest_digest": manifest.digest,
                "duration_seconds": data["render"]["duration_seconds"],
                "fps": data["render"]["fps"],
                "counts": {
                    "assets": len(data["assets"]),
                    "objects": len(scene["objects"]),
                    "cameras": len(scene["cameras"]),
                    "lights": len(scene["lights"]),
                    "effects": len(scene["effects"]),
                    "overlays": len(scene["overlays"]),
                    "animation_tracks": len(data["timeline"]["tracks"]),
                    "audio_tracks": len(data["audio"]["tracks"]),
                },
                "runtime_authority": RUNTIME_AUTHORITY,
            })
            return 0
        if args.command == "compile":
            manifest = SceneManifest.load(args.manifest)
            plan = _pipeline(args).compile(manifest, args.build_dir)
            _print({"status": "SCENE_COMPILED", **plan.to_dict(), "runtime_authority": RUNTIME_AUTHORITY, "canonical_runtime_mutation": False})
            return 0
        if args.command == "render":
            result = _pipeline(args).render(SceneManifest.load(args.manifest), args.build_dir)
            _print(result.to_dict())
            return 0
        if args.command == "tools":
            _print(_pipeline(args).tool_status())
            return 0
        if args.command == "samples":
            files = write_samples(args.output_directory)
            _print({"status": "SAMPLES_CREATED", "files": files, "runtime_authority": RUNTIME_AUTHORITY})
            return 0
        if args.command == "cockpit":
            snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
            scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8")) if args.scenario else None
            manifest = CockpitVisualizationAdapter().build_scene(snapshot, layer=args.layer, scenario=scenario)
            path = manifest.save(args.output)
            _print({"status": "COCKPIT_SCENE_CREATED", "path": str(path), "manifest_digest": manifest.digest, "presentation_layer": args.layer, "runtime_authority": RUNTIME_AUTHORITY, "canonical_runtime_mutation": False})
            return 0
        if args.command == "asset-import":
            record = AssetCache(args.cache).import_file(args.source, kind=args.kind, asset_id=args.id)
            _print({"status": "ASSET_IMPORTED", "asset": record.to_manifest_entry(), "runtime_authority": RUNTIME_AUTHORITY})
            return 0
        if args.command == "boundary-check":
            result = run_boundary_check(args.repository_root)
            _print(result)
            return 0 if result["finding_count"] == 0 else 1
        if args.command == "desktop":
            from sbp_video.desktop import launch

            return launch(args.manifest)
    except (VideoStudioError, OSError, ValueError, json.JSONDecodeError) as error:
        _print({"status": "ERROR", "error": str(error), "runtime_authority": RUNTIME_AUTHORITY})
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
