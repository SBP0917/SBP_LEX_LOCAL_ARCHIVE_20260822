from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping

from sbp_video.canonical import canonical_digest, canonical_json
from sbp_video.constants import (
    ASSET_KINDS,
    BLENDER_ENGINES,
    EFFECT_TYPES,
    ID_PATTERN,
    LIGHT_TYPES,
    OBJECT_TYPES,
    OUTPUT_FORMATS,
    OVERLAY_TYPES,
    PRIMITIVE_TYPES,
    RUNTIME_AUTHORITY,
    SCHEMA_VERSION,
)
from sbp_video.errors import ManifestValidationError
from sbp_video.scene_graph import SceneGraph


_ID_RE = re.compile(ID_PATTERN)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_dict(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path}:expected_object")
        return {}
    return value


def _require_list(value: Any, path: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path}:expected_array")
        return []
    return value


def _validate_id(value: Any, path: str, errors: list[str]) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        errors.append(f"{path}:invalid_id")
        return ""
    return value


def _validate_vector(value: Any, length: int, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) != length or not all(_is_number(item) for item in value):
        errors.append(f"{path}:expected_numeric_vector_{length}")


def _validate_transform(value: Any, path: str, errors: list[str]) -> None:
    transform = _require_dict(value, path, errors)
    _validate_vector(transform.get("location"), 3, f"{path}.location", errors)
    _validate_vector(transform.get("rotation"), 3, f"{path}.rotation", errors)
    _validate_vector(transform.get("scale"), 3, f"{path}.scale", errors)


def _validate_unique_ids(items: list[Any], path: str, errors: list[str]) -> set[str]:
    result: set[str] = set()
    for index, raw in enumerate(items):
        item = _require_dict(raw, f"{path}[{index}]", errors)
        item_id = _validate_id(item.get("id"), f"{path}[{index}].id", errors)
        if item_id in result:
            errors.append(f"{path}[{index}].id:duplicate")
        if item_id:
            result.add(item_id)
    return result


def default_manifest(name: str = "Untitled Scene") -> dict[str, Any]:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip()).strip("-.") or "scene"
    if not slug[0].isalpha():
        slug = "scene-" + slug
    return {
        "schema_version": SCHEMA_VERSION,
        "project": {"id": slug[:128], "name": name, "seed": 1},
        "render": {
            "duration_seconds": 10.0,
            "fps": 30,
            "resolution": {"width": 1920, "height": 1080, "percentage": 100},
            "engine": "BLENDER_EEVEE_NEXT",
            "samples": 64,
            "transparent": False,
        },
        "assets": [],
        "scene": {
            "environment": {"color": [0.015, 0.02, 0.04, 1.0], "strength": 0.35},
            "materials": [],
            "objects": [],
            "cameras": [],
            "active_camera": None,
            "lights": [],
            "effects": [],
            "overlays": [],
        },
        "timeline": {"tracks": [], "markers": []},
        "audio": {"sample_rate": 48000, "tracks": []},
        "output": {
            "format": "mp4",
            "filename": f"{slug}.mp4",
            "video_codec": "libx264",
            "audio_codec": "aac",
            "quality": 18,
        },
        "metadata": {
            "application": "SBP Video Studio",
            "runtime_authority": RUNTIME_AUTHORITY,
            "canonical_runtime_mutation": False,
        },
    }


def validate_manifest(data: Mapping[str, Any]) -> list[str]:
    """Return all deterministic validation findings; an empty list means valid."""

    errors: list[str] = []
    if not isinstance(data, Mapping):
        return ["$:expected_object"]
    root = dict(data)
    if root.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version:unsupported")

    project = _require_dict(root.get("project"), "project", errors)
    _validate_id(project.get("id"), "project.id", errors)
    if not isinstance(project.get("name"), str) or not project.get("name", "").strip():
        errors.append("project.name:required_string")
    if not isinstance(project.get("seed"), int) or isinstance(project.get("seed"), bool):
        errors.append("project.seed:expected_integer")

    render = _require_dict(root.get("render"), "render", errors)
    duration = render.get("duration_seconds")
    if not _is_number(duration) or not 0 < float(duration) <= 86400:
        errors.append("render.duration_seconds:out_of_range")
        duration = 0
    fps = render.get("fps")
    if not isinstance(fps, int) or isinstance(fps, bool) or not 1 <= fps <= 240:
        errors.append("render.fps:out_of_range")
    resolution = _require_dict(render.get("resolution"), "render.resolution", errors)
    for key, maximum in (("width", 16384), ("height", 16384), ("percentage", 100)):
        value = resolution.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
            errors.append(f"render.resolution.{key}:out_of_range")
    if render.get("engine") not in BLENDER_ENGINES:
        errors.append("render.engine:unsupported")
    if not isinstance(render.get("samples"), int) or not 1 <= render.get("samples", 0) <= 65536:
        errors.append("render.samples:out_of_range")
    if not isinstance(render.get("transparent"), bool):
        errors.append("render.transparent:expected_boolean")

    assets = _require_list(root.get("assets"), "assets", errors)
    asset_ids = _validate_unique_ids(assets, "assets", errors)
    for index, raw in enumerate(assets):
        asset = raw if isinstance(raw, dict) else {}
        if asset.get("kind") not in ASSET_KINDS:
            errors.append(f"assets[{index}].kind:unsupported")
        uri = asset.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            errors.append(f"assets[{index}].uri:required_string")
        digest = asset.get("sha256")
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            errors.append(f"assets[{index}].sha256:invalid")

    scene = _require_dict(root.get("scene"), "scene", errors)
    environment = _require_dict(scene.get("environment"), "scene.environment", errors)
    _validate_vector(environment.get("color"), 4, "scene.environment.color", errors)
    if not _is_number(environment.get("strength")) or environment.get("strength", -1) < 0:
        errors.append("scene.environment.strength:out_of_range")

    materials = _require_list(scene.get("materials"), "scene.materials", errors)
    material_ids = _validate_unique_ids(materials, "scene.materials", errors)
    for index, raw in enumerate(materials):
        material = raw if isinstance(raw, dict) else {}
        shader = _require_dict(material.get("shader"), f"scene.materials[{index}].shader", errors)
        if shader.get("type") not in {"principled", "emission", "unlit"}:
            errors.append(f"scene.materials[{index}].shader.type:unsupported")
        if "base_color" in shader:
            _validate_vector(shader["base_color"], 4, f"scene.materials[{index}].shader.base_color", errors)

    objects = _require_list(scene.get("objects"), "scene.objects", errors)
    object_ids = _validate_unique_ids(objects, "scene.objects", errors)
    for index, raw in enumerate(objects):
        item = raw if isinstance(raw, dict) else {}
        object_type = item.get("type")
        if object_type not in OBJECT_TYPES:
            errors.append(f"scene.objects[{index}].type:unsupported")
        if object_type == "primitive" and item.get("primitive") not in PRIMITIVE_TYPES:
            errors.append(f"scene.objects[{index}].primitive:unsupported")
        if object_type == "mesh" and item.get("asset_id") not in asset_ids:
            errors.append(f"scene.objects[{index}].asset_id:unknown_asset")
        if object_type == "text" and not isinstance(item.get("text"), str):
            errors.append(f"scene.objects[{index}].text:required_string")
        _validate_transform(item.get("transform"), f"scene.objects[{index}].transform", errors)
        if item.get("material") is not None and item.get("material") not in material_ids:
            errors.append(f"scene.objects[{index}].material:unknown_material")

    graph = SceneGraph([item for item in objects if isinstance(item, dict)])
    errors.extend(graph.validation_errors())

    cameras = _require_list(scene.get("cameras"), "scene.cameras", errors)
    camera_ids = _validate_unique_ids(cameras, "scene.cameras", errors)
    for index, raw in enumerate(cameras):
        camera = raw if isinstance(raw, dict) else {}
        _validate_transform(camera.get("transform"), f"scene.cameras[{index}].transform", errors)
        if not _is_number(camera.get("focal_length")) or not 1 <= camera.get("focal_length", 0) <= 1000:
            errors.append(f"scene.cameras[{index}].focal_length:out_of_range")
        if camera.get("target") is not None and camera.get("target") not in object_ids:
            errors.append(f"scene.cameras[{index}].target:unknown_object")
    active_camera = scene.get("active_camera")
    if camera_ids and active_camera not in camera_ids:
        errors.append("scene.active_camera:unknown_camera")
    if not camera_ids and active_camera is not None:
        errors.append("scene.active_camera:must_be_null_without_cameras")

    lights = _require_list(scene.get("lights"), "scene.lights", errors)
    light_ids = _validate_unique_ids(lights, "scene.lights", errors)
    for index, raw in enumerate(lights):
        light = raw if isinstance(raw, dict) else {}
        if light.get("type") not in LIGHT_TYPES:
            errors.append(f"scene.lights[{index}].type:unsupported")
        _validate_transform(light.get("transform"), f"scene.lights[{index}].transform", errors)
        _validate_vector(light.get("color"), 3, f"scene.lights[{index}].color", errors)
        if not _is_number(light.get("energy")) or light.get("energy", -1) < 0:
            errors.append(f"scene.lights[{index}].energy:out_of_range")

    effects = _require_list(scene.get("effects"), "scene.effects", errors)
    effect_ids = _validate_unique_ids(effects, "scene.effects", errors)
    for index, raw in enumerate(effects):
        effect = raw if isinstance(raw, dict) else {}
        if effect.get("type") not in EFFECT_TYPES:
            errors.append(f"scene.effects[{index}].type:unsupported")
        if effect.get("emitter") is not None and effect.get("emitter") not in object_ids:
            errors.append(f"scene.effects[{index}].emitter:unknown_object")
        if effect.get("material") is not None and effect.get("material") not in material_ids:
            errors.append(f"scene.effects[{index}].material:unknown_material")
        if effect.get("type") == "particles":
            count = effect.get("count")
            if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10000:
                errors.append(f"scene.effects[{index}].count:out_of_range")
        for key in ("start", "end"):
            if key in effect and (not _is_number(effect[key]) or not 0 <= float(effect[key]) <= float(duration)):
                errors.append(f"scene.effects[{index}].{key}:out_of_range")
        if "start" in effect and "end" in effect and _is_number(effect["start"]) and _is_number(effect["end"]) and effect["end"] < effect["start"]:
            errors.append(f"scene.effects[{index}]:end_before_start")

    overlays = _require_list(scene.get("overlays"), "scene.overlays", errors)
    overlay_ids = _validate_unique_ids(overlays, "scene.overlays", errors)
    for index, raw in enumerate(overlays):
        overlay = raw if isinstance(raw, dict) else {}
        if overlay.get("type") not in OVERLAY_TYPES:
            errors.append(f"scene.overlays[{index}].type:unsupported")
        if not isinstance(overlay.get("content"), str):
            errors.append(f"scene.overlays[{index}].content:required_string")
        _validate_vector(overlay.get("position"), 2, f"scene.overlays[{index}].position", errors)

    timeline = _require_dict(root.get("timeline"), "timeline", errors)
    tracks = _require_list(timeline.get("tracks"), "timeline.tracks", errors)
    _validate_unique_ids(tracks, "timeline.tracks", errors)
    target_ids = {
        "object": object_ids,
        "camera": camera_ids,
        "light": light_ids,
        "material": material_ids,
        "effect": effect_ids,
        "overlay": overlay_ids,
    }
    for index, raw in enumerate(tracks):
        track = raw if isinstance(raw, dict) else {}
        target = track.get("target")
        if target == "environment":
            pass
        elif not isinstance(target, str) or ":" not in target:
            errors.append(f"timeline.tracks[{index}].target:invalid")
        else:
            target_type, target_id = target.split(":", 1)
            if target_type not in target_ids or target_id not in target_ids[target_type]:
                errors.append(f"timeline.tracks[{index}].target:unknown")
        if not isinstance(track.get("property"), str) or not track.get("property"):
            errors.append(f"timeline.tracks[{index}].property:required_string")
        keyframes = _require_list(track.get("keyframes"), f"timeline.tracks[{index}].keyframes", errors)
        previous = -1.0
        for key_index, keyframe_raw in enumerate(keyframes):
            keyframe = _require_dict(keyframe_raw, f"timeline.tracks[{index}].keyframes[{key_index}]", errors)
            time = keyframe.get("time")
            if not _is_number(time) or not 0 <= float(time) <= float(duration):
                errors.append(f"timeline.tracks[{index}].keyframes[{key_index}].time:out_of_range")
            elif float(time) < previous:
                errors.append(f"timeline.tracks[{index}].keyframes:non_monotonic")
            else:
                previous = float(time)
            if "value" not in keyframe:
                errors.append(f"timeline.tracks[{index}].keyframes[{key_index}].value:required")
            if keyframe.get("interpolation", "BEZIER") not in {"CONSTANT", "LINEAR", "BEZIER"}:
                errors.append(f"timeline.tracks[{index}].keyframes[{key_index}].interpolation:unsupported")
    markers = _require_list(timeline.get("markers"), "timeline.markers", errors)
    for index, raw in enumerate(markers):
        marker = _require_dict(raw, f"timeline.markers[{index}]", errors)
        if not isinstance(marker.get("label"), str) or not marker.get("label"):
            errors.append(f"timeline.markers[{index}].label:required_string")
        if not _is_number(marker.get("time")) or not 0 <= float(marker.get("time", -1)) <= float(duration):
            errors.append(f"timeline.markers[{index}].time:out_of_range")

    audio = _require_dict(root.get("audio"), "audio", errors)
    if audio.get("sample_rate") not in {22050, 32000, 44100, 48000, 88200, 96000}:
        errors.append("audio.sample_rate:unsupported")
    audio_tracks = _require_list(audio.get("tracks"), "audio.tracks", errors)
    _validate_unique_ids(audio_tracks, "audio.tracks", errors)
    for index, raw in enumerate(audio_tracks):
        track = raw if isinstance(raw, dict) else {}
        if track.get("asset_id") not in asset_ids:
            errors.append(f"audio.tracks[{index}].asset_id:unknown_asset")
        if not _is_number(track.get("start")) or not 0 <= float(track.get("start", -1)) <= float(duration):
            errors.append(f"audio.tracks[{index}].start:out_of_range")
        if not _is_number(track.get("gain_db", 0)):
            errors.append(f"audio.tracks[{index}].gain_db:expected_number")

    output = _require_dict(root.get("output"), "output", errors)
    if output.get("format") not in OUTPUT_FORMATS:
        errors.append("output.format:unsupported")
    if not isinstance(output.get("filename"), str) or not output.get("filename"):
        errors.append("output.filename:required_string")
    elif (
        Path(output["filename"]).name != output["filename"]
        or "/" in output["filename"]
        or "\\" in output["filename"]
        or output["filename"] in {".", ".."}
    ):
        errors.append("output.filename:must_be_portable_basename")
    for key in ("video_codec", "audio_codec"):
        if not isinstance(output.get(key), str) or not output.get(key):
            errors.append(f"output.{key}:required_string")
    if not isinstance(output.get("quality"), int) or not 0 <= output.get("quality", -1) <= 51:
        errors.append("output.quality:out_of_range")

    metadata = _require_dict(root.get("metadata"), "metadata", errors)
    if metadata.get("runtime_authority") != RUNTIME_AUTHORITY:
        errors.append("metadata.runtime_authority:must_be_NONE")
    if metadata.get("canonical_runtime_mutation") is not False:
        errors.append("metadata.canonical_runtime_mutation:must_be_false")
    return list(dict.fromkeys(errors))


@dataclass(frozen=True)
class SceneManifest:
    _data: dict[str, Any]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SceneManifest":
        copied = deepcopy(dict(data))
        errors = validate_manifest(copied)
        if errors:
            raise ManifestValidationError(errors)
        return cls(copied)

    @classmethod
    def load(cls, path: str | Path) -> "SceneManifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @property
    def digest(self) -> str:
        return canonical_digest(self._data)

    def to_dict(self) -> dict[str, Any]:
        return deepcopy(self._data)

    def to_canonical_json(self) -> str:
        return canonical_json(self._data)

    def save(self, path: str | Path, *, pretty: bool = True) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if pretty:
            content = json.dumps(self._data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        else:
            content = self.to_canonical_json() + "\n"
        target.write_text(content, encoding="utf-8")
        return target
