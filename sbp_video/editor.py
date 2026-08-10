from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sbp_video.assets import AssetRecord
from sbp_video.errors import ManifestValidationError
from sbp_video.manifest import SceneManifest, default_manifest, validate_manifest


def transform(
    location: list[float] | None = None,
    rotation: list[float] | None = None,
    scale: list[float] | None = None,
) -> dict[str, list[float]]:
    return {
        "location": list(location or [0.0, 0.0, 0.0]),
        "rotation": list(rotation or [0.0, 0.0, 0.0]),
        "scale": list(scale or [1.0, 1.0, 1.0]),
    }


@dataclass(frozen=True)
class EditRecord:
    revision: int
    action: str
    subject_id: str | None


class ProjectEditor:
    """In-memory standalone project/scene editor model with explicit saves."""

    def __init__(self, data: Mapping[str, Any]) -> None:
        self._data = deepcopy(dict(data))
        self._revision = 0
        self._history: list[EditRecord] = []

    @classmethod
    def new(
        cls,
        name: str = "Untitled Scene",
        *,
        duration_seconds: float = 10.0,
        fps: int = 30,
        width: int = 1920,
        height: int = 1080,
    ) -> "ProjectEditor":
        data = default_manifest(name)
        data["render"]["duration_seconds"] = duration_seconds
        data["render"]["fps"] = fps
        data["render"]["resolution"].update({"width": width, "height": height})
        return cls(data)

    @classmethod
    def load(cls, path: str | Path) -> "ProjectEditor":
        return cls(SceneManifest.load(path).to_dict())

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def history(self) -> tuple[EditRecord, ...]:
        return tuple(self._history)

    def _changed(self, action: str, subject_id: str | None = None) -> None:
        self._revision += 1
        self._history.append(EditRecord(self._revision, action, subject_id))

    def snapshot(self) -> dict[str, Any]:
        return deepcopy(self._data)

    def manifest(self) -> SceneManifest:
        return SceneManifest.from_dict(self._data)

    def validate(self) -> list[str]:
        return validate_manifest(self._data)

    def save(self, path: str | Path, *, pretty: bool = True) -> Path:
        return self.manifest().save(path, pretty=pretty)

    def set_render(self, **settings: Any) -> "ProjectEditor":
        allowed = {"duration_seconds", "fps", "engine", "samples", "transparent"}
        unknown = set(settings) - allowed
        if unknown:
            raise ValueError(f"unknown render settings: {sorted(unknown)}")
        self._data["render"].update(deepcopy(settings))
        self._changed("set_render")
        return self

    def set_resolution(self, width: int, height: int, percentage: int = 100) -> "ProjectEditor":
        self._data["render"]["resolution"] = {
            "width": width,
            "height": height,
            "percentage": percentage,
        }
        self._changed("set_resolution")
        return self

    def set_environment(self, *, color: list[float], strength: float = 1.0, **settings: Any) -> "ProjectEditor":
        self._data["scene"]["environment"] = {
            "color": list(color),
            "strength": strength,
            **deepcopy(settings),
        }
        self._changed("set_environment")
        return self

    def add_asset(self, record: AssetRecord | Mapping[str, Any]) -> "ProjectEditor":
        entry = record.to_manifest_entry() if isinstance(record, AssetRecord) else deepcopy(dict(record))
        self._data["assets"].append(entry)
        self._changed("add_asset", str(entry.get("id")))
        return self

    def add_material(
        self,
        material_id: str,
        *,
        shader_type: str = "principled",
        base_color: list[float] | None = None,
        metallic: float = 0.0,
        roughness: float = 0.5,
        emission_color: list[float] | None = None,
        emission_strength: float = 0.0,
    ) -> "ProjectEditor":
        shader: dict[str, Any] = {
            "type": shader_type,
            "base_color": list(base_color or [0.8, 0.8, 0.8, 1.0]),
            "metallic": metallic,
            "roughness": roughness,
        }
        if emission_color is not None:
            shader["emission_color"] = list(emission_color)
            shader["emission_strength"] = emission_strength
        self._data["scene"]["materials"].append({"id": material_id, "shader": shader})
        self._changed("add_material", material_id)
        return self

    def add_object(
        self,
        object_id: str,
        *,
        object_type: str = "primitive",
        primitive: str | None = "cube",
        asset_id: str | None = None,
        text: str | None = None,
        material: str | None = None,
        parent: str | None = None,
        location: list[float] | None = None,
        rotation: list[float] | None = None,
        scale: list[float] | None = None,
        **settings: Any,
    ) -> "ProjectEditor":
        item: dict[str, Any] = {
            "id": object_id,
            "type": object_type,
            "transform": transform(location, rotation, scale),
            **deepcopy(settings),
        }
        if object_type == "primitive":
            item["primitive"] = primitive
        if asset_id is not None:
            item["asset_id"] = asset_id
        if text is not None:
            item["text"] = text
        if material is not None:
            item["material"] = material
        if parent is not None:
            item["parent"] = parent
        self._data["scene"]["objects"].append(item)
        self._changed("add_object", object_id)
        return self

    def add_camera(
        self,
        camera_id: str,
        *,
        location: list[float],
        rotation: list[float] | None = None,
        focal_length: float = 50.0,
        target: str | None = None,
        active: bool = False,
    ) -> "ProjectEditor":
        camera: dict[str, Any] = {
            "id": camera_id,
            "transform": transform(location, rotation),
            "focal_length": focal_length,
        }
        if target is not None:
            camera["target"] = target
        self._data["scene"]["cameras"].append(camera)
        if active or self._data["scene"]["active_camera"] is None:
            self._data["scene"]["active_camera"] = camera_id
        self._changed("add_camera", camera_id)
        return self

    def add_light(
        self,
        light_id: str,
        *,
        light_type: str = "area",
        location: list[float],
        rotation: list[float] | None = None,
        color: list[float] | None = None,
        energy: float = 1000.0,
        size: float = 5.0,
    ) -> "ProjectEditor":
        self._data["scene"]["lights"].append({
            "id": light_id,
            "type": light_type,
            "transform": transform(location, rotation),
            "color": list(color or [1.0, 1.0, 1.0]),
            "energy": energy,
            "size": size,
        })
        self._changed("add_light", light_id)
        return self

    def add_effect(self, effect_id: str, *, effect_type: str, **settings: Any) -> "ProjectEditor":
        self._data["scene"]["effects"].append({
            "id": effect_id,
            "type": effect_type,
            **deepcopy(settings),
        })
        self._changed("add_effect", effect_id)
        return self

    def add_overlay(
        self,
        overlay_id: str,
        *,
        content: str,
        overlay_type: str = "text",
        position: list[float] | None = None,
        **settings: Any,
    ) -> "ProjectEditor":
        self._data["scene"]["overlays"].append({
            "id": overlay_id,
            "type": overlay_type,
            "content": content,
            "position": list(position or [0.05, 0.9]),
            **deepcopy(settings),
        })
        self._changed("add_overlay", overlay_id)
        return self

    def add_track(
        self,
        track_id: str,
        *,
        target: str,
        property_name: str,
        keyframes: list[dict[str, Any]],
    ) -> "ProjectEditor":
        self._data["timeline"]["tracks"].append({
            "id": track_id,
            "target": target,
            "property": property_name,
            "keyframes": deepcopy(keyframes),
        })
        self._changed("add_track", track_id)
        return self

    def add_marker(self, label: str, time: float) -> "ProjectEditor":
        self._data["timeline"]["markers"].append({"label": label, "time": time})
        self._changed("add_marker", label)
        return self

    def add_audio_track(
        self,
        track_id: str,
        *,
        asset_id: str,
        start: float = 0.0,
        gain_db: float = 0.0,
        loop: bool = False,
    ) -> "ProjectEditor":
        self._data["audio"]["tracks"].append({
            "id": track_id,
            "asset_id": asset_id,
            "start": start,
            "gain_db": gain_db,
            "loop": loop,
        })
        self._changed("add_audio_track", track_id)
        return self

    def set_output(self, **settings: Any) -> "ProjectEditor":
        self._data["output"].update(deepcopy(settings))
        self._changed("set_output")
        return self

    def require_valid(self) -> "ProjectEditor":
        errors = self.validate()
        if errors:
            raise ManifestValidationError(errors)
        return self
