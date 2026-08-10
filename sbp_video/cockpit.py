from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from sbp_video.canonical import canonical_digest
from sbp_video.editor import ProjectEditor
from sbp_video.manifest import SceneManifest


class PresentationLayer(str, Enum):
    REHEARSAL = "rehearsal"
    FULL_SPEED = "full-speed"
    CONSTRUCTED_SCENARIO = "constructed-scenario"


@dataclass(frozen=True)
class LayerProfile:
    layer: PresentationLayer
    label: str
    audiences: tuple[str, ...]
    speed_factor: float
    purpose: str


LAYER_PROFILES = {
    PresentationLayer.REHEARSAL: LayerProfile(
        PresentationLayer.REHEARSAL,
        "Slower rehearsal / learning traversal",
        ("assessors", "operators", "regulators", "deployment enterprise"),
        0.25,
        "Examine and learn each recorded traversal stage at a deliberately slowed pace.",
    ),
    PresentationLayer.FULL_SPEED: LayerProfile(
        PresentationLayer.FULL_SPEED,
        "Full-speed traversal",
        ("operators", "assessors", "deployment enterprise"),
        1.0,
        "Present the recorded traversal at its actual timing when timing data is available.",
    ),
    PresentationLayer.CONSTRUCTED_SCENARIO: LayerProfile(
        PresentationLayer.CONSTRUCTED_SCENARIO,
        "Constructed scenario",
        ("assessors", "regulators", "insurers", "deployment enterprise"),
        1.0,
        "Visualize an explicitly constructed, non-authoritative scenario.",
    ),
}


def _stage_label(item: Any, index: int) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, Mapping):
        for key in ("label", "name", "stage", "event", "component", "phase", "id"):
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
    return f"Stage {index + 1}"


def _stage_status(item: Any) -> str:
    if isinstance(item, Mapping):
        for key in ("status", "outcome", "result", "state"):
            value = item.get(key)
            if isinstance(value, str):
                return value
    return "observed"


def _extract_stages(snapshot: Mapping[str, Any]) -> list[Any]:
    containers: list[Mapping[str, Any]] = [snapshot]
    state = snapshot.get("state")
    if isinstance(state, Mapping):
        containers.append(state)
    for container in containers:
        for key in (
            "traversal_stages",
            "pipeline_trace",
            "stage_trace",
            "pipeline_a_timeline",
            "events",
            "stages",
            "chronology",
        ):
            value = container.get(key)
            if isinstance(value, list) and value:
                return deepcopy(value)
        order = container.get("pipeline_order")
        if isinstance(order, list) and order:
            return deepcopy(order)
        summary = container.get("last_state_summary")
        if isinstance(summary, Mapping):
            return [
                {"name": str(key).replace("_", " ").title(), "status": value}
                for key, value in summary.items()
            ]
    preferred = (
        "ingress",
        "classification",
        "authority",
        "evidence",
        "convergence",
        "admissibility",
        "audit",
        "replay",
    )
    fallback = [{"name": key, "status": "observed"} for key in preferred if key in snapshot]
    return fallback or [{"name": "Snapshot received", "status": "observed"}]


def _constructed_stages(scenario: Mapping[str, Any]) -> list[Any]:
    for key in ("stages", "events", "steps"):
        value = scenario.get(key)
        if isinstance(value, list) and value:
            return deepcopy(value)
    return [{"name": "Constructed scenario", "status": "hypothetical"}]


def _stage_times(stages: list[Any], layer: PresentationLayer) -> list[float]:
    if layer == PresentationLayer.REHEARSAL:
        return [1.0 + index * 3.0 for index in range(len(stages))]
    if layer == PresentationLayer.FULL_SPEED:
        elapsed = []
        for item in stages:
            value = item.get("elapsed_ms") if isinstance(item, Mapping) else None
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                elapsed = []
                break
            elapsed.append(max(0.0, float(value) / 1000.0))
        if elapsed and any(elapsed):
            start = elapsed[0]
            result: list[float] = []
            previous = 0.0
            for value in elapsed:
                previous = max(previous, value - start, 0.0)
                result.append(0.25 + previous)
            return result
        return [0.25 + index * 0.65 for index in range(len(stages))]
    result: list[float] = []
    cursor = 0.75
    for item in stages:
        result.append(cursor)
        duration = item.get("duration_seconds", 2.0) if isinstance(item, Mapping) else 2.0
        cursor += max(0.25, float(duration)) if isinstance(duration, (int, float)) else 2.0
    return result


class CockpitVisualizationAdapter:
    """Transform detached JSON snapshots into scenes without importing runtime code."""

    def build_scene(
        self,
        snapshot: Mapping[str, Any],
        *,
        layer: PresentationLayer | str,
        scenario: Mapping[str, Any] | None = None,
    ) -> SceneManifest:
        presentation_layer = PresentationLayer(layer)
        profile = LAYER_PROFILES[presentation_layer]
        snapshot_copy = deepcopy(dict(snapshot))
        source_digest = canonical_digest(snapshot_copy)
        if presentation_layer == PresentationLayer.CONSTRUCTED_SCENARIO:
            scenario_copy = deepcopy(dict(scenario or {}))
            stages = _constructed_stages(scenario_copy)
            project_name = str(scenario_copy.get("title", "Constructed SBP-LEX scenario"))
        else:
            stages = _extract_stages(snapshot_copy)
            project_name = f"SBP-LEX Cockpit — {profile.label}"
        times = _stage_times(stages, presentation_layer)
        duration = max(4.0, (times[-1] if times else 0.0) + (3.0 if presentation_layer == PresentationLayer.REHEARSAL else 1.5))

        editor = ProjectEditor.new(project_name, duration_seconds=duration, fps=30, width=1920, height=1080)
        editor.set_environment(color=[0.004, 0.009, 0.025, 1.0], strength=0.18)
        editor.add_material("floor", base_color=[0.015, 0.025, 0.055, 1], metallic=0.7, roughness=0.25)
        editor.add_material("observed", base_color=[0.04, 0.3, 0.72, 1], metallic=0.6, roughness=0.2, emission_color=[0.0, 0.15, 0.8, 1], emission_strength=2.0)
        editor.add_material("positive", base_color=[0.02, 0.55, 0.35, 1], metallic=0.5, roughness=0.25, emission_color=[0.0, 0.8, 0.35, 1], emission_strength=2.0)
        editor.add_material("attention", base_color=[0.75, 0.22, 0.04, 1], metallic=0.45, roughness=0.3, emission_color=[1.0, 0.15, 0.0, 1], emission_strength=1.5)
        center = max(0.0, (len(stages) - 1) * 2.4 / 2)
        editor.add_object("traversal-center", object_type="empty", location=[center, 0, 0.8])
        editor.add_object("cockpit-floor", primitive="plane", material="floor", location=[center, 0, -0.45], scale=[max(3.0, len(stages) * 1.6), 3.0, 1.0])

        for index, item in enumerate(stages):
            status = _stage_status(item).lower()
            material = "positive" if any(word in status for word in ("pass", "ok", "complete", "match")) else "attention" if any(word in status for word in ("warn", "fail", "deny", "error")) else "observed"
            node_id = f"stage-{index + 1:02d}"
            x = index * 2.4
            editor.add_object(node_id, primitive="cube", material=material, location=[x, 0, 0.5], scale=[0.75, 0.75, 0.75])
            editor.add_object(
                f"label-{index + 1:02d}",
                object_type="text",
                text=_stage_label(item, index),
                material=material,
                location=[x, -0.9, 0.2],
                rotation=[70, 0, 0],
                scale=[0.35, 0.35, 0.35],
                extrude=0.01,
            )
            editor.add_effect(
                f"pulse-{index + 1:02d}",
                effect_type="particles",
                emitter=node_id,
                material=material,
                count=8,
                seed=index + 100,
                start=times[index],
                end=min(duration, times[index] + 1.5),
                lifetime=1.2,
                speed=0.45,
                spread=0.55,
                size=0.025,
            )
            editor.add_track(
                f"reveal-{index + 1:02d}",
                target=f"object:{node_id}",
                property_name="scale",
                keyframes=[
                    {"time": max(0, times[index] - 0.2), "value": [0.15, 0.15, 0.15], "interpolation": "LINEAR"},
                    {"time": times[index], "value": [0.75, 0.75, 0.75], "interpolation": "BEZIER"},
                ],
            )
            if index:
                editor.add_object(
                    f"link-{index:02d}",
                    object_type="curve",
                    material="observed",
                    points=[[(index - 1) * 2.4, 0, 0.5], [x, 0, 0.5]],
                    bevel_depth=0.035,
                )

        camera_start = [-3.5, -8.0, 4.0]
        editor.add_camera("cockpit-camera", location=camera_start, focal_length=48, target="traversal-center", active=True)
        editor.add_light("key", light_type="area", location=[center, -3.5, 6], rotation=[25, 0, 0], color=[0.55, 0.72, 1.0], energy=1300, size=7)
        editor.add_light("rim", light_type="area", location=[center, 3.0, 3.5], rotation=[-55, 0, 180], color=[0.1, 0.6, 1.0], energy=900, size=5)
        camera_keys = [{"time": 0.0, "value": camera_start, "interpolation": "BEZIER"}]
        for index, time in enumerate(times):
            camera_keys.append({"time": time, "value": [index * 2.4 - 2.0, -7.0, 3.2], "interpolation": "BEZIER"})
            editor.add_marker(_stage_label(stages[index], index), time)
        editor.add_track("camera-traversal", target="camera:cockpit-camera", property_name="location", keyframes=camera_keys)
        editor.add_overlay("layer", content=profile.label, overlay_type="hud", position=[0.04, 0.93], font_size=0.36)
        editor.add_overlay("audience", content="For: " + ", ".join(profile.audiences), overlay_type="text", position=[0.04, 0.86], font_size=0.22)
        if presentation_layer == PresentationLayer.CONSTRUCTED_SCENARIO:
            editor.add_overlay("scenario-notice", content="CONSTRUCTED SCENARIO — NOT A RUNTIME DECISION", overlay_type="hud", position=[0.04, 0.08], font_size=0.2)
        data = editor.snapshot()
        data["metadata"].update({
            "integration": "sbp-lex-cockpit-snapshot/v1",
            "integration_access": "read_only",
            "source_snapshot_digest": source_digest,
            "presentation_layer": presentation_layer.value,
            "presentation_speed_factor": profile.speed_factor,
            "audiences": list(profile.audiences),
            "governance_decisions": False,
            "execution_authorization": False,
        })
        if canonical_digest(snapshot_copy) != source_digest or dict(snapshot) != snapshot_copy:
            raise RuntimeError("cockpit source snapshot changed during adaptation")
        return SceneManifest.from_dict(data)
