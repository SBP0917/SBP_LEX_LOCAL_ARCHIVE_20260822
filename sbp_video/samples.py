from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sbp_video.cockpit import CockpitVisualizationAdapter, PresentationLayer
from sbp_video.editor import ProjectEditor
from sbp_video.manifest import SceneManifest


def general_scene() -> SceneManifest:
    editor = ProjectEditor.new("Arbitrary Scene — Orbital Product Reveal", duration_seconds=8.0, fps=30, width=1280, height=720)
    editor.set_environment(color=[0.002, 0.004, 0.015, 1.0], strength=0.12)
    editor.add_material("stage", base_color=[0.025, 0.035, 0.08, 1], metallic=0.8, roughness=0.2)
    editor.add_material("core", base_color=[0.015, 0.28, 0.65, 1], metallic=0.65, roughness=0.15, emission_color=[0.0, 0.35, 1.0, 1], emission_strength=3.0)
    editor.add_material("accent", shader_type="emission", base_color=[0.15, 0.85, 1.0, 1], emission_strength=5.0)
    editor.add_object("focus", object_type="empty", location=[0, 0, 0.8])
    editor.add_object("stage", primitive="cylinder", material="stage", location=[0, 0, -0.45], scale=[3.5, 3.5, 0.35])
    editor.add_object("core", primitive="sphere", material="core", location=[0, 0, 0.8], scale=[1.15, 1.15, 1.15])
    editor.add_object("ring-a", primitive="torus", material="accent", parent="core", rotation=[65, 0, 20], scale=[1.5, 1.5, 1.5])
    editor.add_object("ring-b", primitive="torus", material="accent", parent="core", rotation=[0, 70, -15], scale=[1.8, 1.8, 1.8])
    editor.add_object("title", object_type="text", text="CONSTRUCT ANY SCENE", material="accent", location=[0, 0.8, 3.0], scale=[0.65, 0.65, 0.65], extrude=0.025)
    editor.add_camera("hero-camera", location=[7.5, -9.0, 5.5], focal_length=52, target="focus", active=True)
    editor.add_light("key", light_type="area", location=[-4, -4, 7], rotation=[30, 0, -25], color=[0.45, 0.7, 1.0], energy=1500, size=6)
    editor.add_light("warm-rim", light_type="area", location=[4, 2, 4], rotation=[-40, 0, 150], color=[1.0, 0.3, 0.08], energy=1100, size=4)
    editor.add_effect("energy-particles", effect_type="particles", emitter="core", material="accent", count=48, seed=917, start=0.5, end=7.5, lifetime=2.5, speed=0.75, spread=1.5, size=0.025)
    editor.add_track("core-spin", target="object:core", property_name="rotation", keyframes=[
        {"time": 0, "value": [0, 0, 0], "interpolation": "LINEAR"},
        {"time": 8, "value": [20, 35, 360], "interpolation": "LINEAR"},
    ])
    editor.add_track("camera-arc", target="camera:hero-camera", property_name="location", keyframes=[
        {"time": 0, "value": [7.5, -9.0, 5.5], "interpolation": "BEZIER"},
        {"time": 4, "value": [0.0, -10.5, 3.5], "interpolation": "BEZIER"},
        {"time": 8, "value": [-6.5, -8.0, 4.5], "interpolation": "BEZIER"},
    ])
    editor.add_track("title-reveal", target="object:title", property_name="scale", keyframes=[
        {"time": 0, "value": [0, 0, 0], "interpolation": "CONSTANT"},
        {"time": 1.2, "value": [0, 0, 0], "interpolation": "LINEAR"},
        {"time": 2.0, "value": [0.65, 0.65, 0.65], "interpolation": "BEZIER"},
    ])
    editor.add_overlay("caption", content="SBP VIDEO STUDIO  /  LOCAL-FIRST", overlay_type="hud", position=[0.04, 0.93], font_size=0.24)
    editor.add_overlay("data", content="3D • VFX • TIMELINE • AUDIO • EXPORT", overlay_type="data", position=[0.04, 0.08], font_size=0.18)
    editor.add_marker("Reveal", 2.0).add_marker("Orbit apex", 4.0).add_marker("Final frame", 8.0)
    return editor.manifest()


def architecture_scene() -> SceneManifest:
    editor = ProjectEditor.new("Arbitrary Scene — Modular Architecture", duration_seconds=6.0, fps=24, width=1280, height=720)
    editor.set_environment(color=[0.008, 0.012, 0.025, 1], strength=0.25)
    editor.add_material("block", base_color=[0.05, 0.28, 0.52, 1], metallic=0.4, roughness=0.3, emission_color=[0.0, 0.15, 0.5, 1], emission_strength=1.2)
    editor.add_material("line", shader_type="emission", base_color=[0.1, 0.9, 0.8, 1], emission_strength=3)
    editor.add_object("center", object_type="empty", location=[0, 0, 0.5])
    labels = ("SCENE", "CAMERA", "LIGHT", "VFX", "AUDIO")
    for index, label in enumerate(labels):
        x = (index - 2) * 2.1
        editor.add_object(f"block-{index}", primitive="cube", material="block", location=[x, 0, 0.5], scale=[0.75, 0.75, 0.75])
        editor.add_object(f"text-{index}", object_type="text", text=label, material="line", location=[x, -0.85, 0.1], rotation=[70, 0, 0], scale=[0.25, 0.25, 0.25])
        editor.add_track(f"rise-{index}", target=f"object:block-{index}", property_name="location", keyframes=[
            {"time": index * 0.5, "value": [x, 0, -1], "interpolation": "CONSTANT"},
            {"time": 1 + index * 0.5, "value": [x, 0, 0.5], "interpolation": "BEZIER"},
        ])
    editor.add_camera("camera", location=[0, -12, 6], focal_length=55, target="center", active=True)
    editor.add_light("key", light_type="area", location=[0, -4, 7], rotation=[30, 0, 0], color=[0.6, 0.8, 1], energy=1800, size=8)
    editor.add_overlay("title", content="ONE MANIFEST. ARBITRARY CONSTRUCTION.", overlay_type="hud", position=[0.05, 0.92], font_size=0.28)
    return editor.manifest()


def render_smoke_scene() -> SceneManifest:
    """Small deterministic scene used for a real Blender/FFmpeg installation check."""

    editor = ProjectEditor.new(
        "Video Studio Render Smoke",
        duration_seconds=0.5,
        fps=12,
        width=320,
        height=180,
    )
    editor.set_environment(color=[0.005, 0.01, 0.03, 1.0], strength=0.3)
    editor.add_material(
        "smoke-blue",
        base_color=[0.02, 0.25, 0.8, 1.0],
        metallic=0.45,
        roughness=0.22,
        emission_color=[0.0, 0.12, 0.8, 1.0],
        emission_strength=1.2,
    )
    editor.add_object("target", object_type="empty", location=[0, 0, 0])
    editor.add_object("smoke-cube", primitive="cube", material="smoke-blue")
    editor.add_camera("smoke-camera", location=[3.2, -4.0, 2.4], focal_length=50, target="target", active=True)
    editor.add_light("smoke-key", light_type="area", location=[-2, -2, 4], energy=700, size=4)
    editor.add_track(
        "smoke-spin",
        target="object:smoke-cube",
        property_name="rotation",
        keyframes=[
            {"time": 0.0, "value": [0, 0, 0], "interpolation": "LINEAR"},
            {"time": 0.5, "value": [20, 35, 90], "interpolation": "LINEAR"},
        ],
    )
    editor.add_overlay("smoke-label", content="SBP VIDEO STUDIO", overlay_type="hud", position=[0.04, 0.9], font_size=0.16)
    return editor.manifest()


def sample_snapshot() -> dict[str, Any]:
    return {
        "snapshot_type": "detached_observability_export",
        "traversal_stages": [
            {"name": "Ingress", "status": "complete", "elapsed_ms": 0},
            {"name": "Evidence and authority", "status": "complete", "elapsed_ms": 140},
            {"name": "Dual pipeline convergence", "status": "matched", "elapsed_ms": 310},
            {"name": "Admissibility observation", "status": "observed", "elapsed_ms": 460},
            {"name": "Audit continuity", "status": "complete", "elapsed_ms": 610},
        ],
    }


def write_samples(output_directory: str | Path) -> dict[str, str]:
    target = Path(output_directory)
    target.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    for name, manifest in (
        ("general-orbital", general_scene()),
        ("general-architecture", architecture_scene()),
        ("render-smoke", render_smoke_scene()),
    ):
        path = manifest.save(target / f"{name}.scene.json")
        files[name] = str(path)
    snapshot = sample_snapshot()
    scenario = {
        "title": "Constructed insured deployment scenario",
        "stages": [
            {"name": "Simulated deployment entry", "status": "hypothetical", "duration_seconds": 2.5},
            {"name": "Constructed environmental change", "status": "hypothetical", "duration_seconds": 3.0},
            {"name": "Assessor review point", "status": "review", "duration_seconds": 2.0},
            {"name": "Insurer exposure review", "status": "review", "duration_seconds": 2.0},
        ],
    }
    adapter = CockpitVisualizationAdapter()
    for layer in PresentationLayer:
        manifest = adapter.build_scene(snapshot, layer=layer, scenario=scenario if layer == PresentationLayer.CONSTRUCTED_SCENARIO else None)
        path = manifest.save(target / f"cockpit-{layer.value}.scene.json")
        files[f"cockpit-{layer.value}"] = str(path)
    snapshot_path = target / "cockpit-read-only-snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files["cockpit-snapshot"] = str(snapshot_path)
    return files
