from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbp_video.errors import ManifestValidationError
from sbp_video.manifest import SceneManifest, default_manifest, validate_manifest
from sbp_video.samples import architecture_scene, general_scene
from sbp_video.scene_graph import SceneGraph


def test_general_sample_scenes_are_valid_and_deterministic() -> None:
    for manifest in (general_scene(), architecture_scene()):
        assert validate_manifest(manifest.to_dict()) == []
        assert len(manifest.digest) == 64
        rebuilt = SceneManifest.from_dict(json.loads(manifest.to_canonical_json()))
        assert rebuilt.digest == manifest.digest


def test_manifest_digest_is_independent_of_mapping_order() -> None:
    data = default_manifest("Digest Test")
    reordered = {key: data[key] for key in reversed(list(data))}
    assert SceneManifest.from_dict(data).digest == SceneManifest.from_dict(reordered).digest


def test_duplicate_and_cyclic_scene_nodes_are_rejected() -> None:
    data = default_manifest("Broken Graph")
    base_transform = {"location": [0, 0, 0], "rotation": [0, 0, 0], "scale": [1, 1, 1]}
    data["scene"]["objects"] = [
        {"id": "alpha", "type": "empty", "transform": base_transform, "parent": "beta"},
        {"id": "beta", "type": "empty", "transform": base_transform, "parent": "alpha"},
        {"id": "beta", "type": "empty", "transform": base_transform},
    ]
    errors = validate_manifest(data)
    assert any("duplicate" in error or "duplicate_id" in error for error in errors)
    assert any("cycle" in error for error in errors)
    with pytest.raises(ManifestValidationError):
        SceneManifest.from_dict(data)


def test_scene_graph_orders_parents_before_children_and_composes_channels() -> None:
    graph = SceneGraph([
        {"id": "child", "parent": "root", "transform": {"location": [1, 2, 3], "rotation": [0, 5, 0], "scale": [2, 2, 2]}},
        {"id": "root", "transform": {"location": [5, 0, 0], "rotation": [0, 0, 10], "scale": [0.5, 1, 1]}},
    ])
    assert [node.node_id for node in graph.topological_order()] == ["root", "child"]
    assert graph.world_transform("child") == {
        "location": [6.0, 2.0, 3.0],
        "rotation": [0.0, 5.0, 10.0],
        "scale": [1.0, 2.0, 2.0],
    }


def test_saved_manifest_round_trip(tmp_path: Path) -> None:
    manifest = general_scene()
    path = manifest.save(tmp_path / "project.scene.json")
    assert SceneManifest.load(path).digest == manifest.digest


def test_scene_manifest_returns_defensive_copies() -> None:
    manifest = general_scene()
    first = manifest.to_dict()
    second = manifest.to_dict()
    first["project"]["name"] = "changed"
    assert second["project"]["name"] != "changed"


def test_output_filename_cannot_escape_build_directory() -> None:
    data = default_manifest("Portable Output")
    data["output"]["filename"] = "../outside.mp4"
    assert "output.filename:must_be_portable_basename" in validate_manifest(data)
