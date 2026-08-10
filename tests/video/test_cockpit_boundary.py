from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from sbp_video.boundary import run_boundary_check
from sbp_video.cockpit import CockpitVisualizationAdapter, LAYER_PROFILES, PresentationLayer
from sbp_video.samples import sample_snapshot


def test_cockpit_adapter_preserves_all_three_requested_layers() -> None:
    assert set(LAYER_PROFILES) == {
        PresentationLayer.REHEARSAL,
        PresentationLayer.FULL_SPEED,
        PresentationLayer.CONSTRUCTED_SCENARIO,
    }
    assert LAYER_PROFILES[PresentationLayer.REHEARSAL].speed_factor < 1.0
    assert LAYER_PROFILES[PresentationLayer.FULL_SPEED].speed_factor == 1.0
    assert "insurers" in LAYER_PROFILES[PresentationLayer.CONSTRUCTED_SCENARIO].audiences


def test_cockpit_adapter_is_read_only_and_non_authoritative() -> None:
    snapshot = sample_snapshot()
    before = deepcopy(snapshot)
    adapter = CockpitVisualizationAdapter()
    for layer in PresentationLayer:
        scenario = {"title": "Test scenario", "stages": [{"name": "Hypothesis", "status": "hypothetical"}]}
        manifest = adapter.build_scene(snapshot, layer=layer, scenario=scenario)
        metadata = manifest.to_dict()["metadata"]
        assert metadata["runtime_authority"] == "NONE"
        assert metadata["canonical_runtime_mutation"] is False
        assert metadata["governance_decisions"] is False
        assert metadata["execution_authorization"] is False
        assert metadata["integration_access"] == "read_only"
    assert snapshot == before


def test_constructed_scenario_is_visibly_labelled() -> None:
    manifest = CockpitVisualizationAdapter().build_scene(
        {},
        layer=PresentationLayer.CONSTRUCTED_SCENARIO,
        scenario={"title": "Insurer review", "stages": [{"name": "Constructed event"}]},
    ).to_dict()
    contents = [item["content"] for item in manifest["scene"]["overlays"]]
    assert any("NOT A RUNTIME DECISION" in item for item in contents)


def test_video_package_has_no_runtime_import_or_authority_attachment() -> None:
    repository = Path(__file__).resolve().parents[2]
    result = run_boundary_check(repository)
    assert result["status"] == "VIDEO_BOUNDARY_OK", result
    assert result["finding_count"] == 0
    assert result["runtime_authority"] == "NONE"
