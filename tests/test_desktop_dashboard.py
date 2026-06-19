from __future__ import annotations

import ast
from pathlib import Path

from sbp_lex.api.access_control import validate_path
from sbp_lex.desktop.dashboard import (
    DESKTOP_BACKGROUND_URL,
    desktop_background_bytes,
    desktop_dashboard_html,
    export_latest_runtime_json,
    export_replay_ledger_json,
    export_traversal_events_json,
    latest_runtime_snapshot,
    sample_request_payload,
)
from sbp_lex.runtime.canonical_runtime import CANONICAL_RUNTIME


def test_desktop_dashboard_contains_required_runtime_sections() -> None:
    html = desktop_dashboard_html()
    assert "SBP-LEX Desktop V1" in html
    assert "SBP-LEX Operator Cockpit" in html
    assert "Local Governance Observability Console" in html
    assert "Dual Adaptive Deterministic Pipelines" in html
    assert "Pipeline A / Pipeline B Progression" in html
    assert "Audit Continuity" in html
    assert "Replay Comparison" in html
    assert "Controlled Operator Actions" in html
    assert "Run Approved Demo Traversal" in html
    assert "Start Live Test" in html
    assert "Runtime Status" in html
    assert "Reset / Clear View" in html
    assert "Load Demo Request" in html
    assert "Stop / Halt" in html
    assert "Procedural Truth Details" in html
    assert "SKG/DTN Bridge Details" in html
    assert "/runtime/traverse" in html
    assert "/runtime/replay" in html
    assert "/runtime/integrity" in html
    assert DESKTOP_BACKGROUND_URL in html
    assert "--status-pass" in html
    assert "--status-escalate" in html
    assert "--status-deny" in html
    assert "--status-active" in html
    assert "reasonOutcome" in html
    assert "Reason:" in html
    assert "requestBox" not in html
    assert 'id="pipelineVisual"' in html
    assert "pipeline-cylinder" in html
    assert "renderPipelineVisual" in html
    assert 'id="pipelineA"' in html
    assert 'id="pipelineB"' in html
    assert 'id="scaleArena"' in html
    assert "prefers-reduced-motion" in html


def test_cockpit_semantic_classes_cover_owner_defined_states() -> None:
    html = desktop_dashboard_html()
    for state in ("PASS", "ALLOW", "ESCALATE", "REFINE", "DENY", "FAIL", "HALT", "STOP", "ACTIVE", "LIVE", "IDLE", "WAITING"):
        assert state in html
    assert "--status-pass: #19d98b" in html
    assert "--status-escalate: #ff9f1c" in html
    assert "--status-deny: #ff3b30" in html
    assert "--status-active: #19cfff" in html
    assert "--status-idle: #718096" in html


def test_ecg_is_exclusive_to_live_traversal() -> None:
    html = desktop_dashboard_html()
    assert "function ecgMarkup(mode)" in html
    assert "mode==='LIVE'?`<svg class=\"ecg-trace\"" in html
    assert "Live traversal ECG" in html
    assert "ecg-travel" in html
    assert "pipeline-mode-live" in html


def test_alive_last_current_and_historical_motion_rules_exist() -> None:
    html = desktop_dashboard_html()
    assert "pipeline-mode-alive" in html
    assert "heartbeat-state" in html
    assert "heartbeat-glow 2s" in html
    assert "near-life" in html
    assert "Last Current Traversed" in html
    assert "state-glow" in html
    assert "Steady glow · no ECG" in html
    assert "state-historical" in html
    assert "state-terminal" in html
    assert "Heartbeat · governed continuation possible" in html


def test_halt_and_deny_remain_visually_distinct_labels() -> None:
    html = desktop_dashboard_html()
    assert "execution_result==='HALT'?'HALT'" in html
    assert "DENY:'Governed refusal concluded traversal'" in html
    assert "HALT:'Execution-control stop applied'" in html


def test_storm_scales_and_celestial_workspace_follow_state() -> None:
    html = desktop_dashboard_html()
    for state in ("storm-calm", "storm-live", "storm-alive", "storm-escalate", "storm-deny", "storm-execute"):
        assert state in html
    assert "storm-withdraw" in html
    assert "scale-state-live" in html
    assert "scale-state-alive" in html
    assert "scale-state-escalate" in html
    assert "scale-state-deny" in html
    assert "360° · degree / minute / second markings" in html
    assert "Pop Out Celestial Workspace" in html


def test_detail_panel_reserves_space_and_identity_envelope_renders() -> None:
    html = desktop_dashboard_html()
    assert 'id="detailPanel"' in html
    assert ".detail-open .desktop-shell" in html
    assert "margin-right:390px" in html
    assert "position:relative; inset:auto" in html
    assert 'id="identityEnvelope"' in html
    assert "Manufacturer" in html
    assert "AP-ACF" in html
    assert "Licence Authority" in html


def test_cockpit_renderer_imports_no_runtime_authority_modules() -> None:
    path = Path("sbp_lex/desktop/cockpit.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    internal_imports: list[str] = []
    for item in ast.walk(tree):
        if isinstance(item, ast.Import):
            internal_imports.extend(alias.name for alias in item.names if alias.name.startswith("sbp_lex"))
        elif isinstance(item, ast.ImportFrom) and (item.module or "").startswith("sbp_lex"):
            internal_imports.append(item.module or "")
    assert internal_imports == []


def test_cockpit_renderer_introduces_no_prohibited_topology_terms() -> None:
    source = Path("sbp_lex/desktop/cockpit.py").read_text(encoding="utf-8").lower()
    prohibited = (
        "node_quorum",
        "node_attestation",
        "distributed consensus",
        "multi-node execution",
        "distributed mesh",
        "quorum execution",
    )
    assert [term for term in prohibited if term in source] == []


def test_desktop_background_asset_is_png() -> None:
    image = desktop_background_bytes()
    assert image.startswith(b"\x89PNG\r\n\x1a\n")
    assert image.endswith(b"IEND\xaeB`\x82")
    assert len(image) > 1_000_000


def test_desktop_background_route_is_narrowly_allowed() -> None:
    assert validate_path("GET", DESKTOP_BACKGROUND_URL) == (True, "path_allowed")
    assert validate_path("GET", "/desktop/static/images/other.png") == (False, "path_not_allowed")


def test_desktop_sample_request_traverses() -> None:
    payload = sample_request_payload()
    result = CANONICAL_RUNTIME.traverse(payload["request"], request_id=payload["request_id"])
    state = result["state"]
    assert state["decision"] == "ALLOW"
    assert state["execution_result"] == "EXECUTE"
    assert state["pipeline_convergence"]["matched"] is True


def test_desktop_exports_are_structured() -> None:
    latest = export_latest_runtime_json()
    replay = export_replay_ledger_json()
    events = export_traversal_events_json()

    assert latest["export_type"] == "latest_runtime_snapshot"
    assert "status" in latest
    assert replay["export_type"] == "replay_ledger"
    assert "entries" in replay
    assert events["export_type"] == "traversal_events"
    assert "events" in events


def test_latest_runtime_snapshot_has_operator_fields() -> None:
    snapshot = latest_runtime_snapshot()
    summary = snapshot["last_state_summary"]
    operator = snapshot["operator_summary"]
    integrity = snapshot["integrity_summary"]
    replay = snapshot["latest_replay_summary"]
    identity = snapshot["identity_summary"]

    assert operator["console_name"] == "SBP-LEX Desktop V1"
    assert operator["console_role"] == "Local Governance Observability Console"
    assert operator["binding_posture"] in {"localhost-only policy", "private token policy", "security disabled"}
    assert "healthy" in integrity
    assert integrity["status_contract_endpoint"] == "/runtime/integrity"
    assert "decision" in summary
    assert "execution_result" in summary
    assert "execution_verified" in summary
    assert "admissibility_status" in summary
    assert "pipeline_a_timeline" in summary
    assert "pipeline_b_summary" in summary
    assert "convergence_matched" in summary
    assert "audit_hash" in summary
    assert "procedural_truth_status" in summary
    assert "recoverable" in summary
    assert "governed_reentry" in summary
    assert set(identity) == {
        "manufacturer",
        "system_name",
        "model",
        "version",
        "unique_system_identifier",
        "ap_acf_class",
        "ap_acf_subclass",
        "autonomy_level",
        "autonomy_ceiling",
        "operational_scope",
        "operational_environment",
        "licence_state",
        "licence_authority",
        "request_fingerprint",
    }
    assert "available" in replay
    assert snapshot["export_availability"] == {
        "latest_result": True,
        "replay_ledger": True,
        "events": True,
    }
    assert summary["pipeline_count"] in {1, 2}
