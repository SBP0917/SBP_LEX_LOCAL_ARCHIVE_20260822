from __future__ import annotations

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
    assert "Runtime Health" in html
    assert "Pipeline / Convergence" in html
    assert "Execution Decision" in html
    assert "Audit / Replay" in html
    assert "/runtime/traverse" in html
    assert "/runtime/replay" in html
    assert DESKTOP_BACKGROUND_URL in html
    assert "--status-pass" in html
    assert "--status-escalate" in html
    assert "--status-deny" in html
    assert "--status-active" in html
    assert "reasonOutcome" in html
    assert "Reason:" in html


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
    assert "decision" in summary
    assert "execution_result" in summary
    assert "convergence_matched" in summary
    assert "audit_hash" in summary
