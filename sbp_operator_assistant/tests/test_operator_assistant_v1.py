from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sbp_operator_assistant import config
from sbp_operator_assistant.archive_manager import CanonicalArchiveManager
from sbp_operator_assistant.codex_assistant import CodexBuildAssistant
from sbp_operator_assistant.dashboard import render_dashboard_html
from sbp_operator_assistant.file_organiser import FileOrganiser
from sbp_operator_assistant.project_memory import ProjectMemory
from sbp_operator_assistant.storage import JsonStorage
from sbp_operator_assistant.workspace_manager import WorkspaceManager


def storage(tmp_path: Path) -> JsonStorage:
    return JsonStorage(tmp_path / "assistant-data")


def test_workspace_registration_and_preparation_returns_review_items(tmp_path: Path) -> None:
    manager = WorkspaceManager(storage(tmp_path))
    manager.register_workspace(
        "Phase 15.6B",
        ["docs/EXTERNAL_SKG_DTN_BRIDGE_READINESS.md"],
        commands=["python -m pytest -q"],
    )

    prepared = manager.prepare_workspace("Phase 15.6B")

    assert prepared["paths_to_open"] == ["docs/EXTERNAL_SKG_DTN_BRIDGE_READINESS.md"]
    assert prepared["commands_to_review"] == ["python -m pytest -q"]
    assert prepared["destructive_actions"] == []
    assert prepared["launched"] is False


def test_document_registration_listing_and_search(tmp_path: Path) -> None:
    organiser = FileOrganiser(storage(tmp_path))
    organiser.register_document(
        "docs/SBP_OPERATOR_ASSISTANT_V1.md",
        title="SBP Operator Assistant V1",
        project="SBP-LEX",
        tags=["assistant", "operator"],
        phase="Operator Assistant V1",
    )

    assert len(organiser.list_documents(project="SBP-LEX")) == 1
    assert organiser.list_documents(tag="assistant")[0]["archive_key"] == "S"
    assert organiser.search_documents("operator")[0]["phase"] == "Operator Assistant V1"


def test_duplicate_detection_reports_duplicate_paths(tmp_path: Path) -> None:
    assistant_storage = storage(tmp_path)
    assistant_storage.write(
        config.DOCUMENTS_FILE,
        {
            "documents": [
                {"path": "docs/a.md", "title": "A"},
                {"path": "docs/a.md", "title": "A copy"},
            ]
        },
    )

    duplicates = FileOrganiser(assistant_storage).detect_duplicates()

    assert duplicates == [
        {
            "path": "docs/a.md",
            "documents": [
                {"path": "docs/a.md", "title": "A"},
                {"path": "docs/a.md", "title": "A copy"},
            ],
        }
    ]


def test_project_memory_tracks_current_completed_and_pending(tmp_path: Path) -> None:
    memory = ProjectMemory(storage(tmp_path))
    memory.set_current_phase("Operator Assistant V1")
    memory.mark_phase_complete("Phase 18", "reports/PHASE_18_PROCEDURAL_TRUTH_BINDING_REPORT.md")
    memory.add_pending_task("Prepare workspace registry", phase="Operator Assistant V1")

    status = memory.get_project_status()

    assert status["current_phase"] == "Operator Assistant V1"
    assert "Phase 18" in status["completed_phases"]
    assert memory.list_pending_tasks()[0]["task"] == "Prepare workspace registry"


def test_canonical_document_registration_doctrine_lookup_and_phase_link(tmp_path: Path) -> None:
    archive = CanonicalArchiveManager(storage(tmp_path))
    archive.register_canonical_document(
        "docs/PROCEDURAL_TRUTH_BINDING_DURING_STATE_CONSTRUCTION.md",
        "Procedural Truth",
        version="1",
    )
    link = archive.link_document_to_phase(
        "docs/PROCEDURAL_TRUTH_BINDING_DURING_STATE_CONSTRUCTION.md",
        "Phase 18",
    )

    assert archive.find_by_doctrine("Procedural Truth")[0]["version"] == "1"
    assert link["phase"] == "Phase 18"


def test_codex_package_creation_and_latest_lookup(tmp_path: Path) -> None:
    assistant = CodexBuildAssistant(storage(tmp_path))
    package = assistant.create_codex_package(
        "Operator Assistant V1",
        included_docs=["docs/SBP_OPERATOR_ASSISTANT_V1.md"],
        repo_status="local productivity package only",
    )

    assert package["safe_actions_only"] is True
    assert "Runtime authority changes: prohibited." in package["content"]
    assert assistant.get_latest_codex_package("Operator Assistant V1")["id"] == package["id"]


def test_json_storage_persistence_is_human_readable(tmp_path: Path) -> None:
    assistant_storage = storage(tmp_path)
    assistant_storage.write(config.WORKSPACES_FILE, {"workspaces": {"A": {"paths": []}}})

    stored = assistant_storage.path_for(config.WORKSPACES_FILE).read_text(encoding="utf-8")

    assert json.loads(stored)["workspaces"]["A"]["paths"] == []
    assert "\n  " in stored


def test_cli_status_command_is_safe_and_read_only() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sbp_operator_assistant.app", "status"],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert "current_phase" in payload


def test_dashboard_is_separate_assistant_view(tmp_path: Path) -> None:
    memory = ProjectMemory(storage(tmp_path))
    memory.set_current_phase("Operator Assistant V1")

    html = render_dashboard_html(memory.storage)

    assert "SBP Operator Assistant V1" in html
    assert "Quick Launch" in html
    assert "No commands are launched" in html


def test_public_modules_do_not_expose_destructive_file_operations() -> None:
    forbidden = {"delete", "remove", "unlink", "rmtree", "move", "replace"}
    public_names = set()
    for module in [
        WorkspaceManager,
        FileOrganiser,
        ProjectMemory,
        CanonicalArchiveManager,
        CodexBuildAssistant,
    ]:
        public_names.update(name for name in dir(module) if not name.startswith("_"))

    assert forbidden.isdisjoint(public_names)

