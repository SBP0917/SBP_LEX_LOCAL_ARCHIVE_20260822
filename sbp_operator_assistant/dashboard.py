from __future__ import annotations

from html import escape

from sbp_operator_assistant.archive_manager import CanonicalArchiveManager
from sbp_operator_assistant.codex_assistant import CodexBuildAssistant
from sbp_operator_assistant.file_organiser import FileOrganiser
from sbp_operator_assistant.project_memory import ProjectMemory
from sbp_operator_assistant.storage import DEFAULT_STORAGE, JsonStorage


def render_dashboard_html(storage: JsonStorage = DEFAULT_STORAGE) -> str:
    memory = ProjectMemory(storage).get_project_status()
    documents = FileOrganiser(storage).get_recent_documents()
    canonical = CanonicalArchiveManager(storage).list_canonical_documents()
    packages = CodexBuildAssistant(storage).list_codex_packages()
    pending = memory.get("pending_tasks", [])
    completed = memory.get("completed_phases", {})
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SBP Operator Assistant V1</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #111; background: #f7f7f7; }}
    main {{ max-width: 1100px; margin: 0 auto; }}
    section {{ margin: 16px 0; padding: 16px; background: #fff; border: 1px solid #ddd; }}
    h1, h2 {{ margin: 0 0 12px; }}
    ul {{ margin: 0; padding-left: 20px; }}
    code {{ background: #eee; padding: 2px 4px; }}
  </style>
</head>
<body>
<main>
  <h1>SBP Operator Assistant V1</h1>
  <section><h2>Current Phase</h2><p>{escape(str(memory.get("current_phase") or "Not set"))}</p></section>
  <section><h2>Completed Phases</h2>{_list(completed.keys())}</section>
  <section><h2>Pending Tasks</h2>{_list(task.get("task", "") for task in pending)}</section>
  <section><h2>Recent Documents</h2>{_list(document.get("title", "") for document in documents)}</section>
  <section><h2>Canonical Archive Shortcuts</h2>{_list(document.get("path", "") for document in canonical)}</section>
  <section><h2>Codex Package Shortcuts</h2>{_list(package.get("id", "") for package in packages)}</section>
  <section><h2>Repository Status</h2><p>Placeholder for operator-recorded status.</p></section>
  <section><h2>Quick Launch</h2><p>Placeholder only. No commands are launched from this dashboard.</p></section>
</main>
</body>
</html>
"""


def _list(values: object) -> str:
    items = [escape(str(value)) for value in values if str(value)]
    if not items:
        return "<p>None recorded.</p>"
    return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"

