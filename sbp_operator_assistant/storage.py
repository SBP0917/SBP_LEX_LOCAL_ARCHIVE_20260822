from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from sbp_operator_assistant import config


DEFAULT_DOCUMENTS: dict[str, Any] = {"documents": []}
DEFAULT_WORKSPACES: dict[str, Any] = {"workspaces": {}}
DEFAULT_PROJECT_MEMORY: dict[str, Any] = {
    "current_phase": None,
    "completed_phases": {},
    "pending_tasks": [],
    "repository_state_notes": [],
    "canonical_documents": [],
    "outstanding_codex_tasks": [],
    "patent_work": [],
    "ui_work": [],
    "skg_work": [],
    "dtn_work": [],
}
DEFAULT_CANONICAL_ARCHIVE: dict[str, Any] = {"documents": [], "phase_links": []}
DEFAULT_CODEX_PACKAGES: dict[str, Any] = {"packages": []}

DEFAULTS_BY_FILE: dict[str, dict[str, Any]] = {
    config.WORKSPACES_FILE: DEFAULT_WORKSPACES,
    config.DOCUMENTS_FILE: DEFAULT_DOCUMENTS,
    config.PROJECT_MEMORY_FILE: DEFAULT_PROJECT_MEMORY,
    config.CANONICAL_ARCHIVE_FILE: DEFAULT_CANONICAL_ARCHIVE,
    config.CODEX_PACKAGES_FILE: DEFAULT_CODEX_PACKAGES,
}


class JsonStorage:
    """Human-readable JSON storage rooted inside the assistant package."""

    def __init__(self, data_dir: Path | str = config.DATA_DIR) -> None:
        self.data_dir = Path(data_dir)

    def path_for(self, filename: str) -> Path:
        return self.data_dir / filename

    def read(self, filename: str, default: Mapping[str, Any] | None = None) -> dict[str, Any]:
        fallback = deepcopy(dict(default or DEFAULTS_BY_FILE.get(filename, {})))
        path = self.path_for(filename)
        if not path.exists():
            return fallback
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError(f"{filename} must contain a JSON object")
        return loaded

    def write(self, filename: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path = self.path_for(filename)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return dict(payload)


DEFAULT_STORAGE = JsonStorage()


def read_json(filename: str, default: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return DEFAULT_STORAGE.read(filename, default)


def write_json(filename: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    return DEFAULT_STORAGE.write(filename, payload)

