from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

from sbp_operator_assistant import config
from sbp_operator_assistant.schemas import normalise_path, utc_now
from sbp_operator_assistant.storage import DEFAULT_STORAGE, JsonStorage


class WorkspaceManager:
    def __init__(self, storage: JsonStorage = DEFAULT_STORAGE) -> None:
        self.storage = storage

    def _load(self) -> dict[str, Any]:
        return self.storage.read(config.WORKSPACES_FILE)

    def _save(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.storage.write(config.WORKSPACES_FILE, payload)

    def register_workspace(
        self,
        name: str,
        paths: Iterable[str | Path],
        commands: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        if not name.strip():
            raise ValueError("workspace name is required")
        payload = self._load()
        workspace = {
            "name": name,
            "paths": [normalise_path(path) for path in paths],
            "commands": [str(command) for command in (commands or [])],
            "registered_at": utc_now(),
        }
        payload.setdefault("workspaces", {})[name] = workspace
        self._save(payload)
        return deepcopy(workspace)

    def get_workspace(self, name: str) -> dict[str, Any] | None:
        workspace = self._load().get("workspaces", {}).get(name)
        return deepcopy(workspace) if workspace is not None else None

    def list_workspaces(self) -> list[dict[str, Any]]:
        return [
            deepcopy(workspace)
            for _, workspace in sorted(self._load().get("workspaces", {}).items())
        ]

    def prepare_workspace(self, name: str) -> dict[str, Any]:
        workspace = self.get_workspace(name)
        if workspace is None:
            raise KeyError(name)
        return {
            "workspace": name,
            "paths_to_open": list(workspace.get("paths", [])),
            "commands_to_review": list(workspace.get("commands", [])),
            "destructive_actions": [],
            "launched": False,
        }


DEFAULT_MANAGER = WorkspaceManager()


def register_workspace(name: str, paths: Iterable[str | Path], commands: Iterable[str] | None = None) -> dict[str, Any]:
    return DEFAULT_MANAGER.register_workspace(name, paths, commands)


def get_workspace(name: str) -> dict[str, Any] | None:
    return DEFAULT_MANAGER.get_workspace(name)


def list_workspaces() -> list[dict[str, Any]]:
    return DEFAULT_MANAGER.list_workspaces()


def prepare_workspace(name: str) -> dict[str, Any]:
    return DEFAULT_MANAGER.prepare_workspace(name)

