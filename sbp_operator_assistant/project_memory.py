from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from sbp_operator_assistant import config
from sbp_operator_assistant.schemas import utc_now
from sbp_operator_assistant.storage import DEFAULT_STORAGE, JsonStorage


class ProjectMemory:
    def __init__(self, storage: JsonStorage = DEFAULT_STORAGE) -> None:
        self.storage = storage

    def _load(self) -> dict[str, Any]:
        return self.storage.read(config.PROJECT_MEMORY_FILE)

    def _save(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.storage.write(config.PROJECT_MEMORY_FILE, payload)

    def set_current_phase(self, phase_name: str) -> dict[str, Any]:
        if not phase_name.strip():
            raise ValueError("phase name is required")
        payload = self._load()
        payload["current_phase"] = phase_name
        payload["updated_at"] = utc_now()
        self._save(payload)
        return self.get_project_status()

    def mark_phase_complete(self, phase_name: str, report_path: str | None = None) -> dict[str, Any]:
        payload = self._load()
        payload.setdefault("completed_phases", {})[phase_name] = {
            "phase": phase_name,
            "report_path": report_path,
            "completed_at": utc_now(),
        }
        self._save(payload)
        return deepcopy(payload["completed_phases"][phase_name])

    def add_pending_task(self, task: str, phase: str | None = None) -> dict[str, Any]:
        if not task.strip():
            raise ValueError("task is required")
        payload = self._load()
        entry = {
            "task": task,
            "phase": phase,
            "status": "pending",
            "created_at": utc_now(),
        }
        payload.setdefault("pending_tasks", []).append(entry)
        self._save(payload)
        return deepcopy(entry)

    def list_pending_tasks(self) -> list[dict[str, Any]]:
        return [
            deepcopy(task)
            for task in self._load().get("pending_tasks", [])
            if task.get("status") == "pending"
        ]

    def get_project_status(self) -> dict[str, Any]:
        return deepcopy(self._load())


DEFAULT_MEMORY = ProjectMemory()


def set_current_phase(phase_name: str) -> dict[str, Any]:
    return DEFAULT_MEMORY.set_current_phase(phase_name)


def mark_phase_complete(phase_name: str, report_path: str | None = None) -> dict[str, Any]:
    return DEFAULT_MEMORY.mark_phase_complete(phase_name, report_path)


def add_pending_task(task: str, phase: str | None = None) -> dict[str, Any]:
    return DEFAULT_MEMORY.add_pending_task(task, phase)


def list_pending_tasks() -> list[dict[str, Any]]:
    return DEFAULT_MEMORY.list_pending_tasks()


def get_project_status() -> dict[str, Any]:
    return DEFAULT_MEMORY.get_project_status()

