from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable, Mapping

from sbp_operator_assistant import config
from sbp_operator_assistant.schemas import utc_now
from sbp_operator_assistant.storage import DEFAULT_STORAGE, JsonStorage


class CodexBuildAssistant:
    def __init__(self, storage: JsonStorage = DEFAULT_STORAGE) -> None:
        self.storage = storage

    def _load(self) -> dict[str, Any]:
        return self.storage.read(config.CODEX_PACKAGES_FILE)

    def _save(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.storage.write(config.CODEX_PACKAGES_FILE, payload)

    def create_codex_package(
        self,
        phase_name: str,
        included_docs: Iterable[str] | None = None,
        repo_status: str | None = None,
    ) -> dict[str, Any]:
        payload = self._load()
        packages = payload.setdefault("packages", [])
        sequence = len(packages) + 1
        package = {
            "id": f"codex-package-{sequence:04d}",
            "phase_name": phase_name,
            "included_docs": list(included_docs or []),
            "repo_status": repo_status,
            "created_at": utc_now(),
            "content": _build_package_text(phase_name, list(included_docs or []), repo_status),
            "safe_actions_only": True,
        }
        packages.append(package)
        self._save(payload)
        return deepcopy(package)

    def list_codex_packages(self) -> list[dict[str, Any]]:
        return deepcopy(self._load().get("packages", []))

    def get_latest_codex_package(self, phase_name: str) -> dict[str, Any] | None:
        matches = [
            package
            for package in self._load().get("packages", [])
            if package.get("phase_name") == phase_name
        ]
        return deepcopy(matches[-1]) if matches else None


def _build_package_text(phase_name: str, included_docs: list[str], repo_status: str | None) -> str:
    lines = [
        f"Codex Build Package: {phase_name}",
        "",
        "Scope: local SBP operator productivity context only.",
        "Runtime authority changes: prohibited.",
        "Execution governance changes: prohibited.",
        "",
        "Included documents:",
    ]
    lines.extend(f"- {document}" for document in included_docs)
    if not included_docs:
        lines.append("- None")
    lines.extend(["", f"Repository status: {repo_status or 'not recorded'}"])
    return "\n".join(lines)


DEFAULT_ASSISTANT = CodexBuildAssistant()


def create_codex_package(phase_name: str, included_docs: Iterable[str] | None = None, repo_status: str | None = None) -> dict[str, Any]:
    return DEFAULT_ASSISTANT.create_codex_package(phase_name, included_docs, repo_status)


def list_codex_packages() -> list[dict[str, Any]]:
    return DEFAULT_ASSISTANT.list_codex_packages()


def get_latest_codex_package(phase_name: str) -> dict[str, Any] | None:
    return DEFAULT_ASSISTANT.get_latest_codex_package(phase_name)

