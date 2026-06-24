from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

from sbp_operator_assistant import config
from sbp_operator_assistant.schemas import archive_key, normalise_path, normalise_tags, utc_now
from sbp_operator_assistant.storage import DEFAULT_STORAGE, JsonStorage


class FileOrganiser:
    def __init__(self, storage: JsonStorage = DEFAULT_STORAGE) -> None:
        self.storage = storage

    def _load(self) -> dict[str, Any]:
        return self.storage.read(config.DOCUMENTS_FILE)

    def _save(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.storage.write(config.DOCUMENTS_FILE, payload)

    def register_document(
        self,
        path: str | Path,
        title: str | None = None,
        project: str | None = None,
        tags: Iterable[str] | None = None,
        phase: str | None = None,
    ) -> dict[str, Any]:
        payload = self._load()
        documents = payload.setdefault("documents", [])
        stored_path = normalise_path(path)
        name = title or Path(stored_path).name
        existing = next((doc for doc in documents if doc.get("path") == stored_path), None)
        document = {
            "path": stored_path,
            "title": name,
            "project": project,
            "tags": normalise_tags(tags),
            "phase": phase,
            "archive_key": archive_key(name),
            "version": None,
            "registered_at": existing.get("registered_at") if existing else utc_now(),
            "updated_at": utc_now(),
        }
        if existing:
            existing.update(document)
        else:
            documents.append(document)
        self._save(payload)
        return deepcopy(document)

    def list_documents(
        self,
        project: str | None = None,
        phase: str | None = None,
        tag: str | None = None,
    ) -> list[dict[str, Any]]:
        documents = self._load().get("documents", [])
        filtered = []
        for document in documents:
            if project is not None and document.get("project") != project:
                continue
            if phase is not None and document.get("phase") != phase:
                continue
            if tag is not None and tag not in document.get("tags", []):
                continue
            filtered.append(deepcopy(document))
        return sorted(filtered, key=lambda item: (item.get("archive_key", "#"), item.get("title", "")))

    def search_documents(self, query: str) -> list[dict[str, Any]]:
        needle = query.lower()
        results = []
        for document in self._load().get("documents", []):
            haystack = " ".join(
                str(value)
                for value in [
                    document.get("path", ""),
                    document.get("title", ""),
                    document.get("project", ""),
                    document.get("phase", ""),
                    " ".join(document.get("tags", [])),
                ]
            ).lower()
            if needle in haystack:
                results.append(deepcopy(document))
        return results

    def detect_duplicates(self) -> list[dict[str, Any]]:
        by_path: dict[str, list[dict[str, Any]]] = {}
        for document in self._load().get("documents", []):
            by_path.setdefault(str(document.get("path", "")).lower(), []).append(document)
        return [
            {"path": path, "documents": deepcopy(documents)}
            for path, documents in sorted(by_path.items())
            if len(documents) > 1
        ]

    def get_recent_documents(self, limit: int = 10) -> list[dict[str, Any]]:
        documents = sorted(
            self._load().get("documents", []),
            key=lambda item: item.get("updated_at", ""),
            reverse=True,
        )
        return deepcopy(documents[:limit])


DEFAULT_ORGANISER = FileOrganiser()


def register_document(path: str | Path, title: str | None = None, project: str | None = None, tags: Iterable[str] | None = None, phase: str | None = None) -> dict[str, Any]:
    return DEFAULT_ORGANISER.register_document(path, title, project, tags, phase)


def list_documents(project: str | None = None, phase: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
    return DEFAULT_ORGANISER.list_documents(project, phase, tag)


def search_documents(query: str) -> list[dict[str, Any]]:
    return DEFAULT_ORGANISER.search_documents(query)


def detect_duplicates() -> list[dict[str, Any]]:
    return DEFAULT_ORGANISER.detect_duplicates()


def get_recent_documents(limit: int = 10) -> list[dict[str, Any]]:
    return DEFAULT_ORGANISER.get_recent_documents(limit)

