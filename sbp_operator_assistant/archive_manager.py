from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from sbp_operator_assistant import config
from sbp_operator_assistant.schemas import normalise_path, utc_now
from sbp_operator_assistant.storage import DEFAULT_STORAGE, JsonStorage


class CanonicalArchiveManager:
    def __init__(self, storage: JsonStorage = DEFAULT_STORAGE) -> None:
        self.storage = storage

    def _load(self) -> dict[str, Any]:
        return self.storage.read(config.CANONICAL_ARCHIVE_FILE)

    def _save(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.storage.write(config.CANONICAL_ARCHIVE_FILE, payload)

    def register_canonical_document(
        self,
        path: str | Path,
        doctrine_area: str,
        version: str | None = None,
    ) -> dict[str, Any]:
        payload = self._load()
        stored_path = normalise_path(path)
        document = {
            "path": stored_path,
            "doctrine_area": doctrine_area,
            "version": version,
            "registered_at": utc_now(),
        }
        documents = payload.setdefault("documents", [])
        existing = next((item for item in documents if item.get("path") == stored_path), None)
        if existing:
            existing.update(document)
        else:
            documents.append(document)
        self._save(payload)
        return deepcopy(document)

    def list_canonical_documents(self) -> list[dict[str, Any]]:
        return sorted(deepcopy(self._load().get("documents", [])), key=lambda item: item.get("path", ""))

    def find_by_doctrine(self, doctrine_area: str) -> list[dict[str, Any]]:
        return [
            deepcopy(document)
            for document in self._load().get("documents", [])
            if document.get("doctrine_area") == doctrine_area
        ]

    def link_document_to_phase(self, path: str | Path, phase_name: str) -> dict[str, Any]:
        payload = self._load()
        link = {
            "path": normalise_path(path),
            "phase": phase_name,
            "linked_at": utc_now(),
        }
        payload.setdefault("phase_links", []).append(link)
        self._save(payload)
        return deepcopy(link)


DEFAULT_ARCHIVE = CanonicalArchiveManager()


def register_canonical_document(path: str | Path, doctrine_area: str, version: str | None = None) -> dict[str, Any]:
    return DEFAULT_ARCHIVE.register_canonical_document(path, doctrine_area, version)


def list_canonical_documents() -> list[dict[str, Any]]:
    return DEFAULT_ARCHIVE.list_canonical_documents()


def find_by_doctrine(doctrine_area: str) -> list[dict[str, Any]]:
    return DEFAULT_ARCHIVE.find_by_doctrine(doctrine_area)


def link_document_to_phase(path: str | Path, phase_name: str) -> dict[str, Any]:
    return DEFAULT_ARCHIVE.link_document_to_phase(path, phase_name)

