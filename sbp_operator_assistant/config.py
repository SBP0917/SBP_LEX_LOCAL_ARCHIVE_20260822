from __future__ import annotations

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_ROOT / "data"

WORKSPACES_FILE = "workspaces.json"
DOCUMENTS_FILE = "documents.json"
PROJECT_MEMORY_FILE = "project_memory.json"
CANONICAL_ARCHIVE_FILE = "canonical_archive.json"
CODEX_PACKAGES_FILE = "codex_packages.json"

