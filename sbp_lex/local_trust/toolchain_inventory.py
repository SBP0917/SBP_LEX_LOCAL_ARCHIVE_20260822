from __future__ import annotations

import importlib.metadata
import platform
import re
import sys
from pathlib import Path
from typing import Any

from sbp_lex.local_trust.command_policy import (
    IGNORED_OUTPUT_PATHS,
    IGNORED_TEMP_PATHS,
    PYTEST_COLLECTION_POLICY,
    verification_command_policy,
)
from sbp_lex.local_trust.file_digest import digest_file_record

DEPENDENCY_FILE_CANDIDATES: tuple[str, ...] = (
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
)


def collect_toolchain_inventory(repository_root: Path) -> dict[str, Any]:
    dependency_records = collect_dependency_file_digests(repository_root)
    present_dependency_files = [record["path"] for record in dependency_records if record["status"] == "PRESENT"]
    return {
        "python_executable": sys.executable,
        "python_version": sys.version.replace("\n", " "),
        "python_prefix": sys.prefix,
        "python_base_prefix": sys.base_prefix,
        "platform": platform.platform(),
        "pytest_version": package_version("pytest"),
        "pytest_import_available": package_version("pytest") is not None,
        "pip_version_if_available": package_version("pip"),
        "dependency_files": present_dependency_files or ["NO_DEPENDENCY_FILE_PRESENT"],
        "dependency_file_digests": dependency_records,
        "installed_package_snapshot": installed_package_snapshot(),
        "verification_command_policy": verification_command_policy(),
        "pytest_collection_policy": PYTEST_COLLECTION_POLICY,
        "ignored_output_paths": list(IGNORED_OUTPUT_PATHS),
        "ignored_temp_paths": list(IGNORED_TEMP_PATHS),
    }


def collect_dependency_file_digests(repository_root: Path) -> list[dict[str, Any]]:
    return [digest_file_record(repository_root, candidate) for candidate in DEPENDENCY_FILE_CANDIDATES]


def package_version(package_name: str) -> str | None:
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def installed_package_snapshot() -> dict[str, Any]:
    packages: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        version = distribution.version
        if not name or not version:
            continue
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        packages.append({"name": name, "version": version})
    packages.sort(key=lambda item: (item["name"].lower(), item["version"]))
    return {
        "snapshot_mode": "installed_distributions_name_version_only",
        "package_count": len(packages),
        "packages": packages,
    }


def parse_python_version(version_text: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version_text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())
