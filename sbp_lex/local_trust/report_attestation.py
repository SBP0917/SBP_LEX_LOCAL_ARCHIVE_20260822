from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from sbp_lex.local_trust.evidence_registry import REQUIRED_EVIDENCE_SPECS
from sbp_lex.local_trust.file_digest import sha256_file
from sbp_lex.local_trust.manifest import canonical_json


def collect_evidence_items(
    repository_root: Path,
    specs: Iterable[Mapping[str, Any]] = REQUIRED_EVIDENCE_SPECS,
) -> list[dict[str, Any]]:
    return [build_evidence_item(repository_root, spec) for spec in specs]


def build_evidence_item(repository_root: Path, spec: Mapping[str, Any]) -> dict[str, Any]:
    relative_path = normalise_evidence_path(str(spec["path"]))
    path = repository_root / relative_path
    base = {
        "evidence_id": str(spec["evidence_id"]),
        "path": relative_path,
        "category": str(spec["category"]),
        "required": bool(spec.get("required", True)),
        "content_type": content_type_for_path(relative_path),
        "source_phase": str(spec["source_phase"]),
    }
    if not path.exists():
        return {
            **base,
            "exists": False,
            "size_bytes": None,
            "sha256": None,
            "last_modified_utc": None,
            "attestation_status": "MISSING",
        }
    if not path.is_file():
        return {
            **base,
            "exists": False,
            "size_bytes": None,
            "sha256": None,
            "last_modified_utc": None,
            "attestation_status": "NOT_FILE",
        }
    return {
        **base,
        "exists": True,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "last_modified_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "attestation_status": "HASHED",
    }


def missing_evidence_items(evidence_items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": str(item["evidence_id"]),
            "path": str(item["path"]),
            "category": str(item["category"]),
            "required": bool(item.get("required", True)),
            "attestation_status": str(item.get("attestation_status")),
        }
        for item in evidence_items
        if item.get("exists") is not True
    ]


def hash_evidence_item(item: Mapping[str, Any]) -> str:
    return sha256(canonical_json(item).encode("utf-8")).hexdigest()


def validate_evidence_item_hashes(
    repository_root: Path,
    evidence_items: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for item in evidence_items:
        current = build_evidence_item(repository_root, item)
        if _changed(item, current):
            changes.append(
                {
                    "evidence_id": item.get("evidence_id"),
                    "path": item.get("path"),
                    "previous_exists": item.get("exists"),
                    "current_exists": current.get("exists"),
                    "previous_sha256": item.get("sha256"),
                    "current_sha256": current.get("sha256"),
                    "change_type": _change_type(item, current),
                }
            )
    return changes


def content_type_for_path(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".md":
        return "text/markdown"
    if suffix == ".json":
        return "application/json"
    if suffix in {".txt", ".log"}:
        return "text/plain"
    return "application/octet-stream"


def normalise_evidence_path(path: str) -> str:
    return Path(path).as_posix().lstrip("./")


def _changed(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    return (
        previous.get("exists") != current.get("exists")
        or previous.get("sha256") != current.get("sha256")
        or previous.get("size_bytes") != current.get("size_bytes")
    )


def _change_type(previous: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    if previous.get("exists") is True and current.get("exists") is not True:
        return "MISSING_NOW"
    if previous.get("exists") is not True and current.get("exists") is True:
        return "APPEARED_NOW"
    if previous.get("sha256") != current.get("sha256"):
        return "HASH_CHANGED"
    if previous.get("size_bytes") != current.get("size_bytes"):
        return "SIZE_CHANGED"
    return "UNCHANGED"
