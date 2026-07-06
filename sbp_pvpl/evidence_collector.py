from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class LocalEvidenceEntry:
    evidence_id: str
    evidence_type: str
    path: str
    exists: bool
    size_bytes: int
    sha256_digest: str
    collected_at: str
    required: bool
    status: str


DEFAULT_EVIDENCE_TARGETS: tuple[tuple[str, str, str, bool], ...] = (
    ("runtime_artifacts", "directory", "runtime_artifacts", False),
    ("reports", "directory", "reports", True),
    ("university_validation_dossier", "directory", "outputs/university_validation_dossier", True),
    ("oda_02_support_bundle", "json", "runtime_artifacts/oda_02/support_bundle.json", False),
    ("pqc_report", "markdown", "reports/PQC_01_REAL_PROVIDER_CONTRACT_REPORT.md", False),
    ("oda_02_report", "markdown", "reports/ODA_02_EVIDENCE_GRADE_ONSITE_DEPLOYMENT_ASSISTANT_REPORT.md", False),
    ("replay_artifacts", "directory", "runtime_artifacts/replay", False),
    ("audit_integrity_store", "jsonl", "runtime_artifacts/integrity_store.jsonl", False),
)


def _hash_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _hash_directory(path: Path) -> str:
    files = sorted(item for item in path.rglob("*") if item.is_file() and not _is_volatile_output(item))
    digest = sha256()
    for item in files:
        rel = item.relative_to(path).as_posix().encode("utf-8")
        digest.update(rel)
        digest.update(b"\0")
        digest.update(_hash_file(item).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file() and not _is_volatile_output(item))


def _is_volatile_output(path: Path) -> bool:
    parts = set(path.parts)
    return "pvpl_02" in parts or "pytest_tmp_pvpl02" in " ".join(path.parts) or any(part.startswith("pytest_tmp") for part in parts)


def collect_evidence_entry(
    evidence_id: str,
    evidence_type: str,
    path: str | Path,
    *,
    required: bool,
    collected_at: str | None = None,
) -> LocalEvidenceEntry:
    target = Path(path)
    timestamp = collected_at or datetime.now(UTC).isoformat()
    if not target.exists():
        return LocalEvidenceEntry(evidence_id, evidence_type, str(target), False, 0, "MISSING", timestamp, required, "EVIDENCE_MISSING")
    try:
        if target.is_dir():
            size = _directory_size(target)
            status = "EVIDENCE_EMPTY" if size == 0 else "EVIDENCE_HASHED"
            return LocalEvidenceEntry(evidence_id, evidence_type, str(target), True, size, _hash_directory(target), timestamp, required, status)
        size = target.stat().st_size
        status = "EVIDENCE_EMPTY" if size == 0 else "EVIDENCE_HASHED"
        return LocalEvidenceEntry(evidence_id, evidence_type, str(target), True, size, _hash_file(target), timestamp, required, status)
    except OSError:
        return LocalEvidenceEntry(evidence_id, evidence_type, str(target), True, 0, "UNREADABLE", timestamp, required, "EVIDENCE_UNREADABLE")


def collect_local_evidence(runtime_root: str | Path = ".") -> list[dict[str, object]]:
    root = Path(runtime_root)
    timestamp = datetime.now(UTC).isoformat()
    return [
        asdict(collect_evidence_entry(evidence_id, evidence_type, root / relative_path, required=required, collected_at=timestamp))
        for evidence_id, evidence_type, relative_path, required in DEFAULT_EVIDENCE_TARGETS
    ]
