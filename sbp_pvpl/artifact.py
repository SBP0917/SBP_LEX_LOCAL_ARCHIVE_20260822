from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class ProofArtifact:
    artifact_id: str
    path: str
    exists: bool
    sha256: str
    size_bytes: int


def hash_file(path: str | Path) -> str:
    target = Path(path)
    return sha256(target.read_bytes()).hexdigest()


def inspect_proof_artifact(artifact_id: str, path: str | Path) -> ProofArtifact:
    target = Path(path)
    exists = target.exists() and target.is_file()
    return ProofArtifact(
        artifact_id=artifact_id,
        path=str(target),
        exists=exists,
        sha256=hash_file(target) if exists else "MISSING",
        size_bytes=target.stat().st_size if exists else 0,
    )
