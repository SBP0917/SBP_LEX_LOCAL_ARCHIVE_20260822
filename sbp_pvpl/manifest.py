from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sbp_pvpl.artifact import ProofArtifact
from sbp_pvpl.constants import PVPL_EVIDENCE_VERSION
from sbp_pvpl.digests import canonical_json_digest
from sbp_pvpl.evidence_collector import collect_local_evidence
from sbp_pvpl.status import PVPLStatus


@dataclass(frozen=True)
class ProofManifest:
    manifest_type: str
    manifest_version: str
    created_at: str
    repository_root: str
    evidence_scope: str
    evidence_entries: list[dict[str, Any]] = field(default_factory=list)
    required_evidence_summary: dict[str, int] = field(default_factory=dict)
    missing_evidence_count: int = 0
    present_evidence_count: int = 0
    proof_policy: dict[str, object] = field(default_factory=dict)
    runtime_authority: str = "NONE"
    publication_active: bool = False
    external_publication_target: str = "NONE"
    blockchain_active: bool = False
    ledger_active: bool = False
    cloud_active: bool = False
    manifest_payload_digest: str = ""
    manifest_digest: str = ""
    signature_mode: str = "PVPL_LOCAL_DIGEST_ONLY"
    status: PVPLStatus = PVPLStatus.PROOF_OK

    @property
    def artifacts(self) -> list[dict[str, Any]]:
        return self.evidence_entries


def _entry_from_artifact(artifact: ProofArtifact) -> dict[str, object]:
    status = "EVIDENCE_HASHED" if artifact.exists and artifact.size_bytes > 0 else "EVIDENCE_EMPTY" if artifact.exists else "EVIDENCE_MISSING"
    return {
        "evidence_id": artifact.artifact_id,
        "evidence_type": "legacy_proof_artifact",
        "path": artifact.path,
        "exists": artifact.exists,
        "size_bytes": artifact.size_bytes,
        "sha256_digest": artifact.sha256,
        "collected_at": datetime.now(UTC).isoformat(),
        "required": True,
        "status": status,
    }


def _summary(entries: list[dict[str, Any]]) -> dict[str, int]:
    required = [entry for entry in entries if entry.get("required") is True]
    return {
        "required_count": len(required),
        "required_present_count": sum(1 for entry in required if entry.get("exists") is True),
        "required_missing_count": sum(1 for entry in required if entry.get("exists") is not True),
    }


def _payload_for_manifest_digest(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "manifest_digest"}


def _payload_for_policy_digest(entries: list[dict[str, Any]], proof_policy: dict[str, object]) -> dict[str, object]:
    return {"evidence_entries": entries, "proof_policy": proof_policy}


def build_proof_manifest(
    artifacts: list[ProofArtifact] | None = None,
    *,
    runtime_root: str | Path = ".",
    evidence_entries: list[dict[str, Any]] | None = None,
) -> ProofManifest:
    root = Path(runtime_root).resolve()
    entries = evidence_entries if evidence_entries is not None else (
        [_entry_from_artifact(artifact) for artifact in artifacts] if artifacts is not None else collect_local_evidence(root)
    )
    summary = _summary(entries)
    missing = sum(1 for entry in entries if entry.get("exists") is not True or entry.get("status") == "EVIDENCE_MISSING")
    present = sum(1 for entry in entries if entry.get("exists") is True)
    proof_policy = {
        "local_private_only": True,
        "external_publication_allowed": False,
        "runtime_authority": "NONE",
        "blockchain_allowed": False,
        "ledger_allowed": False,
        "cloud_allowed": False,
        "certification_claimed": False,
    }
    if summary["required_missing_count"] == 0:
        status = PVPLStatus.PROOF_OK
    elif artifacts is not None and evidence_entries is None:
        status = PVPLStatus.PROOF_MISSING_EVIDENCE
    else:
        status = PVPLStatus.PROOF_INCOMPLETE
    draft = ProofManifest(
        manifest_type="PVPL_LOCAL_PROOF_MANIFEST",
        manifest_version=PVPL_EVIDENCE_VERSION,
        created_at=datetime.now(UTC).isoformat(),
        repository_root=str(root),
        evidence_scope="local_private_reviewer_evidence",
        evidence_entries=entries,
        required_evidence_summary=summary,
        missing_evidence_count=missing,
        present_evidence_count=present,
        proof_policy=proof_policy,
        status=status,
    )
    payload = asdict(draft)
    payload["manifest_payload_digest"] = canonical_json_digest(_payload_for_policy_digest(entries, proof_policy))
    payload["manifest_digest"] = canonical_json_digest(_payload_for_manifest_digest(payload))
    return replace(draft, manifest_payload_digest=payload["manifest_payload_digest"], manifest_digest=payload["manifest_digest"])


def verify_manifest_digest(manifest: dict[str, Any]) -> bool:
    expected_payload = canonical_json_digest(_payload_for_policy_digest(manifest.get("evidence_entries", []), manifest.get("proof_policy", {})))
    if manifest.get("manifest_payload_digest") != expected_payload:
        return False
    return manifest.get("manifest_digest") == canonical_json_digest(_payload_for_manifest_digest(manifest))
