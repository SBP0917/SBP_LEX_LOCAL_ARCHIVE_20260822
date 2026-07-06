from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import json

from sbp_pvpl.digests import canonical_json_digest
from sbp_pvpl.manifest import ProofManifest, verify_manifest_digest
from sbp_pvpl.status import PVPLStatus


@dataclass(frozen=True)
class ProofBundle:
    bundle_type: str
    bundle_version: str
    created_at: str
    proof_manifest: ProofManifest
    evidence_snapshot: list[dict[str, Any]]
    reviewer_summary: dict[str, object]
    verification_instructions: list[str]
    boundary_statement: str
    bundle_payload_digest: str
    bundle_digest: str
    runtime_authority: str = "NONE"

    @property
    def manifest(self) -> ProofManifest:
        return self.proof_manifest

    @property
    def proof_summary(self) -> dict[str, object]:
        return self.reviewer_summary


def _payload_for_bundle_digest(bundle: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in bundle.items() if key != "bundle_digest"}


def _payload_for_bundle_payload_digest(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "proof_manifest": bundle.get("proof_manifest"),
        "evidence_snapshot": bundle.get("evidence_snapshot"),
        "reviewer_summary": bundle.get("reviewer_summary"),
        "boundary_statement": bundle.get("boundary_statement"),
    }


def build_proof_bundle(manifest: ProofManifest) -> ProofBundle:
    evidence = manifest.evidence_entries
    summary = {
        "evidence_count": len(evidence),
        "artifact_count": len(evidence),
        "missing_count": manifest.missing_evidence_count,
        "present_count": manifest.present_evidence_count,
        "publication_active": False,
        "runtime_attached": False,
        "runtime_authority": "NONE",
        "external_publication_target": "NONE",
        "blockchain_active": False,
        "ledger_active": False,
        "cloud_active": False,
        "certification_claimed": False,
    }
    draft = {
        "bundle_type": "PVPL_LOCAL_PROOF_BUNDLE",
        "bundle_version": "PVPL-02",
        "created_at": datetime.now(UTC).isoformat(),
        "proof_manifest": asdict(manifest),
        "evidence_snapshot": evidence,
        "reviewer_summary": summary,
        "verification_instructions": [
            "Run python -m sbp_pvpl.cli --verify-bundle --runtime-root . --bundle <bundle-path>.",
            "Review missing evidence entries before relying on the local proof package.",
            "Do not treat PVPL as runtime authority or external publication.",
        ],
        "boundary_statement": "PVPL is local/private, runtime-detached, publication-inactive, and non-authoritative.",
        "bundle_payload_digest": "",
        "bundle_digest": "",
        "runtime_authority": "NONE",
    }
    draft["bundle_payload_digest"] = canonical_json_digest(_payload_for_bundle_payload_digest(draft))
    draft["bundle_digest"] = canonical_json_digest(_payload_for_bundle_digest(draft))
    return ProofBundle(
        bundle_type=draft["bundle_type"],
        bundle_version=draft["bundle_version"],
        created_at=draft["created_at"],
        proof_manifest=manifest,
        evidence_snapshot=evidence,
        reviewer_summary=summary,
        verification_instructions=draft["verification_instructions"],
        boundary_statement=draft["boundary_statement"],
        bundle_payload_digest=draft["bundle_payload_digest"],
        bundle_digest=draft["bundle_digest"],
        runtime_authority="NONE",
    )


def bundle_to_dict(bundle: ProofBundle) -> dict[str, Any]:
    return asdict(bundle)


def write_proof_bundle(bundle: ProofBundle, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle_to_dict(bundle), indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def verify_bundle_digest(bundle: dict[str, Any]) -> bool:
    expected_payload = canonical_json_digest(_payload_for_bundle_payload_digest(bundle))
    if bundle.get("bundle_payload_digest") != expected_payload:
        return False
    return bundle.get("bundle_digest") == canonical_json_digest(_payload_for_bundle_digest(bundle))


def validate_proof_bundle(bundle: ProofBundle | dict[str, Any]) -> dict[str, object]:
    payload = bundle_to_dict(bundle) if isinstance(bundle, ProofBundle) else bundle
    failures: list[str] = []
    if payload.get("runtime_authority") != "NONE":
        failures.append("runtime_authority_not_none")
    summary = payload.get("reviewer_summary") or payload.get("proof_summary") or {}
    manifest = payload.get("proof_manifest") or payload.get("manifest") or {}
    if summary.get("runtime_attached") is not False:
        failures.append("runtime_attached_not_false")
    for field in ("publication_active", "blockchain_active", "ledger_active", "cloud_active"):
        if summary.get(field) is not False or manifest.get(field) is not False:
            failures.append(f"{field}_not_false")
    if summary.get("external_publication_target", "NONE") != "NONE" or manifest.get("external_publication_target", "NONE") != "NONE":
        failures.append("external_publication_target_not_none")
    if not verify_manifest_digest(manifest):
        failures.append("manifest_digest_invalid")
    if "bundle_digest" in payload and not verify_bundle_digest(payload):
        failures.append("bundle_digest_invalid")
    if failures:
        status = PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY if any("not_false" in item or "not_none" in item for item in failures) else PVPLStatus.PROOF_INVALID
    else:
        status = PVPLStatus.PROOF_OK
    return {"status": status.value, "validation_failures": failures}
