from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from sbp_pvpl.bundle import validate_proof_bundle
from sbp_pvpl.evidence_collector import collect_evidence_entry
from sbp_pvpl.status import PVPLStatus


def load_bundle(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_local_proof_bundle(bundle: dict[str, Any], runtime_root: str | Path = ".") -> dict[str, object]:
    structural = validate_proof_bundle(bundle)
    failures = list(structural["validation_failures"])
    root = Path(runtime_root)
    manifest = bundle.get("proof_manifest", {})
    entries = manifest.get("evidence_entries", [])
    required_missing = []
    tampered = []
    for entry in entries:
        path = Path(entry.get("path", ""))
        current = collect_evidence_entry(
            str(entry.get("evidence_id", "unknown")),
            str(entry.get("evidence_type", "unknown")),
            path if path.is_absolute() else root / path,
            required=bool(entry.get("required")),
            collected_at=str(entry.get("collected_at", "")) or None,
        )
        if entry.get("required") is True and not current.exists:
            required_missing.append(entry.get("evidence_id"))
        if current.exists and entry.get("exists") is True and current.sha256_digest != entry.get("sha256_digest"):
            tampered.append(entry.get("evidence_id"))
    if required_missing:
        failures.extend(f"required_evidence_missing:{item}" for item in required_missing)
    if tampered:
        failures.extend(f"evidence_digest_mismatch:{item}" for item in tampered)

    if any(item.endswith("_not_false") or item.endswith("_not_none") for item in failures):
        status = PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY
    elif any("digest" in item or "tamper" in item for item in failures):
        status = PVPLStatus.PROOF_TAMPER_DETECTED
    elif required_missing or manifest.get("required_evidence_summary", {}).get("required_missing_count", 0):
        status = PVPLStatus.PROOF_INCOMPLETE
    elif failures:
        status = PVPLStatus.PROOF_INVALID
    else:
        status = PVPLStatus.PROOF_OK
    return {
        "status": status.value,
        "validation_failures": sorted(set(failures)),
        "required_missing": required_missing,
        "tampered_evidence": tampered,
    }


def verify_local_proof_bundle_file(bundle_path: str | Path, runtime_root: str | Path = ".") -> dict[str, object]:
    return verify_local_proof_bundle(load_bundle(bundle_path), runtime_root)
