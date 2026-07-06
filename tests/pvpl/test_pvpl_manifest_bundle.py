from sbp_pvpl.artifact import inspect_proof_artifact
from sbp_pvpl.bundle import build_proof_bundle, validate_proof_bundle
from sbp_pvpl.manifest import build_proof_manifest
from sbp_pvpl.status import PVPLStatus


def test_manifest_and_bundle_are_local_and_valid(tmp_path) -> None:
    path = tmp_path / "audit.json"
    path.write_text("{}", encoding="utf-8")
    manifest = build_proof_manifest([inspect_proof_artifact("audit", path)])
    bundle = build_proof_bundle(manifest)

    assert manifest.status == PVPLStatus.PROOF_OK
    assert bundle.runtime_authority == "NONE"
    assert bundle.proof_summary["publication_active"] is False
    assert validate_proof_bundle(bundle) == {"status": "PROOF_OK", "validation_failures": []}


def test_manifest_records_missing_evidence(tmp_path) -> None:
    manifest = build_proof_manifest([inspect_proof_artifact("missing", tmp_path / "missing.json")])

    assert manifest.status == PVPLStatus.PROOF_MISSING_EVIDENCE
