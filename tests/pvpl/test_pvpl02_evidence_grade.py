import json
import subprocess
import sys

from sbp_pvpl.boundary_checker import run_boundary_check
from sbp_pvpl.bundle import build_proof_bundle, bundle_to_dict, verify_bundle_digest, write_proof_bundle
from sbp_pvpl.evidence_collector import collect_evidence_entry
from sbp_pvpl.manifest import build_proof_manifest, verify_manifest_digest
from sbp_pvpl.report_writer import write_proof_report
from sbp_pvpl.status import PVPLStatus
from sbp_pvpl.verifier import verify_local_proof_bundle, verify_local_proof_bundle_file


def test_evidence_collector_hashes_present_records_missing_and_empty(tmp_path) -> None:
    present = tmp_path / "present.txt"
    present.write_text("evidence", encoding="utf-8")
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")

    present_entry = collect_evidence_entry("present", "text", present, required=True)
    empty_entry = collect_evidence_entry("empty", "text", empty, required=False)
    missing_entry = collect_evidence_entry("missing", "text", tmp_path / "missing.txt", required=True)

    assert present_entry.status == "EVIDENCE_HASHED"
    assert present_entry.sha256_digest != "MISSING"
    assert empty_entry.status == "EVIDENCE_EMPTY"
    assert missing_entry.status == "EVIDENCE_MISSING"
    assert missing_entry.exists is False


def test_manifest_digest_and_boundary_fields(tmp_path) -> None:
    evidence = tmp_path / "proof.txt"
    evidence.write_text("proof", encoding="utf-8")
    entry = collect_evidence_entry("proof", "text", evidence, required=True)
    manifest = build_proof_manifest(evidence_entries=[entry.__dict__], runtime_root=tmp_path)
    payload = manifest.__dict__.copy()

    assert manifest.manifest_type == "PVPL_LOCAL_PROOF_MANIFEST"
    assert manifest.runtime_authority == "NONE"
    assert manifest.publication_active is False
    assert manifest.blockchain_active is False
    assert manifest.ledger_active is False
    assert manifest.cloud_active is False
    assert verify_manifest_digest(payload) is True
    payload["publication_active"] = True
    assert verify_manifest_digest(payload) is False


def test_bundle_digest_and_tamper_detection(tmp_path) -> None:
    evidence = tmp_path / "proof.txt"
    evidence.write_text("proof", encoding="utf-8")
    manifest = build_proof_manifest(evidence_entries=[collect_evidence_entry("proof", "text", evidence, required=True).__dict__], runtime_root=tmp_path)
    bundle = build_proof_bundle(manifest)
    payload = bundle_to_dict(bundle)

    assert payload["bundle_type"] == "PVPL_LOCAL_PROOF_BUNDLE"
    assert verify_bundle_digest(payload) is True
    payload["reviewer_summary"]["present_count"] = 0
    assert verify_bundle_digest(payload) is False
    assert verify_local_proof_bundle(payload, tmp_path)["status"] == PVPLStatus.PROOF_TAMPER_DETECTED


def test_changed_evidence_after_bundle_creation_detected(tmp_path) -> None:
    evidence = tmp_path / "proof.txt"
    evidence.write_text("proof", encoding="utf-8")
    manifest = build_proof_manifest(evidence_entries=[collect_evidence_entry("proof", "text", evidence, required=True).__dict__], runtime_root=tmp_path)
    bundle = build_proof_bundle(manifest)
    evidence.write_text("changed", encoding="utf-8")

    result = verify_local_proof_bundle(bundle_to_dict(bundle), tmp_path)

    assert result["status"] == PVPLStatus.PROOF_TAMPER_DETECTED
    assert result["tampered_evidence"] == ["proof"]


def test_missing_required_evidence_returns_incomplete(tmp_path) -> None:
    manifest = build_proof_manifest(
        evidence_entries=[collect_evidence_entry("missing", "text", tmp_path / "missing.txt", required=True).__dict__],
        runtime_root=tmp_path,
    )
    bundle = build_proof_bundle(manifest)

    result = verify_local_proof_bundle(bundle_to_dict(bundle), tmp_path)

    assert result["status"] == PVPLStatus.PROOF_INCOMPLETE


def test_forbidden_publication_activation_is_blocked(tmp_path) -> None:
    evidence = tmp_path / "proof.txt"
    evidence.write_text("proof", encoding="utf-8")
    manifest = build_proof_manifest(evidence_entries=[collect_evidence_entry("proof", "text", evidence, required=True).__dict__], runtime_root=tmp_path)
    payload = bundle_to_dict(build_proof_bundle(manifest))
    payload["reviewer_summary"]["publication_active"] = True

    result = verify_local_proof_bundle(payload, tmp_path)

    assert result["status"] == PVPLStatus.PROOF_BLOCKED_RUNTIME_BOUNDARY


def test_report_writer_outputs_markdown_without_external_publication_claim(tmp_path) -> None:
    evidence = tmp_path / "proof.txt"
    evidence.write_text("proof", encoding="utf-8")
    manifest = build_proof_manifest(evidence_entries=[collect_evidence_entry("proof", "text", evidence, required=True).__dict__], runtime_root=tmp_path)
    bundle_path = write_proof_bundle(build_proof_bundle(manifest), tmp_path / "bundle.json")
    report_path = write_proof_report(bundle_path, tmp_path / "proof_report.md", tmp_path)
    text = report_path.read_text(encoding="utf-8")

    assert "Evidence count" in text
    assert "runtime-detached" in text
    assert "does not claim external publication" in text


def test_boundary_checker_confirms_detachment() -> None:
    result = run_boundary_check(".")

    assert result["status"] == PVPLStatus.PROOF_OK
    assert result["findings"] == []


def test_cli_build_verify_and_report(tmp_path) -> None:
    bundle = tmp_path / "proof_bundle.json"
    report = tmp_path / "proof_report.md"
    build = subprocess.run(
        [sys.executable, "-m", "sbp_pvpl.cli", "--build-bundle", "--runtime-root", ".", "--out", str(bundle)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    verify = subprocess.run(
        [sys.executable, "-m", "sbp_pvpl.cli", "--verify-bundle", "--runtime-root", ".", "--bundle", str(bundle)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    write = subprocess.run(
        [sys.executable, "-m", "sbp_pvpl.cli", "--write-report", "--runtime-root", ".", "--bundle", str(bundle), "--out", str(report)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert build.returncode == 0
    assert bundle.exists()
    assert json.loads(verify.stdout)["status"] in {PVPLStatus.PROOF_OK, PVPLStatus.PROOF_INCOMPLETE}
    assert write.returncode == 0
    assert report.exists()
