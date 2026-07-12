from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sbp_lex.custody.common import seal as seal_r3, unseal as unseal_r3
from sbp_lex.ivvp.common import IVVPError, file_sha256, read_json, seal, unseal, write_json
from sbp_lex.ivvp.package import _claims, _commands, _identity, _package_file_inventory, _traceability, build_package
from sbp_lex.ivvp.verifier import verify_package
from sbp_lex.security.pqc import generate_digest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = {
    "evidence_version": "R4_DESKTOP_V1_IVVP_V1", "runtime_result": "PASS",
    "runtime_decision": "ALLOW", "execution_result": "EXECUTE",
    "convergence_matched": True, "runtime_output_digest": "a" * 64,
    "replay_result": "PASS", "replay_count": 2, "replay_matched": True,
    "replay_mismatches": 0, "replay_output_digest": "b" * 64,
}


@pytest.fixture(scope="module")
def package(tmp_path_factory):
    path = tmp_path_factory.mktemp("r4") / "validation_package"
    build_package(ROOT, path, runtime_evidence=RUNTIME)
    return path


def clone(package: Path, tmp_path: Path) -> Path:
    target = tmp_path / "package"; shutil.copytree(package, target); return target


def resign_package(path: Path, *, refresh_evidence=False):
    identity = read_json(path / "REPOSITORY_IDENTITY.json", label="identity")
    claims = read_json(path / "ENGINEERING_CLAIMS_REGISTER.json", label="claims")
    trace = read_json(path / "EVIDENCE_TRACEABILITY_INDEX.json", label="trace")
    inventory = read_json(path / "EVIDENCE_INVENTORY.json", label="inventory")
    if refresh_evidence:
        for record in inventory["evidence"]:
            item = path / record["package_path"]; record["sha256"] = file_sha256(item); record["size_bytes"] = item.stat().st_size
        inventory["evidence_inventory_digest"] = generate_digest({"evidence": inventory["evidence"]}); write_json(path / "EVIDENCE_INVENTORY.json", inventory)
    manifest = unseal(read_json(path / "PACKAGE_MANIFEST.json", label="manifest"), label="package_manifest")
    manifest.update({"repository_commit": identity["repository_commit"], "git_tree_identity": identity["git_tree_identity"], "measured_baseline_identifier": identity["measured_baseline_identifier"], "runtime_identity": identity["runtime_identity"], "identity_digest": identity["identity_digest"], "claims_digest": claims["claims_digest"], "traceability_digest": trace["traceability_digest"], "evidence_inventory_digest": inventory["evidence_inventory_digest"]})
    manifest["package_files"] = _package_file_inventory(path)
    manifest["package_identity"] = generate_digest({k: v for k, v in manifest.items() if k != "package_identity"})
    write_json(path / "PACKAGE_MANIFEST.json", seal(manifest))


def test_package_builds_and_verifies(package):
    assert verify_package(package, repository_root=ROOT)["status"] == "R4_IVVP_VALID"


def test_package_contains_required_assessor_documents(package):
    required = {"REPOSITORY_IDENTITY.json", "ENGINEERING_CLAIMS_REGISTER.json", "EVIDENCE_TRACEABILITY_INDEX.json", "INDEPENDENT_VERIFICATION_GUIDE.md", "QUICK_START.md", "VERIFICATION_COMMANDS.json", "VALIDATION_SUMMARY.md", "EVIDENCE_INVENTORY.json", "PACKAGE_MANIFEST.json"}
    assert required.issubset({item.name for item in package.iterdir()})


def test_repository_identity_matches_canonical_state():
    identity = _identity(ROOT)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    assert identity["repository_commit"] == head
    assert identity["canonical_designation"] == "SBP_LEX_DUAL_V6_DESKTOP_V1"


def test_identity_is_deterministic():
    assert _identity(ROOT) == _identity(ROOT)


def test_claims_are_deterministic():
    identity = _identity(ROOT); assert _claims(identity) == _claims(identity)


def test_claims_have_complete_traceability():
    claims = _claims(_identity(ROOT))["claims"]
    assert claims and all(item["supporting_reports"] and item["supporting_tests"] and item["evidence_status"] == "SUPPORTED" for item in claims)


def test_claim_identifiers_are_unique():
    identifiers = [item["claim_identifier"] for item in _claims(_identity(ROOT))["claims"]]
    assert len(identifiers) == len(set(identifiers))


def test_traceability_covers_major_layers():
    layers = {item["assurance_layer"] for item in _traceability(_identity(ROOT))["evidence_items"]}
    assert {"H7", "PHQ", "R1", "R2", "R3", "LOCAL_TRUST", "CONSTITUTIONAL_GATES", "TOOLCHAIN_GUARD", "RELEASE_INTEGRITY", "CAPSTONE", "RUNTIME_REPLAY"} == layers


def test_verification_commands_are_non_mutating():
    assert all(item["mutates_tracked_repository_state"] is False for item in _commands()["commands"])


def test_package_payload_is_deterministic(tmp_path):
    first = tmp_path / "first"; second = tmp_path / "second"
    build_package(ROOT, first, runtime_evidence=RUNTIME); build_package(ROOT, second, runtime_evidence=RUNTIME)
    a = unseal(read_json(first / "PACKAGE_MANIFEST.json", label="manifest"), label="package_manifest")
    b = unseal(read_json(second / "PACKAGE_MANIFEST.json", label="manifest"), label="package_manifest")
    assert a == b


def test_missing_evidence_rejected(package, tmp_path):
    target = clone(package, tmp_path); (target / "evidence/outputs/r1_recovery_drill.json").unlink()
    with pytest.raises(IVVPError, match="missing_package_file"): verify_package(target)


def test_substituted_evidence_rejected(package, tmp_path):
    target = clone(package, tmp_path); (target / "evidence/outputs/r1_recovery_drill.json").write_text("{}", encoding="utf-8")
    with pytest.raises(IVVPError, match="substituted_package_file"): verify_package(target)


def test_unexpected_package_file_rejected(package, tmp_path):
    target = clone(package, tmp_path); (target / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(IVVPError, match="unexpected_package_file"): verify_package(target)


def test_corrupt_manifest_rejected(package, tmp_path):
    target = clone(package, tmp_path); value = read_json(target / "PACKAGE_MANIFEST.json", label="manifest"); value["payload_digest"] = "0" * 64; write_json(target / "PACKAGE_MANIFEST.json", value)
    with pytest.raises(IVVPError, match="package_manifest_digest_invalid"): verify_package(target)


def test_foreign_identity_rejected(package, tmp_path):
    target = clone(package, tmp_path); identity = read_json(target / "REPOSITORY_IDENTITY.json", label="identity"); identity["repository_identity"] = "foreign/repository"; identity["identity_digest"] = generate_digest({k: v for k, v in identity.items() if k != "identity_digest"}); write_json(target / "REPOSITORY_IDENTITY.json", identity); resign_package(target)
    with pytest.raises(IVVPError, match="foreign_repository_identity"): verify_package(target)


def test_stale_runtime_identity_rejected(package, tmp_path):
    target = clone(package, tmp_path); identity = read_json(target / "REPOSITORY_IDENTITY.json", label="identity"); identity["runtime_identity"] = "0" * 64; identity["identity_digest"] = generate_digest({k: v for k, v in identity.items() if k != "identity_digest"}); write_json(target / "REPOSITORY_IDENTITY.json", identity)
    claims = read_json(target / "ENGINEERING_CLAIMS_REGISTER.json", label="claims"); claims["runtime_identity"] = identity["runtime_identity"]; write_json(target / "ENGINEERING_CLAIMS_REGISTER.json", claims)
    trace = read_json(target / "EVIDENCE_TRACEABILITY_INDEX.json", label="trace"); trace["runtime_identity"] = identity["runtime_identity"]; write_json(target / "EVIDENCE_TRACEABILITY_INDEX.json", trace)
    inventory = read_json(target / "EVIDENCE_INVENTORY.json", label="inventory"); inventory["runtime_identity"] = identity["runtime_identity"]; write_json(target / "EVIDENCE_INVENTORY.json", inventory); resign_package(target)
    with pytest.raises(IVVPError, match="stale_measured_identity"): verify_package(target)


def test_stale_r3_evidence_rejected(package, tmp_path):
    target = clone(package, tmp_path); path = target / "evidence/outputs/r3_operational_custody_assurance.json"; payload = unseal_r3(read_json(path, label="r3"), label="custody_assurance_profile"); payload["runtime_identity"] = "0" * 64; payload["profile_digest"] = generate_digest({k: v for k, v in payload.items() if k != "profile_digest"}); write_json(path, seal_r3(payload)); resign_package(target, refresh_evidence=True)
    with pytest.raises(IVVPError, match="stale_r3_evidence"): verify_package(target)


def test_broken_report_link_rejected(package, tmp_path):
    target = clone(package, tmp_path); claims = read_json(target / "ENGINEERING_CLAIMS_REGISTER.json", label="claims"); claims["claims"][0]["supporting_reports"] = ["MISSING_REPORT.md"]; claims["claims_digest"] = generate_digest({"claims": claims["claims"]}); write_json(target / "ENGINEERING_CLAIMS_REGISTER.json", claims); resign_package(target)
    with pytest.raises(IVVPError, match="broken_report_link"): verify_package(target)


def test_broken_traceability_rejected(package, tmp_path):
    target = clone(package, tmp_path); trace = read_json(target / "EVIDENCE_TRACEABILITY_INDEX.json", label="trace"); trace["evidence_items"][0]["current_status"] = "UNKNOWN"; trace["traceability_digest"] = generate_digest({"evidence_items": trace["evidence_items"]}); write_json(target / "EVIDENCE_TRACEABILITY_INDEX.json", trace); resign_package(target)
    with pytest.raises(IVVPError, match="broken_traceability"): verify_package(target)


def test_runtime_failure_evidence_rejected(package, tmp_path):
    target = clone(package, tmp_path); runtime = read_json(target / "RUNTIME_REPLAY_EVIDENCE.json", label="runtime"); runtime["runtime_result"] = "FAIL"; write_json(target / "RUNTIME_REPLAY_EVIDENCE.json", runtime); resign_package(target)
    with pytest.raises(IVVPError, match="runtime_replay_evidence_failed"): verify_package(target)


def test_command_mutation_flag_rejected(package, tmp_path):
    target = clone(package, tmp_path); commands = read_json(target / "VERIFICATION_COMMANDS.json", label="commands"); commands["commands"][0]["mutates_tracked_repository_state"] = True; commands["command_pack_digest"] = generate_digest({"commands": commands["commands"]}); write_json(target / "VERIFICATION_COMMANDS.json", commands); resign_package(target)
    with pytest.raises(IVVPError, match="verification_command_pack_invalid"): verify_package(target)


def test_package_contains_no_source_code(package):
    assert not any(path.suffix == ".py" for path in (package / "evidence").rglob("*"))


def test_quick_start_is_bounded(package):
    text = (package / "QUICK_START.md").read_text("utf-8")
    assert "10-20 minutes" in text and "R4_IVVP_VALID" in text


def test_summary_disclaims_certification(package):
    assert "no certification" in (package / "VALIDATION_SUMMARY.md").read_text("utf-8").lower()


def test_inventory_identifiers_are_deterministic(package):
    records = read_json(package / "EVIDENCE_INVENTORY.json", label="inventory")["evidence"]
    identifiers = [item["evidence_identifier"] for item in records]
    assert len(identifiers) == len(set(identifiers))


def test_all_documents_share_identity(package):
    identity = read_json(package / "REPOSITORY_IDENTITY.json", label="identity")
    for name in ("INDEPENDENT_VERIFICATION_GUIDE.md", "QUICK_START.md", "VALIDATION_SUMMARY.md"):
        text = (package / name).read_text("utf-8")
        assert identity["repository_commit"] in text and identity["measured_baseline_identifier"] in text and identity["runtime_identity"] in text
