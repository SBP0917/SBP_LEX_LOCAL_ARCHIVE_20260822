from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from sbp_lex.security.pqc import generate_digest
from sbp_lex.supply_chain.assurance import (
    build_bundle,
    build_manifest_payload,
    validate_bundle,
    validate_manifest_payload,
)
from sbp_lex.supply_chain.common import SupplyChainError, seal, unseal
from sbp_lex.supply_chain.provenance import (
    EXPECTED_REPOSITORY_IDENTITY,
    _distribution,
    artifact_records,
    collect_build_provenance,
    collect_dependency_provenance,
    collect_repository_provenance,
    measured_linkage,
    normalize_repository_identity,
    validate_artifact_records,
    validate_build_provenance,
    validate_dependency_provenance,
    validate_repository_provenance,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def evidence(tmp_path_factory):
    target = tmp_path_factory.mktemp("r2")
    paths = {
        "sbom_path": target / "sbom.json",
        "manifest_path": target / "manifest.json",
        "verification_path": target / "verification.json",
    }
    result = build_bundle(ROOT, **paths)
    return target, paths, result


def resigned(payload):
    copied = copy.deepcopy(payload)
    copied["supply_chain_identity"] = generate_digest({k: v for k, v in copied.items() if k != "supply_chain_identity"})
    return copied


def repository_record():
    return collect_repository_provenance(ROOT)


def test_bundle_builds_and_validates_offline(evidence):
    _, paths, result = evidence
    assert result["status"] == "R2_SUPPLY_CHAIN_ASSURANCE_PASS"
    assert validate_bundle(ROOT, **paths)["status"] == "R2_SUPPLY_CHAIN_ASSURANCE_PASS"


def test_repository_identity_normalization():
    assert normalize_repository_identity("https://github.com/SBP0917/SBP_LEX_DUAL_V6.git") == EXPECTED_REPOSITORY_IDENTITY
    assert normalize_repository_identity("git@github.com:SBP0917/SBP_LEX_DUAL_V6.git") == EXPECTED_REPOSITORY_IDENTITY


def test_repository_provenance_is_valid():
    record = repository_record()
    validate_repository_provenance(record, ROOT)
    assert record["canonical_branch"] == "main"


def test_repository_provenance_is_deterministic():
    assert repository_record() == repository_record()


@pytest.mark.parametrize("field,value,reason", [
    ("repository_identity", "github.com/foreign/repository", "unknown_repository"),
    ("canonical_branch", "experimental", "noncanonical_branch"),
    ("parent_lineage", [], "detached_lineage"),
])
def test_repository_provenance_rejects_semantic_tamper(field, value, reason):
    record = repository_record()
    record[field] = value
    record["repository_digest"] = generate_digest({k: v for k, v in record.items() if k != "repository_digest"})
    with pytest.raises(SupplyChainError, match=reason):
        validate_repository_provenance(record, ROOT)


def test_repository_provenance_rejects_digest_corruption():
    record = repository_record(); record["repository_digest"] = "0" * 64
    with pytest.raises(SupplyChainError, match="repository_digest_mismatch"):
        validate_repository_provenance(record, ROOT)


def test_sbom_contains_direct_and_transitive_dependencies():
    sbom = collect_dependency_provenance(ROOT)
    assert sbom["direct_dependency_count"] == 2
    assert sbom["transitive_dependency_count"] >= 1
    assert {item["normalized_name"] for item in sbom["dependencies"]} >= {"pytest", "cryptography", "cffi"}


def test_sbom_is_deterministic():
    assert collect_dependency_provenance(ROOT) == collect_dependency_provenance(ROOT)


def test_dependency_records_include_required_provenance():
    sbom = collect_dependency_provenance(ROOT)
    for item in sbom["dependencies"]:
        assert item["version"] and item["source"] and item["licence"]
        assert len(item["distribution_sha256"]) == 64
        assert item["approval_status"] == item["integrity_status"] == "APPROVED" or item["integrity_status"] == "VERIFIED"


def test_dependency_digest_tamper_rejected():
    sbom = collect_dependency_provenance(ROOT); sbom["dependency_digest"] = "f" * 64
    with pytest.raises(SupplyChainError, match="dependency_digest_mismatch"):
        validate_dependency_provenance(sbom, verify_installed=False)


def test_duplicate_dependency_identity_rejected():
    sbom = collect_dependency_provenance(ROOT)
    sbom["dependencies"].append(copy.deepcopy(sbom["dependencies"][0]))
    core = {k: v for k, v in sbom.items() if k != "dependency_digest"}; sbom["dependency_digest"] = generate_digest(core)
    with pytest.raises(SupplyChainError, match="duplicate_dependency_identity"):
        validate_dependency_provenance(sbom, verify_installed=False)


def test_unapproved_dependency_rejected():
    sbom = collect_dependency_provenance(ROOT); sbom["dependencies"][0]["approval_status"] = "UNKNOWN"
    sbom["dependency_digest"] = generate_digest({k: v for k, v in sbom.items() if k != "dependency_digest"})
    with pytest.raises(SupplyChainError, match="dependency_unapproved"):
        validate_dependency_provenance(sbom, verify_installed=False)


def test_missing_dependency_rejected():
    with pytest.raises(SupplyChainError, match="missing_dependency"):
        _distribution("desktop-v1-package-that-does-not-exist")


def test_build_provenance_binds_runtime_and_baseline():
    repository = repository_record(); build = collect_build_provenance(ROOT, repository)
    assert build["runtime_identity"] == measured_linkage(ROOT)["runtime_identity"]
    assert build["measured_baseline_identifier"] == measured_linkage(ROOT)["measured_baseline_identifier"]


@pytest.mark.parametrize("field,reason", [
    ("runtime_identity", "runtime_identity_mismatch"),
    ("measured_baseline_identifier", "measured_baseline_identifier_mismatch"),
    ("repository_commit", "foreign_build"),
])
def test_build_link_tamper_rejected(field, reason):
    repository = repository_record(); build = collect_build_provenance(ROOT, repository)
    build[field] = "0" * (40 if field == "repository_commit" else 64)
    build["build_identity"] = generate_digest({k: v for k, v in build.items() if k != "build_identity"})
    with pytest.raises(SupplyChainError, match=reason):
        validate_build_provenance(build, ROOT, repository)


def test_artifact_records_hash_and_validate(tmp_path):
    (tmp_path / "a.txt").write_text("approved\n", encoding="utf-8")
    records = artifact_records(tmp_path, ["a.txt"])
    validate_artifact_records(records, tmp_path)


def test_artifact_substitution_rejected(tmp_path):
    path = tmp_path / "a.txt"; path.write_text("approved\n", encoding="utf-8")
    records = artifact_records(tmp_path, ["a.txt"]); path.write_text("substituted\n", encoding="utf-8")
    with pytest.raises(SupplyChainError, match="artifact_substitution"):
        validate_artifact_records(records, tmp_path)


def test_duplicate_artifact_identity_rejected(tmp_path):
    path = tmp_path / "a.txt"; path.write_text("approved\n", encoding="utf-8")
    records = artifact_records(tmp_path, ["a.txt"]); records.append(copy.deepcopy(records[0]))
    with pytest.raises(SupplyChainError, match="duplicate_artifact_identity"):
        validate_artifact_records(records, tmp_path)


def test_artifact_path_escape_rejected(tmp_path):
    with pytest.raises(SupplyChainError, match="escape"):
        artifact_records(tmp_path, ["../foreign.txt"])


def test_artifact_symlink_rejected(tmp_path):
    target = tmp_path / "target"; target.write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(SupplyChainError, match="symlink"):
        artifact_records(tmp_path, ["link"])


def test_manifest_payload_is_deterministic():
    sbom = collect_dependency_provenance(ROOT)
    assert build_manifest_payload(ROOT, sbom) == build_manifest_payload(ROOT, sbom)


def test_manifest_signature_corruption_rejected(evidence):
    target, _, _ = evidence
    manifest = json.loads((target / "manifest.json").read_text("utf-8")); manifest["payload_digest"] = "0" * 64
    with pytest.raises(SupplyChainError, match="manifest_digest_invalid"):
        unseal(manifest, label="r2_manifest")


def test_manifest_payload_corruption_rejected(evidence):
    target, _, _ = evidence
    manifest = json.loads((target / "manifest.json").read_text("utf-8")); manifest["payload"]["manifest_status"] = "UNKNOWN"
    with pytest.raises(SupplyChainError, match="manifest_digest_invalid"):
        unseal(manifest, label="r2_manifest")


def test_manifest_rejects_wrong_sbom_link(evidence):
    target, _, _ = evidence
    sbom = json.loads((target / "sbom.json").read_text("utf-8")); payload = unseal(json.loads((target / "manifest.json").read_text("utf-8")), label="r2_manifest")
    payload["dependency_digest"] = "0" * 64; payload = resigned(payload)
    with pytest.raises(SupplyChainError, match="sbom_link_mismatch"):
        validate_manifest_payload(payload, sbom, ROOT, verify_installed=False)


def test_manifest_rejects_stale_artifact(evidence):
    target, _, _ = evidence
    sbom = json.loads((target / "sbom.json").read_text("utf-8")); payload = unseal(json.loads((target / "manifest.json").read_text("utf-8")), label="r2_manifest")
    payload["artefact_inventory"][0]["sha256"] = "0" * 64; payload = resigned(payload)
    with pytest.raises(SupplyChainError, match="artifact_substitution"):
        validate_manifest_payload(payload, sbom, ROOT, verify_installed=False)


def test_manifest_rejects_validation_identity_tamper(evidence):
    target, _, _ = evidence
    sbom = json.loads((target / "sbom.json").read_text("utf-8")); payload = unseal(json.loads((target / "manifest.json").read_text("utf-8")), label="r2_manifest")
    payload["validation_identity"] = "0" * 64; payload = resigned(payload)
    with pytest.raises(SupplyChainError, match="validation_identity_mismatch"):
        validate_manifest_payload(payload, sbom, ROOT, verify_installed=False)


def test_manifest_contains_no_timestamp():
    payload = build_manifest_payload(ROOT, collect_dependency_provenance(ROOT))
    encoded = json.dumps(payload).lower()
    assert "created_at" not in encoded
    assert "build_time" not in encoded
    assert payload["canonical_payload_contains_timestamp"] is False
    assert payload["network_required_for_verification"] is False


def test_sealed_payload_round_trip():
    value = {"status": "approved", "sequence": 1}
    assert unseal(seal(value), label="test") == value


def test_unknown_provenance_fails_closed():
    payload = build_manifest_payload(ROOT, collect_dependency_provenance(ROOT))
    payload["repository_provenance"]["repository_identity"] = "unknown"
    payload["repository_provenance"]["repository_digest"] = generate_digest({k: v for k, v in payload["repository_provenance"].items() if k != "repository_digest"})
    payload = resigned(payload)
    with pytest.raises(SupplyChainError, match="unknown_repository"):
        validate_manifest_payload(payload, collect_dependency_provenance(ROOT), ROOT, verify_installed=False)


def test_offline_result_staleness_rejected(evidence):
    target, paths, _ = evidence
    verification = json.loads((target / "verification.json").read_text("utf-8"))
    payload = unseal(verification, label="r2_verification"); payload["manifest_digest"] = "0" * 64
    (target / "verification.json").write_text(json.dumps(seal(payload)), encoding="utf-8")
    with pytest.raises(SupplyChainError, match="offline_verification_result_stale"):
        validate_bundle(ROOT, **paths)


def test_sbom_uses_no_absolute_install_paths():
    sbom = collect_dependency_provenance(ROOT)
    encoded = json.dumps(sbom)
    assert str(Path.home()) not in encoded
    assert "site-packages" not in encoded


def test_dependency_order_is_stable():
    names = [item["normalized_name"] for item in collect_dependency_provenance(ROOT)["dependencies"]]
    assert names == sorted(names)


def test_transitive_dependencies_record_parentage():
    records = collect_dependency_provenance(ROOT)["dependencies"]
    transitive = [item for item in records if item["relationship"] == "TRANSITIVE"]
    assert transitive and all(item["required_by"] for item in transitive)


def test_artifact_order_is_stable(tmp_path):
    for name in ("z.txt", "a.txt", "m.txt"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    records = artifact_records(tmp_path, ["z.txt", "a.txt", "m.txt"])
    assert [item["path"] for item in records] == ["a.txt", "m.txt", "z.txt"]
