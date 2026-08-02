from __future__ import annotations

import copy
import json
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest

import sbp_lex.supply_chain.provenance as provenance_module
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
    PRODUCTION_TRUSTED_REPOSITORY_ANCHOR_COMMIT,
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


def test_r2_contract_schemas_are_closed_and_match_generated_evidence(
    evidence,
):
    target, _, _ = evidence
    sbom = json.loads((target / "sbom.json").read_text("utf-8"))
    manifest = unseal(
        json.loads((target / "manifest.json").read_text("utf-8")),
        label="r2_manifest",
    )
    sbom_schema = json.loads(
        (
            ROOT
            / "sbp_lex/supply_chain/schemas/r2_sbom.schema.json"
        ).read_text("utf-8")
    )
    manifest_schema = json.loads(
        (
            ROOT
            / "sbp_lex/supply_chain/schemas/r2_build_manifest.schema.json"
        ).read_text("utf-8")
    )
    assert sbom_schema["additionalProperties"] is False
    assert set(sbom) == set(sbom_schema["required"])
    assert set(sbom["dependencies"][0]) == set(
        sbom_schema["$defs"]["dependency"]["required"]
    )
    payload_schema = manifest_schema["properties"]["payload"]
    assert payload_schema["additionalProperties"] is False
    assert set(manifest) == set(payload_schema["required"])
    assert set(manifest["repository_provenance"]) == set(
        manifest_schema["$defs"]["repository"]["required"]
    )
    assert set(manifest["build_provenance"]) == set(
        manifest_schema["$defs"]["build"]["required"]
    )
    assert set(manifest["artefact_inventory"][0]) == set(
        manifest_schema["$defs"]["artefact"]["required"]
    )


def test_repository_identity_normalization():
    assert normalize_repository_identity("https://github.com/SBP0917/SBP_LEX_DUAL_V6.git") == EXPECTED_REPOSITORY_IDENTITY
    assert normalize_repository_identity("git@github.com:SBP0917/SBP_LEX_DUAL_V6.git") == EXPECTED_REPOSITORY_IDENTITY


def test_repository_provenance_is_valid():
    record = repository_record()
    validate_repository_provenance(record, ROOT)
    assert record["canonical_branch"] == "main"


def test_repository_provenance_is_deterministic():
    assert repository_record() == repository_record()


@pytest.mark.parametrize("bounded", [True, False])
def test_repository_provenance_requires_bounded_evidence_recording_lineage(
    tmp_path,
    monkeypatch,
    bounded,
):
    source_commit = "a" * 40
    current_commit = "b" * 40
    repository_tree = "c" * 40
    anchor_tree = "d" * 40
    anchor = provenance_module.TRUSTED_REPOSITORY_ANCHOR_COMMIT
    record = {
        "provenance_version": provenance_module.R2_VERSION,
        "desktop_scope": provenance_module.DESKTOP_SCOPE,
        "repository_identity": EXPECTED_REPOSITORY_IDENTITY,
        "canonical_branch": "main",
        "repository_commit": source_commit,
        "repository_tree": repository_tree,
        "parent_lineage": [source_commit],
        "lineage_depth_recorded": 1,
        "trusted_repository_anchor_commit": anchor,
        "trusted_repository_anchor_tree": anchor_tree,
        "upstream_reference": provenance_module.CANONICAL_UPSTREAM,
        "tracked_working_tree_clean": True,
        "untracked_files_checked": True,
        "origin_kind": "canonical_origin",
    }
    record["repository_digest"] = generate_digest(record)

    responses = {
        ("remote", "get-url", "origin"):
            "https://github.com/SBP0917/SBP_LEX_DUAL_V6.git",
        ("branch", "--show-current"): "main",
        (
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ): "",
        (
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ): provenance_module.CANONICAL_UPSTREAM,
        (
            "merge-base",
            "--is-ancestor",
            anchor,
            source_commit,
        ): "",
        ("rev-parse", f"{anchor}^{{tree}}"): anchor_tree,
        (
            "merge-base",
            "--is-ancestor",
            source_commit,
            "HEAD",
        ): "",
        ("rev-parse", "HEAD"): current_commit,
        ("rev-parse", f"{source_commit}^{{tree}}"): repository_tree,
    }
    monkeypatch.setattr(
        provenance_module,
        "_git",
        lambda root, *args: responses[args],
    )
    calls = []
    monkeypatch.setattr(
        provenance_module,
        "generated_evidence_lineage_is_bounded",
        lambda root, recorded, *, current_commit: (
            calls.append((root, recorded, current_commit)) or bounded
        ),
    )

    if bounded:
        validate_repository_provenance(record, tmp_path)
    else:
        with pytest.raises(
            SupplyChainError,
            match="repository_head_mismatch",
        ):
            validate_repository_provenance(record, tmp_path)
    assert calls == [(tmp_path, source_commit, current_commit)]


def test_production_repository_anchor_is_explicit_and_fixed():
    assert PRODUCTION_TRUSTED_REPOSITORY_ANCHOR_COMMIT == (
        "1f6d63422aeab848a8d4f26a6f8a46e3125c780a"
    )


def test_repository_provenance_rejects_untracked_execution_surface(
    tmp_path, monkeypatch,
):
    anchor = provenance_module.TRUSTED_REPOSITORY_ANCHOR_COMMIT
    calls = []

    def fake_git(root, *args):
        del root
        calls.append(args)
        responses = {
            ("rev-parse", "HEAD"): "a" * 40,
            ("branch", "--show-current"): "main",
            ("remote", "get-url", "origin"):
                "https://github.com/SBP0917/SBP_LEX_DUAL_V6.git",
            ("rev-parse", "HEAD^{tree}"): "b" * 40,
            ("rev-parse", f"{anchor}^{{tree}}"): "c" * 40,
            (
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{upstream}",
            ): "origin/main",
            (
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ): "?? sitecustomize.py",
        }
        return responses[args]

    monkeypatch.setattr(provenance_module, "_git", fake_git)
    with pytest.raises(
        SupplyChainError, match="tracked_working_tree_dirty",
    ):
        collect_repository_provenance(tmp_path)
    assert (
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ) in calls


def test_repository_provenance_requires_untracked_file_check():
    record = repository_record()
    record.pop("untracked_files_checked")
    record["repository_digest"] = generate_digest({
        key: value
        for key, value in record.items()
        if key != "repository_digest"
    })
    with pytest.raises(
        SupplyChainError, match="repository_provenance_schema_invalid",
    ):
        validate_repository_provenance(record, ROOT)


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
    assert sbom["direct_dependency_count"] == 3
    assert sbom["transitive_dependency_count"] >= 1
    assert {
        item["normalized_name"] for item in sbom["dependencies"]
    } >= {"pytest", "cryptography", "packaging", "cffi"}


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


def test_dependency_unknown_field_rejected():
    sbom = collect_dependency_provenance(ROOT)
    sbom["dependencies"][0]["undeclared_semantics"] = True
    sbom["dependency_digest"] = generate_digest({
        key: value
        for key, value in sbom.items()
        if key != "dependency_digest"
    })
    with pytest.raises(
        SupplyChainError, match="dependency_record_schema_invalid",
    ):
        validate_dependency_provenance(sbom, verify_installed=False)


def test_duplicate_dependency_identity_rejected():
    sbom = collect_dependency_provenance(ROOT)
    sbom["dependencies"].append(copy.deepcopy(sbom["dependencies"][0]))
    sbom["dependency_count"] += 1
    count_field = (
        "direct_dependency_count"
        if sbom["dependencies"][0]["relationship"] == "DIRECT"
        else "transitive_dependency_count"
    )
    sbom[count_field] += 1
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


def test_tracked_artifact_binds_checkout_and_git_blob_bytes():
    record = artifact_records(
        ROOT,
        ["main.py"],
        require_repository_tracking=True,
    )[0]
    checkout = (ROOT / "main.py").read_bytes()
    blob = subprocess.run(
        ["git", "cat-file", "blob", record["repository_blob"]],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    assert record["sha256"] == sha256(checkout).hexdigest()
    assert record["size_bytes"] == len(checkout)
    assert record["repository_blob_sha256"] == sha256(blob).hexdigest()
    assert record["repository_blob_size_bytes"] == len(blob)
    validate_artifact_records(
        [record],
        ROOT,
        require_repository_tracking=True,
    )


def test_artifact_substitution_rejected(tmp_path):
    path = tmp_path / "a.txt"; path.write_text("approved\n", encoding="utf-8")
    records = artifact_records(tmp_path, ["a.txt"]); path.write_text("substituted\n", encoding="utf-8")
    with pytest.raises(SupplyChainError, match="artifact_substitution"):
        validate_artifact_records(records, tmp_path)


def test_artifact_unknown_field_rejected(tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("approved\n", encoding="utf-8")
    records = artifact_records(tmp_path, ["a.txt"])
    records[0]["undeclared_semantics"] = True
    with pytest.raises(SupplyChainError, match="artifact_record_invalid"):
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


def test_artifact_symlink_escape_rejected_as_symlink(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    target = tmp_path / "foreign"
    target.write_text("x", encoding="utf-8")
    link = root / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(SupplyChainError, match="artifact_symlink"):
        artifact_records(root, ["link"])


def test_artifact_override_symlink_rejected(tmp_path):
    target = tmp_path / "target"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "override-link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(SupplyChainError, match="symlink"):
        artifact_records(
            tmp_path,
            ["outputs/generated.json"],
            artifact_sources={"outputs/generated.json": link},
        )


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


def test_manifest_rejects_unknown_signed_semantics():
    payload = build_manifest_payload(
        ROOT, collect_dependency_provenance(ROOT),
    )
    payload["undeclared_semantics"] = True
    payload["supply_chain_identity"] = generate_digest({
        key: value
        for key, value in payload.items()
        if key != "supply_chain_identity"
    })
    with pytest.raises(SupplyChainError, match="manifest_schema_invalid"):
        validate_manifest_payload(
            payload,
            collect_dependency_provenance(ROOT),
            ROOT,
            verify_installed=False,
        )


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
