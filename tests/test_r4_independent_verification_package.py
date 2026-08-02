from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import sbp_lex.ivvp.verifier as verifier_module
from sbp_lex.custody.common import seal as seal_r3, unseal as unseal_r3
from sbp_lex.ivvp.common import IVVPError, file_sha256, read_json, seal, unseal, write_json
from sbp_lex.ivvp.package import (
    _claims,
    _commands,
    _identity,
    _package_file_inventory,
    _traceability,
    build_package,
)
from sbp_lex.ivvp.verifier import verify_package
from sbp_lex.security.pqc import generate_digest
from sbp_lex.supply_chain.common import (
    seal as seal_r2,
    unseal as unseal_r2,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def package(tmp_path_factory):
    path = tmp_path_factory.mktemp("r4") / "validation_package"
    build_package(ROOT, path)
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


@pytest.mark.parametrize(
    ("changed_path", "expected_error"),
    [
        ("validation_package/PACKAGE_MANIFEST.json", None),
        ("outputs/local_trust_root_manifest.json", None),
        (
            "sbp_lex/security/pqc.py",
            "repository_handoff_scope_invalid",
        ),
    ],
)
def test_repository_handoff_commit_is_bounded_and_evidence_only(
    tmp_path,
    changed_path,
    expected_error,
):
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "SBP Evidence Test"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "evidence-test@sbp.invalid"],
        cwd=repository,
        check=True,
    )
    source = repository / "README.md"
    source.write_text("source\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "--", "README.md"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "source baseline"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    source_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    changed = repository / changed_path
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("{}\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "--", changed_path],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "record generated evidence"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    handoff_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    if expected_error is None:
        verifier_module._verify_repository_handoff_lineage(
            repository,
            source_commit,
            handoff_commit,
        )
    else:
        with pytest.raises(IVVPError, match=expected_error):
            verifier_module._verify_repository_handoff_lineage(
                repository,
                source_commit,
                handoff_commit,
            )


def test_recovery_inventory_is_linked_to_packaged_evidence(tmp_path):
    package = tmp_path / "package"
    relative = "outputs/example_recovery_dependency.json"
    evidence = package / "evidence" / relative
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"status":"current"}\n', encoding="utf-8")
    inventory = {
        "artefacts": [{
            "source_path": relative,
            "current_digest": file_sha256(evidence),
            "size_bytes": evidence.stat().st_size,
        }],
    }

    verifier_module._verify_recovery_inventory_links(
        package,
        inventory,
        required_paths=(relative,),
    )

    inventory["artefacts"][0]["current_digest"] = "0" * 64
    with pytest.raises(
        IVVPError,
        match="r1_recovery_inventory_linkage_invalid",
    ):
        verifier_module._verify_recovery_inventory_links(
            package,
            inventory,
            required_paths=(relative,),
        )


def test_detached_verifier_requires_out_of_band_signer_fingerprint(
    package, monkeypatch,
):
    monkeypatch.delenv(
        "SBP_LEX_EXPECTED_SIGNER_FINGERPRINT", raising=False,
    )
    with pytest.raises(
        IVVPError, match="expected_signer_fingerprint_required",
    ):
        verify_package(package)


def test_detached_verifier_rejects_wrong_out_of_band_fingerprint(package):
    with pytest.raises(
        IVVPError, match="expected_signer_fingerprint_mismatch",
    ):
        verify_package(
            package,
            expected_signer_fingerprint="0" * 64,
        )


def test_package_contains_required_assessor_documents(package):
    required = {"REPOSITORY_IDENTITY.json", "ENGINEERING_CLAIMS_REGISTER.json", "EVIDENCE_TRACEABILITY_INDEX.json", "INDEPENDENT_VERIFICATION_GUIDE.md", "QUICK_START.md", "VERIFICATION_COMMANDS.json", "VALIDATION_SUMMARY.md", "EVIDENCE_INVENTORY.json", "PACKAGE_MANIFEST.json"}
    assert required.issubset({item.name for item in package.iterdir()})


def test_r4_contract_schemas_are_closed_and_match_package(package):
    manifest = unseal(
        read_json(package / "PACKAGE_MANIFEST.json", label="manifest"),
        label="package_manifest",
    )
    claims = read_json(
        package / "ENGINEERING_CLAIMS_REGISTER.json",
        label="claims",
    )
    inventory = read_json(
        package / "EVIDENCE_INVENTORY.json",
        label="inventory",
    )
    schema_root = ROOT / "sbp_lex/ivvp/schemas"
    manifest_schema = json.loads(
        (schema_root / "package_manifest.schema.json").read_text("utf-8")
    )
    claims_schema = json.loads(
        (schema_root / "engineering_claims.schema.json").read_text("utf-8")
    )
    inventory_schema = json.loads(
        (schema_root / "evidence_inventory.schema.json").read_text("utf-8")
    )
    payload_schema = manifest_schema["properties"]["payload"]
    assert payload_schema["additionalProperties"] is False
    assert set(manifest) == set(payload_schema["required"])
    assert claims_schema["additionalProperties"] is False
    assert set(claims) == set(claims_schema["required"])
    assert set(claims["claims"][0]) == set(
        claims_schema["$defs"]["claim"]["required"]
    )
    assert inventory_schema["additionalProperties"] is False
    assert set(inventory) == set(inventory_schema["required"])
    assert set(inventory["evidence"][0]) == set(
        inventory_schema["$defs"]["evidenceRecord"]["required"]
    )


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
    assert {"H7", "PHQ", "R1", "R2", "R3", "DOUBLE_TRIPLE", "LOCAL_TRUST", "CONSTITUTIONAL_GATES", "TOOLCHAIN_GUARD", "RELEASE_INTEGRITY", "CAPSTONE", "RUNTIME_REPLAY"} == layers


def test_verification_commands_are_non_mutating():
    commands = _commands()["commands"]
    assert all(
        item["mutates_tracked_repository_state"] is False
        for item in commands
    )
    double_triple = next(
        item
        for item in commands
        if item["command_identifier"] == "double_triple_handover"
    )
    assert (
        double_triple["command"]
        == "scripts\\run_double_triple_assurance.bat"
    )


def test_package_semantic_identity_is_stable_across_fresh_signatures(tmp_path):
    first = tmp_path / "first"; second = tmp_path / "second"
    build_package(ROOT, first); build_package(ROOT, second)
    a = unseal(read_json(first / "PACKAGE_MANIFEST.json", label="manifest"), label="package_manifest")
    b = unseal(read_json(second / "PACKAGE_MANIFEST.json", label="manifest"), label="package_manifest")
    stable_fields = {
        "manifest_version", "desktop_scope", "repository_identity",
        "repository_commit", "git_tree_identity",
        "trusted_repository_anchor_commit",
        "trusted_repository_anchor_tree",
        "trusted_signing_key_fingerprint",
        "measured_baseline_identifier", "runtime_identity",
        "identity_digest", "claims_digest", "traceability_digest",
        "package_status",
    }
    assert {key: a[key] for key in stable_fields} == {
        key: b[key] for key in stable_fields
    }
    assert verify_package(first)["status"] == "R4_IVVP_VALID"
    assert verify_package(second)["status"] == "R4_IVVP_VALID"


def test_missing_evidence_rejected(package, tmp_path):
    target = clone(package, tmp_path); (target / "evidence/outputs/r1_recovery_drill.json").unlink()
    with pytest.raises(IVVPError, match="missing_package_file"): verify_package(target)


def test_substituted_evidence_rejected(package, tmp_path):
    target = clone(package, tmp_path); (target / "evidence/outputs/r1_recovery_drill.json").write_text("{}", encoding="utf-8")
    with pytest.raises(IVVPError, match="substituted_package_file"): verify_package(target)


def test_resigned_package_with_legacy_assurance_marker_is_rejected(
    package,
    tmp_path,
):
    target = clone(package, tmp_path)
    path = target / "evidence/README.md"
    path.write_text(
        "PQC_01_PROVIDER_SIGNATURE_V1\n",
        encoding="utf-8",
    )
    resign_package(target)
    with pytest.raises(IVVPError, match="legacy_assurance_evidence"):
        verify_package(target)


def test_inner_local_trust_tamper_rejected_after_outer_resign(
    package, tmp_path,
):
    target = clone(package, tmp_path)
    path = target / "evidence/outputs/local_trust_root_manifest.json"
    value = read_json(path, label="local_trust")
    value["local_trust_status"] = "FORGED_PASS"
    write_json(path, value)
    resign_package(target, refresh_evidence=True)
    with pytest.raises(
        IVVPError, match="referenced_evidence_substituted",
    ):
        verify_package(target)


def test_runtime_attestation_tamper_rejected_after_outer_resign(
    package, tmp_path,
):
    target = clone(package, tmp_path)
    path = target / "RUNTIME_REPLAY_EVIDENCE.json"
    runtime = read_json(path, label="runtime")
    runtime["runtime_startup_attestation"]["payload"][
        "runtime_identity"
    ] = "0" * 64
    write_json(path, runtime)
    resign_package(target)
    with pytest.raises(
        IVVPError, match="runtime_startup_attestation_invalid",
    ):
        verify_package(target)


def test_false_repository_blob_digest_rejected_after_full_resign(
    package, tmp_path,
):
    target = clone(package, tmp_path)
    manifest_path = (
        target / "evidence/outputs/r2_deterministic_build_manifest.json"
    )
    manifest = unseal_r2(
        read_json(manifest_path, label="r2_manifest"),
        label="r2_manifest",
    )
    tracked = next(
        record
        for record in manifest["artefact_inventory"]
        if record["tracked_at_repository_commit"]
    )
    tracked["repository_blob_sha256"] = "0" * 64
    manifest["artefact_inventory_digest"] = generate_digest({
        "artefacts": manifest["artefact_inventory"],
    })
    manifest["supply_chain_identity"] = generate_digest({
        key: value
        for key, value in manifest.items()
        if key != "supply_chain_identity"
    })
    sealed_manifest = seal_r2(manifest)
    write_json(manifest_path, sealed_manifest)

    verification_path = (
        target / "evidence/outputs/r2_offline_verification.json"
    )
    verification = unseal_r2(
        read_json(verification_path, label="r2_verification"),
        label="r2_verification",
    )
    verification["manifest_digest"] = sealed_manifest["payload_digest"]
    verification["supply_chain_identity"] = (
        manifest["supply_chain_identity"]
    )
    write_json(verification_path, seal_r2(verification))

    r3_path = (
        target / "evidence/outputs/r3_operational_custody_assurance.json"
    )
    r3 = unseal_r3(
        read_json(r3_path, label="r3"),
        label="custody_assurance_profile",
    )
    r3["r2_supply_chain_identity"] = manifest["supply_chain_identity"]
    r3["profile_digest"] = generate_digest({
        key: value
        for key, value in r3.items()
        if key != "profile_digest"
    })
    write_json(r3_path, seal_r3(r3))
    resign_package(target, refresh_evidence=True)

    with pytest.raises(
        IVVPError, match="repository_artifact_content_mismatch",
    ):
        verify_package(target, repository_root=ROOT)


def test_nonportable_evidence_inventory_path_rejected_after_resign(
    package, tmp_path,
):
    target = clone(package, tmp_path)
    inventory_path = target / "EVIDENCE_INVENTORY.json"
    inventory = read_json(inventory_path, label="inventory")
    inventory["evidence"][0]["source_path"] = "../outside.json"
    inventory["evidence_inventory_digest"] = generate_digest({
        "evidence": inventory["evidence"],
    })
    write_json(inventory_path, inventory)
    resign_package(target)
    with pytest.raises(
        IVVPError, match="nonportable_evidence_reference",
    ):
        verify_package(target)


def test_non_mapping_traceability_record_fails_closed(package, tmp_path):
    target = clone(package, tmp_path)
    trace_path = target / "EVIDENCE_TRACEABILITY_INDEX.json"
    trace = read_json(trace_path, label="trace")
    trace["evidence_items"][0] = "malformed"
    trace["traceability_digest"] = generate_digest({
        "evidence_items": trace["evidence_items"],
    })
    write_json(trace_path, trace)
    resign_package(target)
    with pytest.raises(IVVPError, match="broken_traceability"):
        verify_package(target)


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


def test_unapproved_batch_launcher_rejected(package, tmp_path):
    target = clone(package, tmp_path)
    commands = read_json(
        target / "VERIFICATION_COMMANDS.json", label="commands",
    )
    record = next(
        item
        for item in commands["commands"]
        if item["command_identifier"] == "double_triple_handover"
    )
    record["command"] = "scripts\\unmeasured_assurance.bat"
    commands["command_pack_digest"] = generate_digest({
        "commands": commands["commands"],
    })
    write_json(target / "VERIFICATION_COMMANDS.json", commands)
    resign_package(target)
    with pytest.raises(
        IVVPError, match="verification_command_pack_invalid",
    ):
        verify_package(target)


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


def test_package_build_rejects_repository_as_destination():
    with pytest.raises(IVVPError, match="unsafe_package_destination"):
        build_package(ROOT, ROOT)


def test_package_build_rejects_unrecognized_existing_destination(tmp_path):
    target = tmp_path / "unrelated"
    target.mkdir()
    sentinel = target / "do-not-delete.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(
        IVVPError, match="unrecognized_existing_package_destination",
    ):
        build_package(ROOT, target)
    assert sentinel.read_text("utf-8") == "preserve"


def test_package_build_rejects_fake_manifest_destination(tmp_path):
    target = tmp_path / "unrelated"
    target.mkdir()
    sentinel = target / "do-not-delete.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    (target / "PACKAGE_MANIFEST.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    with pytest.raises(
        IVVPError, match="unrecognized_existing_package_destination",
    ):
        build_package(ROOT, target)
    assert sentinel.read_text("utf-8") == "preserve"


def test_quick_start_requires_out_of_band_public_key(package):
    text = (package / "QUICK_START.md").read_text("utf-8")
    assert "SBP_LEX_TRUSTED_SIGNING_PUBLIC_KEY" in text
    assert "--repository-root" in text
