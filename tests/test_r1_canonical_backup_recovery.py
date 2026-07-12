from __future__ import annotations

import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from sbp_lex.recovery.backup import create_backup, validate_backup_package
from sbp_lex.recovery.common import RecoveryError, bound_payload
from sbp_lex.recovery.inventory import ArtifactSpec, build_inventory, validate_inventory
from sbp_lex.recovery.manifest import create_manifest, validate_manifest
from sbp_lex.recovery.recovery_drill import run_recovery_drill
from sbp_lex.recovery.restore import (
    preflight_restore,
    restore_backup,
    validate_authoritative_restore,
)
from sbp_lex.security.pqc import generate_digest

COMMIT = "a" * 40
BASELINE = "DESKTOP_V1_R1_TEST_BASELINE_01"
IDENTITY = "b" * 64
TIMESTAMP = "2026-01-01T00:00:00+00:00"


def write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def ledger(sequences=(1, 2), *, broken_link=False) -> bytes:
    records = []
    previous = None
    for sequence in sequences:
        payload = {
            "sequence": sequence,
            "event": f"event-{sequence}",
            "previous_hash": "0" * 64 if broken_link else previous,
        }
        record = {**payload, "record_hash": generate_digest(payload)}
        records.append(record)
        previous = record["record_hash"]
    return b"".join(
        (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
        for item in records
    )


def specs() -> tuple[ArtifactSpec, ...]:
    return (
        ArtifactSpec("configuration.foundation", "configuration", "config.json", "configuration/config.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 100, "strict_json", "configuration_authority"),
        ArtifactSpec("security.state", "security_state", "security.json", "security/security.json", "REQUIRED", "PROTECTED_PRIVATE", "json", 1, None, 200, "strict_json", "security_authority"),
        ArtifactSpec("external.replay", "external_identity_replay", "external.jsonl", "external/external.jsonl", "REQUIRED", "PROTECTED_PRIVATE", "jsonl", 1, None, 300, "jsonl_hash_chain", "external_authority"),
        ArtifactSpec("execution.lifecycle", "execution_integrity", "execution.jsonl", "execution/execution.jsonl", "REQUIRED", "PROTECTED_PRIVATE", "jsonl", 1, None, 400, "jsonl_hash_chain", "execution_authority"),
        ArtifactSpec("audit.ledger", "audit_attestations", "audit.jsonl", "audit/audit.jsonl", "REQUIRED", "PROTECTED_PRIVATE", "jsonl", 1, None, 500, "jsonl_hash_chain", "audit_authority"),
        ArtifactSpec("measured.baseline", "measured_startup", "measured.json", "measured/measured.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 600, "strict_json", "measured_authority"),
        ArtifactSpec("local_trust.evidence", "local_trust", "local_trust.json", "local_trust/local_trust.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 700, "strict_json", "local_trust_authority"),
        ArtifactSpec("formal.phq", "formal_assurance", "phq.json", "formal/phq.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 800, "strict_json", "formal_authority"),
    )


def source(root: Path) -> Path:
    root.mkdir(parents=True)
    write(root / "config.json", b'{"mode":"desktop-v1"}\n')
    write(root / "security.json", b'{"state":"approved"}\n')
    write(root / "external.jsonl", ledger())
    write(root / "execution.jsonl", ledger())
    write(root / "audit.jsonl", ledger())
    write(root / "measured.json", b'{"baseline":"approved"}\n')
    write(root / "local_trust.json", b'{"changes":0,"status":"valid"}\n')
    write(root / "phq.json", b'{"authority":"non-authoritative","status":"valid"}\n')
    return root


def package(tmp_path: Path):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    backup = tmp_path / "backup"
    manifest = create_backup(
        src, inventory, backup,
        repository_commit=COMMIT,
        measured_baseline_identifier=BASELINE,
        runtime_identity=IDENTITY,
        generation=1,
        approved_backup_root=tmp_path,
        creation_timestamp=TIMESTAMP,
    )
    return src, inventory, backup, manifest


def restore_args(tmp_path: Path, backup: Path):
    approved = tmp_path / "approved"
    approved.mkdir(exist_ok=True)
    return {
        "package_root": backup,
        "destination": approved / "restored",
        "approved_destination_root": approved,
        "expected_repository_commit": COMMIT,
        "expected_measured_baseline_identifier": BASELINE,
        "expected_runtime_identity": IDENTITY,
    }


def rewrite_manifest(backup: Path, mutate) -> None:
    value = json.loads((backup / "manifest.json").read_text())
    payload = value["payload"]
    mutate(payload)
    (backup / "manifest.json").write_text(
        json.dumps(bound_payload(payload), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def test_valid_backup_creation_and_sealed_manifest(tmp_path):
    _, inventory, backup, manifest = package(tmp_path)
    payload = validate_backup_package(backup)
    assert payload["backup_identifier"] == manifest["backup_identifier"]
    assert payload["artefact_inventory"]["aggregate_digest"] == inventory["aggregate_digest"]
    assert (backup / "COMPLETE").is_file()


def test_valid_staged_restore_and_fresh_process(tmp_path):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    result = restore_backup(
        **args,
        fresh_process_commands=((sys.executable, "-c", "import os; from pathlib import Path; assert (Path(os.environ['SBP_LEX_RECOVERY_GENERATION_ROOT'])/'configuration/config.json').is_file()"),),
    )
    assert result["status"] == "AUTHORITATIVE_RESTORE_VALID"
    assert len(result["fresh_process_results"]) == 1
    assert validate_authoritative_restore(args["destination"])["generation"] == 1


def test_manifest_is_deterministic_for_fixed_inputs(tmp_path):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    first = create_manifest(inventory, repository_commit=COMMIT, measured_baseline_identifier=BASELINE, runtime_identity=IDENTITY, generation=1, creation_timestamp=TIMESTAMP)
    second = create_manifest(inventory, repository_commit=COMMIT, measured_baseline_identifier=BASELINE, runtime_identity=IDENTITY, generation=1, creation_timestamp=TIMESTAMP)
    assert first["payload_digest"] == second["payload_digest"]
    assert first["payload"]["backup_identifier"] == second["payload"]["backup_identifier"]


@pytest.mark.parametrize("missing", ["config.json", "security.json", "measured.json", "local_trust.json", "phq.json"])
def test_missing_required_artefact_fails_closed(tmp_path, missing):
    src = source(tmp_path / "source")
    (src / missing).unlink()
    with pytest.raises(RecoveryError, match="required_artefact_missing"):
        build_inventory(src, specs())


def test_unknown_required_artefact_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    expected = {item.logical_name for item in specs()} - {"formal.phq"}
    with pytest.raises(RecoveryError, match="unknown_required_artefact"):
        validate_inventory(inventory, expected_required=expected)


def test_incomplete_required_inventory_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    expected = {item.logical_name for item in specs()} | {"configuration.missing"}
    with pytest.raises(RecoveryError, match="required_artefact_inventory_incomplete"):
        validate_inventory(inventory, expected_required=expected)


@pytest.mark.parametrize("field,value,reason", [
    ("source_path", "../escape.json", "source_path_escape"),
    ("source_path", "C:/absolute.json", "source_path_absolute"),
    ("relative_recovery_path", "../../escape.json", "recovery_path_escape"),
    ("relative_recovery_path", "C:/absolute.json", "recovery_path_absolute"),
])
def test_path_traversal_and_absolute_paths_are_rejected(tmp_path, field, value, reason):
    src = source(tmp_path / "source")
    first = replace(specs()[0], **{field: value})
    with pytest.raises(RecoveryError, match=reason):
        build_inventory(src, (first,) + specs()[1:])


def test_source_symlink_is_rejected_where_supported(tmp_path):
    src = source(tmp_path / "source")
    link = src / "link.json"
    try:
        link.symlink_to(src / "config.json")
    except OSError:
        pytest.skip("symlink creation unavailable")
    first = replace(specs()[0], source_path="link.json")
    with pytest.raises(RecoveryError, match="source_path_symlink|source_symlink"):
        build_inventory(src, (first,) + specs()[1:])


def test_duplicate_logical_identity_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    duplicate = replace(specs()[1], logical_name=specs()[0].logical_name)
    with pytest.raises(RecoveryError, match="duplicate_logical_identity"):
        build_inventory(src, (specs()[0], duplicate) + specs()[2:])


def test_conflicting_restore_location_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    duplicate = replace(specs()[1], relative_recovery_path=specs()[0].relative_recovery_path)
    with pytest.raises(RecoveryError, match="conflicting_restore_location"):
        build_inventory(src, (specs()[0], duplicate) + specs()[2:])


def test_ambiguous_authority_domain_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    invalid = replace(specs()[0], authority_domain="all_authority")
    with pytest.raises(RecoveryError, match="ambiguous_authority_domain"):
        build_inventory(src, (invalid,) + specs()[1:])


@pytest.mark.parametrize("kind", ["manifest_json", "manifest_signature", "manifest_aggregate", "artefact", "complete", "deleted_member", "extra_member"])
def test_corrupted_or_partial_package_is_rejected(tmp_path, kind):
    _, _, backup, _ = package(tmp_path)
    if kind == "manifest_json":
        (backup / "manifest.json").write_bytes(b"{")
    elif kind == "manifest_signature":
        value = json.loads((backup / "manifest.json").read_text())
        value["integrity_signature"]["signature"] = "AAAA"
        (backup / "manifest.json").write_text(json.dumps(value))
    elif kind == "manifest_aggregate":
        rewrite_manifest(backup, lambda payload: payload.__setitem__("aggregate_digest", "0" * 64))
    elif kind == "artefact":
        path = next((backup / "domains").rglob("config.json"))
        path.write_bytes(path.read_bytes() + b"x")
    elif kind == "complete":
        (backup / "COMPLETE").write_text("0" * 64)
    elif kind == "deleted_member":
        next((backup / "domains").rglob("config.json")).unlink()
    else:
        write(backup / "unexpected.txt", b"unexpected")
    with pytest.raises(RecoveryError):
        validate_backup_package(backup)


def test_duplicate_json_key_in_manifest_is_rejected(tmp_path):
    _, _, backup, _ = package(tmp_path)
    (backup / "manifest.json").write_text('{"payload":{},"payload":{}}')
    with pytest.raises(RecoveryError, match="json_invalid"):
        validate_backup_package(backup)


@pytest.mark.parametrize("sequences", [(1, 1), (2, 1)])
def test_duplicate_or_reordered_ledger_sequence_is_rejected(tmp_path, sequences):
    src = source(tmp_path / "source")
    write(src / "audit.jsonl", ledger(sequences))
    with pytest.raises(RecoveryError, match="ledger_sequence_invalid"):
        build_inventory(src, specs())


def test_broken_ledger_linkage_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    write(src / "audit.jsonl", ledger(broken_link=True))
    with pytest.raises(RecoveryError, match="ledger_linkage_invalid"):
        build_inventory(src, specs())


@pytest.mark.parametrize("field,expected,reason", [
    ("expected_repository_commit", "c" * 40, "repository_commit_mismatch"),
    ("expected_measured_baseline_identifier", "DESKTOP_V1_UNKNOWN_BASELINE_99", "unknown_baseline_ancestor"),
    ("expected_runtime_identity", "d" * 64, "runtime_identity_mismatch"),
])
def test_repository_baseline_and_runtime_substitution_are_rejected(tmp_path, field, expected, reason):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    args[field] = expected
    with pytest.raises(RecoveryError, match=reason):
        preflight_restore(**args)


def test_foreign_desktop_package_is_rejected(tmp_path):
    _, _, backup, _ = package(tmp_path)
    rewrite_manifest(backup, lambda payload: payload.__setitem__("desktop_scope", "FOREIGN_DESKTOP"))
    with pytest.raises(RecoveryError, match="foreign_desktop_package"):
        validate_backup_package(backup)


def test_authority_domain_substitution_is_rejected(tmp_path):
    _, _, backup, _ = package(tmp_path)
    def mutate(payload):
        payload["domain_manifests"][0]["authority_domain"] = "local_trust"
    rewrite_manifest(backup, mutate)
    with pytest.raises(RecoveryError, match="authority_domain_substitution"):
        validate_backup_package(backup)


def test_unapproved_restore_destination_is_rejected(tmp_path):
    _, _, backup, _ = package(tmp_path)
    approved = tmp_path / "approved"
    approved.mkdir()
    with pytest.raises(RecoveryError, match="unapproved_destination"):
        preflight_restore(
            backup, tmp_path / "outside",
            approved_destination_root=approved,
            expected_repository_commit=COMMIT,
            expected_measured_baseline_identifier=BASELINE,
            expected_runtime_identity=IDENTITY,
        )


def test_concurrent_backup_publication_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    target = tmp_path / "backup"
    (tmp_path / ".backup.backup.lock").write_text("held")
    with pytest.raises(RecoveryError, match="concurrent_backup_publication"):
        create_backup(src, inventory, target, repository_commit=COMMIT, measured_baseline_identifier=BASELINE, runtime_identity=IDENTITY, generation=1, approved_backup_root=tmp_path, creation_timestamp=TIMESTAMP)


def test_unapproved_backup_destination_is_rejected(tmp_path):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    approved = tmp_path / "approved-backups"
    approved.mkdir()
    with pytest.raises(RecoveryError, match="unapproved_destination"):
        create_backup(
            src, inventory, tmp_path / "outside-backup",
            repository_commit=COMMIT,
            measured_baseline_identifier=BASELINE,
            runtime_identity=IDENTITY,
            generation=1,
            approved_backup_root=approved,
            creation_timestamp=TIMESTAMP,
        )


def test_second_authoritative_restore_writer_is_rejected(tmp_path):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    lock = args["destination"].with_name(f".{args['destination'].name}.restore.lock")
    lock.write_text("held")
    with pytest.raises(RecoveryError, match="second_authoritative_restore_writer"):
        restore_backup(**args)


def test_nonempty_unmanaged_restore_destination_is_rejected(tmp_path):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    args["destination"].mkdir()
    write(args["destination"] / "unmanaged.txt", b"do not overwrite")
    with pytest.raises(RecoveryError, match="destination_not_empty"):
        preflight_restore(**args)


def test_package_symlink_substitution_is_rejected_where_supported(tmp_path):
    _, _, backup, _ = package(tmp_path)
    source_member = next((backup / "domains").rglob("config.json"))
    replacement = source_member.with_name("replacement.json")
    replacement.write_bytes(source_member.read_bytes())
    source_member.unlink()
    try:
        source_member.symlink_to(replacement)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(RecoveryError, match="backup_package_symlink"):
        validate_backup_package(backup)


def test_truncated_ledger_package_member_is_rejected(tmp_path):
    _, _, backup, _ = package(tmp_path)
    member = next((backup / "domains" / "audit_attestations").rglob("audit.jsonl"))
    member.write_bytes(member.read_bytes().splitlines(keepends=True)[0])
    with pytest.raises(RecoveryError, match="backup_artefact_digest_mismatch"):
        validate_backup_package(backup)


def test_authoritative_generation_rejects_unexpected_member(tmp_path):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    result = restore_backup(**args)
    generation = args["destination"] / ".recovery_generations" / result["backup_identifier"]
    write(generation / "unexpected.json", b"{}\n")
    with pytest.raises(RecoveryError, match="authoritative_generation_member_set_invalid"):
        validate_authoritative_restore(args["destination"])


@pytest.mark.parametrize("point", ["restore_before_durability_flush", "restore_after_durability_flush_before_fresh_startup"])
def test_durability_boundary_interruption_has_unambiguous_authority(tmp_path, point):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    def fault(current):
        if current == point:
            raise RuntimeError("simulated crash")
    with pytest.raises(RecoveryError, match="restore_interrupted"):
        restore_backup(**args, fault_hook=fault)
    if point == "restore_before_durability_flush":
        with pytest.raises(RecoveryError, match="authoritative_restore_missing"):
            validate_authoritative_restore(args["destination"])
    else:
        assert validate_authoritative_restore(args["destination"])["generation"] == 1


@pytest.mark.parametrize("point", ["backup_staging_created", "backup_member:configuration.foundation", "backup_before_publication"])
def test_interrupted_backup_leaves_no_valid_partial_package(tmp_path, point):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    target = tmp_path / "backup"
    def fault(current):
        if current == point:
            raise RuntimeError("simulated crash")
    with pytest.raises(RecoveryError, match="backup_interrupted"):
        create_backup(src, inventory, target, repository_commit=COMMIT, measured_baseline_identifier=BASELINE, runtime_identity=IDENTITY, generation=1, approved_backup_root=tmp_path, creation_timestamp=TIMESTAMP, fault_hook=fault)
    assert not target.exists()
    assert not list(tmp_path.glob("*.backup.tmp"))


def test_interruption_after_backup_publication_leaves_complete_new_package(tmp_path):
    src = source(tmp_path / "source")
    inventory = build_inventory(src, specs())
    target = tmp_path / "backup"
    def fault(current):
        if current == "backup_after_publication":
            raise RuntimeError("simulated crash")
    with pytest.raises(RecoveryError, match="backup_interrupted"):
        create_backup(src, inventory, target, repository_commit=COMMIT, measured_baseline_identifier=BASELINE, runtime_identity=IDENTITY, generation=1, approved_backup_root=tmp_path, creation_timestamp=TIMESTAMP, fault_hook=fault)
    assert validate_backup_package(target)["generation"] == 1


@pytest.mark.parametrize("point", ["restore_extraction_started", "restore_member:configuration.foundation", "restore_validation_started", "restore_before_authoritative_replacement"])
def test_interrupted_restore_before_publication_keeps_no_authoritative_state(tmp_path, point):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    def fault(current):
        if current == point:
            raise RuntimeError("simulated crash")
    with pytest.raises(RecoveryError, match="restore_interrupted"):
        restore_backup(**args, fault_hook=fault)
    with pytest.raises(RecoveryError, match="authoritative_restore_missing"):
        validate_authoritative_restore(args["destination"])


def test_interruption_after_generation_publication_does_not_publish_pointer(tmp_path):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    def fault(current):
        if current == "restore_after_generation_publication":
            raise RuntimeError("simulated crash")
    with pytest.raises(RecoveryError, match="restore_interrupted"):
        restore_backup(**args, fault_hook=fault)
    assert len(list((args["destination"] / ".recovery_generations").iterdir())) == 1
    with pytest.raises(RecoveryError, match="authoritative_restore_missing"):
        validate_authoritative_restore(args["destination"])


def test_interruption_after_pointer_publication_leaves_complete_new_state(tmp_path):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    def fault(current):
        if current == "restore_after_pointer_publication":
            raise RuntimeError("simulated crash")
    with pytest.raises(RecoveryError, match="restore_interrupted"):
        restore_backup(**args, fault_hook=fault)
    assert validate_authoritative_restore(args["destination"])["generation"] == 1


def second_generation(tmp_path, src, first_inventory, first_manifest, *, change=True, sequence=2, predecessor=True):
    if change:
        write(src / "config.json", b'{"mode":"desktop-v1-r2"}\n')
    first_digest = first_inventory["artefacts"][0]["current_digest"]
    second_specs = (replace(
        specs()[0], sequence=sequence,
        predecessor_identity=first_digest if predecessor else "0" * 64,
    ),) + specs()[1:]
    inventory = build_inventory(src, second_specs)
    backup = tmp_path / f"backup2-{sequence}-{int(predecessor)}-{int(change)}"
    manifest = create_backup(
        src, inventory, backup,
        repository_commit=COMMIT,
        measured_baseline_identifier=BASELINE,
        runtime_identity=IDENTITY,
        generation=2,
        approved_backup_root=tmp_path,
        creation_timestamp="2026-01-02T00:00:00+00:00",
        predecessor_backup_identifier=first_manifest["backup_identifier"],
    )
    return inventory, backup, manifest


def test_valid_second_generation_and_rollback_attempt_rejected(tmp_path):
    src, first_inventory, backup, first_manifest = package(tmp_path)
    args = restore_args(tmp_path, backup)
    restore_backup(**args)
    _, backup2, _ = second_generation(tmp_path, src, first_inventory, first_manifest)
    restore_backup(**{**args, "package_root": backup2})
    assert validate_authoritative_restore(args["destination"])["generation"] == 2
    with pytest.raises(RecoveryError, match="replayed_backup_identifier|backup_generation_rollback"):
        restore_backup(**args)


def test_stale_artefact_sequence_and_anchor_are_rejected(tmp_path):
    src, first_inventory, backup, first_manifest = package(tmp_path)
    args = restore_args(tmp_path, backup)
    restore_backup(**args)
    _, stale, _ = second_generation(tmp_path, src, first_inventory, first_manifest, sequence=1)
    with pytest.raises(RecoveryError, match="mixed_generation_package"):
        preflight_restore(**{**args, "package_root": stale})


def test_broken_artefact_predecessor_is_rejected(tmp_path):
    src, first_inventory, backup, first_manifest = package(tmp_path)
    args = restore_args(tmp_path, backup)
    restore_backup(**args)
    _, broken, _ = second_generation(tmp_path, src, first_inventory, first_manifest, predecessor=False)
    with pytest.raises(RecoveryError, match="artefact_predecessor_mismatch"):
        preflight_restore(**{**args, "package_root": broken})


def test_broken_backup_ancestry_is_rejected(tmp_path):
    src, first_inventory, backup, first_manifest = package(tmp_path)
    args = restore_args(tmp_path, backup)
    restore_backup(**args)
    write(src / "config.json", b'{"mode":"changed"}\n')
    second_specs = (replace(specs()[0], sequence=2, predecessor_identity=first_inventory["artefacts"][0]["current_digest"]),) + specs()[1:]
    inventory = build_inventory(src, second_specs)
    broken = tmp_path / "broken-ancestry"
    create_backup(src, inventory, broken, repository_commit=COMMIT, measured_baseline_identifier=BASELINE, runtime_identity=IDENTITY, generation=2, approved_backup_root=tmp_path, creation_timestamp="2026-01-03T00:00:00+00:00", predecessor_backup_identifier="R1_BACKUP_99999999_ABCDEFGHIJKLMNOPQRSTUVWX")
    with pytest.raises(RecoveryError, match="broken_backup_ancestry"):
        preflight_restore(**{**args, "package_root": broken})


def test_secret_leakage_scan_rejects_backup_source(tmp_path):
    src = source(tmp_path / "source")
    write(src / "security.json", b'{"api_token":"actual-secret-value"}\n')
    with pytest.raises(RecoveryError, match="secret_material_detected"):
        build_inventory(src, specs())


def test_fresh_process_failure_creates_persistent_inoperability(tmp_path):
    _, _, backup, _ = package(tmp_path)
    args = restore_args(tmp_path, backup)
    with pytest.raises(RecoveryError, match="fresh_process_validation_failed"):
        restore_backup(**args, fresh_process_commands=((sys.executable, "-c", "raise SystemExit(7)"),))
    with pytest.raises(RecoveryError, match="restore_persistently_inoperable"):
        validate_authoritative_restore(args["destination"])


@pytest.mark.parametrize("logical_fragment", ["local_trust", "execution", "phq", "audit"])
def test_domain_integrity_inconsistency_is_rejected(tmp_path, logical_fragment):
    _, _, backup, _ = package(tmp_path)
    payload = validate_backup_package(backup)
    artefact = next(item for item in payload["artefact_inventory"]["artefacts"] if logical_fragment in item["logical_name"])
    member = backup / "domains" / artefact["authority_domain"] / artefact["sensitivity_class"].lower() / artefact["relative_recovery_path"]
    member.write_bytes(member.read_bytes() + b"tamper")
    with pytest.raises(RecoveryError, match="backup_artefact_digest_mismatch"):
        validate_backup_package(backup)


def test_recovery_drill_proves_valid_restore_corruption_and_replay_defence(tmp_path):
    result = run_recovery_drill(tmp_path / "drill")
    assert result["status"] == "RECOVERY_DRILL_PASS"
    assert result["fresh_process_validated"] is True
    assert result["corruption_rejected"] is True
    assert result["replay_rejected"] is True
    assert result["live_state_modified"] is False
