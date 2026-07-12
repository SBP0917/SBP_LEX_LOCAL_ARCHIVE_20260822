from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from sbp_lex.custody.common import CustodyError, seal, unseal
from sbp_lex.custody.custody_chain import create_event, validate_chain
from sbp_lex.custody.custody_manifest import create_custody_manifest, export_custody_package, validate_custody_package
from sbp_lex.custody.custody_verifier import verify_custody_continuity
from sbp_lex.custody.external_key_custody import (
    create_key_custody_manifest, public_key_record, revocation_record, rotation_record,
    signing_request, signing_response, validate_key_custody_manifest, validate_signing_response,
)
from sbp_lex.custody.recovery_media import create_media_manifest, media_lifecycle_record, recovery_invocation, validate_media_manifest
from sbp_lex.recovery.backup import create_backup
from sbp_lex.recovery.inventory import ArtifactSpec, build_inventory
from sbp_lex.security.pqc import generate_digest

COMMIT = "a" * 40
BASELINE = "DESKTOP_V1_R3_TEST_BASELINE_01"
IDENTITY = "b" * 64
CHAIN = "R3_CUSTODY_CHAIN_TEST_0001"
KEY_CUSTODY = "R3_KEY_CUSTODY_TEST_0001"
TIMESTAMP = "2026-07-12T00:00:00+00:00"
PUBLIC = base64.b64encode(b"public-key-material-for-tests-0001").decode()
SIGNATURE = base64.b64encode(b"external-signature-for-tests").decode()


def _backup(tmp_path: Path) -> Path:
    source = tmp_path / "source"; source.mkdir(); (source / "config.json").write_text('{"approved":true}\n', encoding="utf-8")
    specs = (ArtifactSpec("configuration.test", "configuration", "config.json", "configuration/config.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 100, "strict_json", "test_authority"),)
    inventory = build_inventory(source, specs)
    root = tmp_path / "backups"; root.mkdir(); target = root / "backup-1"
    create_backup(source, inventory, target, repository_commit=COMMIT, measured_baseline_identifier=BASELINE, runtime_identity=IDENTITY, generation=1, approved_backup_root=root, creation_timestamp=TIMESTAMP)
    return target


def _key_manifest():
    keys = [
        public_key_record(key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", role="EXTERNAL_SIGNING", algorithm="ML-DSA", public_key=PUBLIC, sequence=1),
        public_key_record(key_identifier="R3_RECOVERY_ONLY_KEY_0001", role="RECOVERY_ONLY", algorithm="ML-DSA", public_key=PUBLIC, sequence=1),
    ]
    return create_key_custody_manifest(custody_identifier=KEY_CUSTODY, keys=keys, control_authorities=["operator-a", "administrator-b"])


def _package(tmp_path: Path):
    backup = _backup(tmp_path); keys = _key_manifest(); exports = tmp_path / "exports"; exports.mkdir(); package = exports / "package"
    payload = export_custody_package(backup, package, approved_export_root=exports, custody_chain_identifier=CHAIN, sequence=1, export_timestamp=TIMESTAMP, key_custody_manifest_digest=keys["payload_digest"])
    return package, keys, payload


def _events(package_id: str, *, complete=True):
    values = []
    for sequence, action, role, receipt in [
        (1, "EXPORT", "repository_operator", None),
        (2, "RECEIPT", "custody_operator", "c" * 64),
        (3, "MEDIA_CREATED", "recovery_operator", None),
        (4, "VERIFIED", "auditor", None),
    ]:
        if not complete and action == "VERIFIED": break
        previous = unseal(values[-1], label="event")["event_digest"] if values else None
        values.append(create_event(chain_identifier=CHAIN, sequence=sequence, action=action, actor_role=role, package_identifier=package_id, occurred_at=TIMESTAMP, previous_event_digest=previous, receipt_digest=receipt))
    return values


def test_off_host_export_and_import_validate(tmp_path):
    package, _, payload = _package(tmp_path)
    checked = validate_custody_package(package, expected_repository_commit=COMMIT, expected_measured_baseline_identifier=BASELINE, expected_runtime_identity=IDENTITY)
    assert checked["custody_package_identifier"] == payload["custody_package_identifier"]


def test_custody_manifest_payload_is_deterministic(tmp_path):
    backup = _backup(tmp_path); digest = "d" * 64
    first = create_custody_manifest(backup, custody_chain_identifier=CHAIN, sequence=1, export_timestamp=TIMESTAMP, key_custody_manifest_digest=digest)
    second = create_custody_manifest(backup, custody_chain_identifier=CHAIN, sequence=1, export_timestamp=TIMESTAMP, key_custody_manifest_digest=digest)
    assert first["payload"] == second["payload"] and first["payload_digest"] == second["payload_digest"]


def test_modified_backup_rejected(tmp_path):
    package, _, _ = _package(tmp_path); (package / "backup" / "COMPLETE").write_text("0" * 64, encoding="ascii")
    with pytest.raises(Exception): validate_custody_package(package)


def test_corrupted_completion_rejected(tmp_path):
    package, _, _ = _package(tmp_path); (package / "CUSTODY_COMPLETE").write_text("0" * 64, encoding="ascii")
    with pytest.raises(CustodyError, match="corrupted_custody_package"): validate_custody_package(package)


def test_unexpected_custody_package_member_rejected(tmp_path):
    package, _, _ = _package(tmp_path); (package / "foreign.bin").write_bytes(b"foreign")
    with pytest.raises(CustodyError, match="unexpected_custody_package_member"): validate_custody_package(package)


@pytest.mark.parametrize("keyword,value,reason", [
    ("expected_repository_commit", "f" * 40, "foreign_repository_package"),
    ("expected_measured_baseline_identifier", "FOREIGN_BASELINE_0001", "stale_measured_baseline"),
    ("expected_runtime_identity", "f" * 64, "runtime_identity_mismatch"),
])
def test_foreign_or_stale_binding_rejected(tmp_path, keyword, value, reason):
    package, _, _ = _package(tmp_path)
    with pytest.raises(CustodyError, match=reason): validate_custody_package(package, **{keyword: value})


def test_stale_generation_rejected(tmp_path):
    package, _, _ = _package(tmp_path)
    with pytest.raises(CustodyError, match="stale_custody_package"): validate_custody_package(package, minimum_backup_generation=2)


def test_replayed_package_rejected(tmp_path):
    package, _, _ = _package(tmp_path); seen = set(); validate_custody_package(package, seen_package_identifiers=seen)
    with pytest.raises(CustodyError, match="replayed_custody_package"): validate_custody_package(package, seen_package_identifiers=seen)


def test_substituted_manifest_rejected(tmp_path):
    package, _, _ = _package(tmp_path); value = json.loads((package / "custody_manifest.json").read_text()); value["payload"]["backup_package_digest"] = "0" * 64
    (package / "custody_manifest.json").write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(CustodyError, match="custody_manifest_digest_invalid"): validate_custody_package(package)


def test_valid_custody_chain():
    events = _events("R3_CUSTODY_PACKAGE_TEST_0001")
    assert len(validate_chain(events, expected_chain_identifier=CHAIN, expected_package_identifier="R3_CUSTODY_PACKAGE_TEST_0001")) == 4


def test_broken_custody_chain_rejected():
    events = _events("R3_CUSTODY_PACKAGE_TEST_0001"); payload = unseal(events[2], label="event"); payload["previous_event_digest"] = "0" * 64; payload["event_digest"] = generate_digest({k: v for k, v in payload.items() if k != "event_digest"}); events[2] = seal(payload)
    with pytest.raises(CustodyError, match="broken_custody_chain"): validate_chain(events, expected_chain_identifier=CHAIN, expected_package_identifier="R3_CUSTODY_PACKAGE_TEST_0001")


def test_unknown_custody_chain_rejected():
    events = _events("R3_CUSTODY_PACKAGE_TEST_0001")
    with pytest.raises(CustodyError, match="unknown_custody_identifier"): validate_chain(events, expected_chain_identifier="R3_UNKNOWN_CHAIN_0001", expected_package_identifier="R3_CUSTODY_PACKAGE_TEST_0001")


def test_incorrect_receipt_rejected():
    events = _events("R3_CUSTODY_PACKAGE_TEST_0001"); payload = unseal(events[1], label="event"); payload["receipt_digest"] = None; payload["event_digest"] = generate_digest({k: v for k, v in payload.items() if k != "event_digest"}); events[1] = seal(payload)
    with pytest.raises(CustodyError, match="incorrect_receipt"): validate_chain(events, expected_chain_identifier=CHAIN, expected_package_identifier="R3_CUSTODY_PACKAGE_TEST_0001")


def test_key_custody_manifest_validates():
    assert validate_key_custody_manifest(_key_manifest())["private_key_material_present"] is False


def test_dual_control_required():
    keys = [public_key_record(key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", role="EXTERNAL_SIGNING", algorithm="ML-DSA", public_key=PUBLIC, sequence=1), public_key_record(key_identifier="R3_RECOVERY_ONLY_KEY_0001", role="RECOVERY_ONLY", algorithm="ML-DSA", public_key=PUBLIC, sequence=1)]
    with pytest.raises(CustodyError, match="dual_control_required"): create_key_custody_manifest(custody_identifier=KEY_CUSTODY, keys=keys, control_authorities=["one"])


def test_recovery_key_separation_required():
    keys = [public_key_record(key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", role="EXTERNAL_SIGNING", algorithm="ML-DSA", public_key=PUBLIC, sequence=1), public_key_record(key_identifier="R3_EXTERNAL_SIGNING_KEY_0002", role="EXTERNAL_SIGNING", algorithm="ML-DSA", public_key=PUBLIC, sequence=2)]
    with pytest.raises(CustodyError, match="recovery_key_separation_required"): create_key_custody_manifest(custody_identifier=KEY_CUSTODY, keys=keys, control_authorities=["a", "b"])


def test_private_key_text_rejected():
    bad = base64.b64encode(b"private-key-material-not-allowed").decode()
    with pytest.raises(CustodyError, match="public_key_invalid"): public_key_record(key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", role="EXTERNAL_SIGNING", algorithm="ML-DSA", public_key="private" + bad, sequence=1)


def test_signing_request_and_response_validate():
    request = signing_request(request_identifier="R3_SIGNING_REQUEST_0001", custody_identifier=KEY_CUSTODY, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", payload_digest="d" * 64, purpose="CUSTODY_MANIFEST", approvals=["a", "b"])
    response = signing_response(request=request, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", signature=SIGNATURE, algorithm="ML-DSA")
    assert validate_signing_response(response, request, _key_manifest())["key_identifier"] == "R3_EXTERNAL_SIGNING_KEY_0001"


def test_revoked_key_rejected():
    request = signing_request(request_identifier="R3_SIGNING_REQUEST_0001", custody_identifier=KEY_CUSTODY, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", payload_digest="d" * 64, purpose="CUSTODY_MANIFEST", approvals=["a", "b"])
    response = signing_response(request=request, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", signature=SIGNATURE, algorithm="ML-DSA")
    with pytest.raises(CustodyError): validate_signing_response(response, request, _key_manifest(), revoked_key_identifiers=["R3_EXTERNAL_SIGNING_KEY_0001"])


def test_signing_response_request_mismatch():
    request = signing_request(request_identifier="R3_SIGNING_REQUEST_0001", custody_identifier=KEY_CUSTODY, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", payload_digest="d" * 64, purpose="CUSTODY_MANIFEST", approvals=["a", "b"])
    other = signing_request(request_identifier="R3_SIGNING_REQUEST_0002", custody_identifier=KEY_CUSTODY, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", payload_digest="e" * 64, purpose="CUSTODY_MANIFEST", approvals=["a", "b"])
    response = signing_response(request=request, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", signature=SIGNATURE, algorithm="ML-DSA")
    with pytest.raises(CustodyError, match="signing_response_request_mismatch"): validate_signing_response(response, other, _key_manifest())


def test_revocation_and_rotation_records_are_sealed():
    assert unseal(revocation_record(custody_identifier=KEY_CUSTODY, key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", sequence=1, effective_at=TIMESTAMP, reason="incident", approvals=["a", "b"]), label="revocation")["record_type"] == "KEY_REVOCATION"
    assert unseal(rotation_record(custody_identifier=KEY_CUSTODY, old_key_identifier="R3_EXTERNAL_SIGNING_KEY_0001", new_key_identifier="R3_EXTERNAL_SIGNING_KEY_0002", sequence=2, effective_at=TIMESTAMP, approvals=["a", "b"]), label="rotation")["record_type"] == "KEY_ROTATION"


def test_media_manifest_validates(tmp_path):
    package, _, custody = _package(tmp_path); media = create_media_manifest(media_identifier="R3_RECOVERY_MEDIA_0001", custody_package_identifier=custody["custody_package_identifier"], custody_manifest_digest=custody["custody_manifest_digest"], package_checksum=custody["backup_package_digest"], copy_number=1)
    assert validate_media_manifest(media, expected_package_identifier=custody["custody_package_identifier"], expected_manifest_digest=custody["custody_manifest_digest"], expected_checksum=custody["backup_package_digest"])["status"] == "ACTIVE"


def test_corrupted_media_rejected(tmp_path):
    _, _, custody = _package(tmp_path); media = create_media_manifest(media_identifier="R3_RECOVERY_MEDIA_0001", custody_package_identifier=custody["custody_package_identifier"], custody_manifest_digest=custody["custody_manifest_digest"], package_checksum=custody["backup_package_digest"], copy_number=1)
    with pytest.raises(CustodyError, match="corrupted_recovery_media"): validate_media_manifest(media, expected_package_identifier=custody["custody_package_identifier"], expected_manifest_digest=custody["custody_manifest_digest"], expected_checksum="0" * 64)


def test_media_duplication_limit():
    with pytest.raises(CustodyError, match="media_duplication_policy_invalid"): create_media_manifest(media_identifier="R3_RECOVERY_MEDIA_0003", custody_package_identifier="R3_CUSTODY_PACKAGE_0001", custody_manifest_digest="d" * 64, package_checksum="e" * 64, copy_number=3)


@pytest.mark.parametrize("prior,new", [("ACTIVE", "RETIRED"), ("FAILED", "DESTROYED"), ("RETIRED", "DESTROYED")])
def test_media_lifecycle_valid(prior, new):
    assert unseal(media_lifecycle_record(media_identifier="R3_RECOVERY_MEDIA_0001", sequence=1, prior_status=prior, new_status=new, occurred_at=TIMESTAMP, reason="procedure", approvals=["a", "b"]), label="media")["new_status"] == new


def test_destroyed_media_cannot_reactivate():
    with pytest.raises(CustodyError, match="transition_invalid"): media_lifecycle_record(media_identifier="R3_RECOVERY_MEDIA_0001", sequence=2, prior_status="DESTROYED", new_status="ACTIVE", occurred_at=TIMESTAMP, reason="invalid", approvals=["a", "b"])


def test_recovery_invocation_requires_dual_control():
    with pytest.raises(CustodyError, match="dual_control"): recovery_invocation(invocation_identifier="R3_RECOVERY_INVOCATION_0001", media_identifier="R3_RECOVERY_MEDIA_0001", custody_package_identifier="R3_CUSTODY_PACKAGE_0001", requested_at=TIMESTAMP, approvals=["one"])


def test_complete_custody_continuity(tmp_path):
    package, keys, custody = _package(tmp_path); media = create_media_manifest(media_identifier="R3_RECOVERY_MEDIA_0001", custody_package_identifier=custody["custody_package_identifier"], custody_manifest_digest=custody["custody_manifest_digest"], package_checksum=custody["backup_package_digest"], copy_number=1)
    result = verify_custody_continuity(package, key_custody_manifest=keys, media_manifest=media, custody_events=_events(custody["custody_package_identifier"]), expected_repository_commit=COMMIT, expected_measured_baseline_identifier=BASELINE, expected_runtime_identity=IDENTITY, expected_key_manifest_digest=keys["payload_digest"], restore_result={"restore_status":"PASS","measured_startup_status":"MEASURED_STARTUP_APPROVED","runtime_status":"PASS","replay_status":"PASS"})
    assert result["status"] == "R3_CUSTODY_ASSURANCE_PASS"


def test_incomplete_custody_continuity_rejected(tmp_path):
    package, keys, custody = _package(tmp_path); media = create_media_manifest(media_identifier="R3_RECOVERY_MEDIA_0001", custody_package_identifier=custody["custody_package_identifier"], custody_manifest_digest=custody["custody_manifest_digest"], package_checksum=custody["backup_package_digest"], copy_number=1)
    with pytest.raises(CustodyError, match="custody_chain_incomplete"): verify_custody_continuity(package, key_custody_manifest=keys, media_manifest=media, custody_events=_events(custody["custody_package_identifier"], complete=False), expected_repository_commit=COMMIT, expected_measured_baseline_identifier=BASELINE, expected_runtime_identity=IDENTITY, expected_key_manifest_digest=keys["payload_digest"])


def test_failed_post_restore_assurance_rejected(tmp_path):
    package, keys, custody = _package(tmp_path); media = create_media_manifest(media_identifier="R3_RECOVERY_MEDIA_0001", custody_package_identifier=custody["custody_package_identifier"], custody_manifest_digest=custody["custody_manifest_digest"], package_checksum=custody["backup_package_digest"], copy_number=1)
    with pytest.raises(CustodyError, match="post_restore_assurance_failed"): verify_custody_continuity(package, key_custody_manifest=keys, media_manifest=media, custody_events=_events(custody["custody_package_identifier"]), expected_repository_commit=COMMIT, expected_measured_baseline_identifier=BASELINE, expected_runtime_identity=IDENTITY, expected_key_manifest_digest=keys["payload_digest"], restore_result={"restore_status":"FAIL"})


def test_missing_recovery_media_rejected(tmp_path):
    package, keys, custody = _package(tmp_path)
    with pytest.raises(CustodyError, match="recovery_media_missing"): verify_custody_continuity(package, key_custody_manifest=keys, media_manifest=None, custody_events=_events(custody["custody_package_identifier"]), expected_repository_commit=COMMIT, expected_measured_baseline_identifier=BASELINE, expected_runtime_identity=IDENTITY, expected_key_manifest_digest=keys["payload_digest"])
