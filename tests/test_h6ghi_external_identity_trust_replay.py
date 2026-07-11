from __future__ import annotations

import json
import threading
from copy import deepcopy
from pathlib import Path

import pytest

from external_substrates.demo.build_demo_pre_context_package import build_demo_chain
from external_substrates.shared.canonical_json import canonical_dumps
from external_substrates.shared.external_boundary import ExternalBoundaryError, adapt_external_chain
from external_substrates.shared.external_replay_store import ExternalReplayStore, ExternalReplayStoreError
from external_substrates.shared.source_crypto import (
    ALGORITHM,
    PURPOSE,
    encode_public_key,
    generate_source_keypair,
    sign_source_package,
)
from external_substrates.shared.source_trust_store import (
    ExternalSourceTrustStore,
    ExternalTrustStoreError,
    authorize_trust_change,
    trust_record_values,
)

NOW = "2026-06-19T00:01:00Z"
BEFORE = "2026-06-18T00:00:00Z"
AFTER = "2026-06-20T00:00:00Z"


def authorization(action: str, source: str, key: str) -> dict:
    return authorize_trust_change(
        action=action, source_id=source, key_id=key,
        approval_reference=f"H6GHI-TEST-{action}-{source}-{key}",
    )


def record(
    source: str, substrate: str, key: str, public: bytes, *, status: str = "ACTIVE",
    version: int = 1, start: str = BEFORE, end: str = AFTER,
    algorithm: str = ALGORITHM, replacement: str | None = None,
    package_types: list[str] | None = None, schemas: list[str] | None = None,
) -> dict:
    return trust_record_values(
        source_id=source, substrate_type=substrate, key_id=key, key_version=version,
        algorithm=algorithm, public_verification_material=encode_public_key(public),
        allowed_package_types=package_types or [f"external_{substrate.lower()}_signal_package"],
        allowed_schema_versions=schemas or ["1.0"], not_before=start, expires_at=end,
        status=status, replacement_key_id=replacement,
        revoked_at=NOW if status == "REVOKED" else None,
        revocation_reason="test revocation" if status == "REVOKED" else None,
    )


def new_trust_store(tmp_path: Path) -> ExternalSourceTrustStore:
    root = tmp_path / "trust"
    store = ExternalSourceTrustStore(root / "store.json", allowed_root=root)
    store.initialize(authorization("INITIALIZE", "local-admin", "store"))
    return store


def append(store: ExternalSourceTrustStore, values: dict) -> dict:
    return store.append(
        values,
        authorization("APPEND_TRUST_RECORD", values["source_id"], values["key_id"]),
    )


def new_replay_store(tmp_path: Path, name: str = "replay") -> ExternalReplayStore:
    root = tmp_path / name
    store = ExternalReplayStore(root / "ledger.jsonl", allowed_root=root)
    store.initialize()
    return store


def managed_fixture(tmp_path: Path):
    skg_private, skg_public = generate_source_keypair()
    dtn_private, dtn_public = generate_source_keypair()
    trust = new_trust_store(tmp_path)
    append(trust, record("skg-demo-source", "SKG", "skg-key-1", skg_public))
    append(trust, record("dtn-demo-source", "DTN", "dtn-key-1", dtn_public))
    skg, dtn, pre = build_demo_chain()
    skg = sign_source_package(
        skg, private_key=skg_private, source_id="skg-demo-source",
        key_id="skg-key-1", substrate_type="SKG",
    )
    dtn = sign_source_package(
        dtn, private_key=dtn_private, source_id="dtn-demo-source",
        key_id="dtn-key-1", substrate_type="DTN",
    )
    return skg, dtn, pre, trust, new_replay_store(tmp_path), skg_private, dtn_private


def accept(fixture) -> dict:
    skg, dtn, pre, trust, replay, *_ = fixture
    return adapt_external_chain(
        *(canonical_dumps(item) for item in (skg, dtn, pre)),
        now=NOW, trust_store=trust, replay_store=replay,
    )


def test_valid_skg_and_dtn_asymmetric_signatures_are_domain_separated(tmp_path: Path) -> None:
    result = accept(managed_fixture(tmp_path))
    assert result["object_type"] == "ExternalIngressEnvelope"
    assert result["canonical_traversal_state"] is False


@pytest.mark.parametrize("target", ["skg", "dtn"])
def test_wrong_source_key_fails_closed(tmp_path: Path, target: str) -> None:
    fixture = list(managed_fixture(tmp_path))
    wrong_private, _ = generate_source_keypair()
    index = 0 if target == "skg" else 1
    package = fixture[index]
    fixture[index] = sign_source_package(
        package, private_key=wrong_private,
        source_id=f"{target}-demo-source", key_id=f"{target}-key-1",
        substrate_type=target.upper(),
    )
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))


@pytest.mark.parametrize(
    ("package_index", "substrate", "source", "key"),
    [(0, "DTN", "skg-demo-source", "dtn-key-1"), (1, "SKG", "dtn-demo-source", "skg-key-1")],
)
def test_cross_substrate_key_use_fails(tmp_path: Path, package_index, substrate, source, key) -> None:
    fixture = list(managed_fixture(tmp_path))
    private = fixture[6] if package_index == 0 else fixture[5]
    fixture[package_index] = sign_source_package(
        fixture[package_index], private_key=private, source_id=source,
        key_id=key, substrate_type=substrate,
    )
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))


@pytest.mark.parametrize(
    ("field", "value"),
    [("purpose", "RUNTIME_AUTHORITY"), ("algorithm", "HMAC-SHA256"), ("algorithm", "UNKNOWN")],
)
def test_wrong_purpose_downgrade_and_unknown_algorithm_fail(tmp_path: Path, field, value) -> None:
    fixture = list(managed_fixture(tmp_path))
    fixture[0]["signature"][field] = value
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))


def test_wrong_package_class_and_schema_permission_fail(tmp_path: Path) -> None:
    fixture = list(managed_fixture(tmp_path))
    trust = fixture[3]
    _, public = generate_source_keypair()
    with pytest.raises(ExternalTrustStoreError):
        append(trust, record("skg-demo-source", "SKG", "bad-class", public, package_types=["external_dtn_signal_package"]))
    values = record("skg-demo-source", "SKG", "schema-key", public, schemas=["2.0"])
    append(trust, values)
    fixture[0]["signature"]["key_id"] = "schema-key"
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))


@pytest.mark.parametrize("status", ["PENDING", "ROTATING", "SUSPENDED", "REVOKED", "EXPIRED", "RETIRED"])
def test_only_active_keys_verify_new_packages(tmp_path: Path, status: str) -> None:
    private, public = generate_source_keypair()
    trust = new_trust_store(tmp_path)
    append(trust, record("source", "SKG", "key", public, status=status))
    with pytest.raises(ExternalTrustStoreError):
        trust.active_record(
            source_id="source", key_id="key", substrate_type="SKG",
            package_type="external_skg_signal_package", schema_version="1.0", now=NOW,
        )
    assert private not in canonical_dumps(trust.export_public_records()).encode()


def test_expired_validity_period_fails(tmp_path: Path) -> None:
    _, public = generate_source_keypair()
    trust = new_trust_store(tmp_path)
    append(trust, record("source", "SKG", "key", public, end="2026-06-18T01:00:00Z"))
    with pytest.raises(ExternalTrustStoreError, match="expired"):
        trust.active_record(
            source_id="source", key_id="key", substrate_type="SKG",
            package_type="external_skg_signal_package", schema_version="1.0", now=NOW,
        )


def test_bounded_rotation_overlap_and_expiry(tmp_path: Path) -> None:
    _, old_public = generate_source_keypair()
    _, new_public = generate_source_keypair()
    trust = new_trust_store(tmp_path)
    append(trust, record("source", "SKG", "old", old_public, end="2026-06-19T00:08:00Z"))
    append(trust, record("source", "SKG", "old", old_public, version=2, end="2026-06-19T00:08:00Z", replacement="new"))
    append(trust, record("source", "SKG", "new", new_public, start="2026-06-19T00:00:00Z"))
    assert trust.active_record(source_id="source", key_id="old", substrate_type="SKG", package_type="external_skg_signal_package", schema_version="1.0", now=NOW)
    assert trust.active_record(source_id="source", key_id="new", substrate_type="SKG", package_type="external_skg_signal_package", schema_version="1.0", now=NOW)
    with pytest.raises(ExternalTrustStoreError):
        trust.active_record(source_id="source", key_id="old", substrate_type="SKG", package_type="external_skg_signal_package", schema_version="1.0", now="2026-06-19T00:09:00Z")


def test_rotation_overlap_and_replacement_scope_broadening_fail(tmp_path: Path) -> None:
    _, old_public = generate_source_keypair()
    _, new_public = generate_source_keypair()
    trust = new_trust_store(tmp_path)
    append(trust, record("source", "SKG", "old", old_public, end="2026-06-19T01:00:00Z", replacement="new"))
    with pytest.raises(ExternalTrustStoreError, match="overlap"):
        append(trust, record("source", "SKG", "new", new_public, start="2026-06-19T00:00:00Z"))
    with pytest.raises(ExternalTrustStoreError):
        append(trust, record("source", "SKG", "new", new_public, package_types=["external_skg_signal_package", "forbidden"]))


def test_malformed_key_signature_altered_package_and_source_identity_fail(tmp_path: Path) -> None:
    fixture = list(managed_fixture(tmp_path))
    fixture[0]["signature"]["signature"] = "not-base64"
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))
    fixture = list(managed_fixture(tmp_path / "altered"))
    fixture[0]["signals"] = {}
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))
    fixture = list(managed_fixture(tmp_path / "identity"))
    fixture[0]["signature"]["source_id"] = "different-source"
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))


def test_malformed_public_key_is_rejected_at_administration(tmp_path: Path) -> None:
    trust = new_trust_store(tmp_path)
    values = record("source", "SKG", "key", generate_source_keypair()[1])
    values["public_verification_material"] = "not-a-key"
    with pytest.raises(ExternalTrustStoreError, match="public_key"):
        append(trust, values)


def test_missing_corrupt_rollback_and_stale_checkpoint_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "missing"
    missing = ExternalSourceTrustStore(root / "store.json", allowed_root=root)
    with pytest.raises(ExternalTrustStoreError):
        missing.validate()
    trust = new_trust_store(tmp_path / "corrupt")
    trust.path.write_text("{}", encoding="utf-8")
    with pytest.raises(ExternalTrustStoreError):
        trust.validate()
    trust = new_trust_store(tmp_path / "rollback")
    old_checkpoint = trust.checkpoint_path.read_bytes()
    _, public = generate_source_keypair()
    append(trust, record("source", "SKG", "key", public))
    trust.checkpoint_path.write_bytes(old_checkpoint)
    with pytest.raises(ExternalTrustStoreError, match="checkpoint"):
        trust.validate()


def test_trust_store_rollback_with_current_anchor_fails(tmp_path: Path) -> None:
    trust = new_trust_store(tmp_path)
    old_store = trust.path.read_bytes()
    old_checkpoint = trust.checkpoint_path.read_bytes()
    _, public = generate_source_keypair()
    append(trust, record("source", "SKG", "key", public))
    trust.path.write_bytes(old_store)
    trust.checkpoint_path.write_bytes(old_checkpoint)
    with pytest.raises(ExternalTrustStoreError, match="rollback"):
        trust.validate()


def test_unauthorised_trust_store_mutation_fails(tmp_path: Path) -> None:
    trust = new_trust_store(tmp_path)
    _, public = generate_source_keypair()
    with pytest.raises(ExternalTrustStoreError, match="unauthorised"):
        trust.append(record("source", "SKG", "key", public), {})


def replay_accept(store: ExternalReplayStore, **overrides) -> dict:
    values = {
        "external_package_id": "package-1", "canonical_package_digest": "a" * 64,
        "source_id": "source-1", "key_id": "key-1", "substrate_type": "SKG",
        "issued_timestamp": "2026-06-19T00:00:00Z", "accepted_timestamp": NOW,
        "freshness_window": 300,
    }
    values.update(overrides)
    return store.accept(**values)


def test_replay_survives_process_restart_and_reconstructed_state(tmp_path: Path) -> None:
    store = new_replay_store(tmp_path)
    replay_accept(store)
    reconstructed = ExternalReplayStore(store.path, allowed_root=store.path.parent)
    with pytest.raises(ExternalReplayStoreError, match="replay"):
        replay_accept(reconstructed)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"canonical_package_digest": "b" * 64}, "content_changed"),
        ({"external_package_id": "package-2"}, "digest_reused"),
        ({"source_id": "source-2"}, "cross_source"),
    ],
)
def test_replay_substitution_variants_fail(tmp_path: Path, overrides, reason) -> None:
    store = new_replay_store(tmp_path)
    replay_accept(store)
    with pytest.raises(ExternalReplayStoreError, match=reason):
        replay_accept(store, **overrides)


def test_concurrent_duplicate_acceptance_allows_exactly_one(tmp_path: Path) -> None:
    store = new_replay_store(tmp_path)
    results: list[str] = []
    barrier = threading.Barrier(2)
    def worker() -> None:
        instance = ExternalReplayStore(store.path, allowed_root=store.path.parent)
        barrier.wait()
        try:
            replay_accept(instance)
        except ExternalReplayStoreError:
            results.append("rejected")
        else:
            results.append("accepted")
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for item in threads:
        item.start()
    for item in threads:
        item.join()
    assert sorted(results) == ["accepted", "rejected"]
    assert len(store.records()) == 1


def test_replay_truncation_corruption_and_checkpoint_rollback_fail(tmp_path: Path) -> None:
    store = new_replay_store(tmp_path / "truncated")
    replay_accept(store)
    store.path.write_bytes(store.path.read_bytes()[:-1])
    with pytest.raises(ExternalReplayStoreError, match="truncated"):
        store.validate()
    store = new_replay_store(tmp_path / "corrupted")
    store.path.write_bytes(b"not-json\n")
    with pytest.raises(ExternalReplayStoreError, match="corrupted"):
        store.validate()
    store = new_replay_store(tmp_path / "checkpoint")
    old = store.checkpoint_path.read_bytes()
    replay_accept(store)
    store.checkpoint_path.write_bytes(old)
    with pytest.raises(ExternalReplayStoreError, match="checkpoint"):
        store.validate()


def test_replay_ledger_deletion_and_anchor_rollback_fail(tmp_path: Path) -> None:
    store = new_replay_store(tmp_path / "deleted")
    store.path.unlink()
    with pytest.raises(ExternalReplayStoreError, match="missing"):
        store.validate()
    store = new_replay_store(tmp_path / "rollback")
    old_ledger = store.path.read_bytes()
    old_checkpoint = store.checkpoint_path.read_bytes()
    replay_accept(store)
    store.path.write_bytes(old_ledger)
    store.checkpoint_path.write_bytes(old_checkpoint)
    with pytest.raises(ExternalReplayStoreError, match="rollback"):
        store.validate()


def test_retention_never_removes_active_protection(tmp_path: Path) -> None:
    store = new_replay_store(tmp_path)
    replay_accept(store)
    assert store.compact(now="2026-06-19T00:05:00Z", maximum_records=0) == 0
    assert len(store.records()) == 1
    assert store.compact(now="2026-06-19T00:20:00Z", maximum_records=0) == 1
    assert store.records() == []


def test_private_keys_never_enter_trust_or_replay_state(tmp_path: Path) -> None:
    fixture = managed_fixture(tmp_path)
    accept(fixture)
    private_values = (fixture[5], fixture[6])
    persisted = fixture[3].path.read_bytes() + fixture[4].path.read_bytes()
    assert all(value not in persisted for value in private_values)
    assert "private" not in persisted.decode("utf-8").lower()


def test_failure_produces_no_eie_and_protected_state_is_mandatory(tmp_path: Path) -> None:
    skg, dtn, pre = build_demo_chain()
    with pytest.raises(ExternalBoundaryError, match="protected_external_security_state_required"):
        adapt_external_chain(*(canonical_dumps(item) for item in (skg, dtn, pre)), now=NOW)
    fixture = list(managed_fixture(tmp_path))
    fixture[0]["signature"]["signature"] = "poisoned"
    with pytest.raises(ExternalBoundaryError):
        accept(tuple(fixture))
    assert fixture[4].records() == []
