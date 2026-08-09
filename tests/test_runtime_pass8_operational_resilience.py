from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from sbp_lex.recovery.backup import create_backup, validate_backup_package
from sbp_lex.recovery.common import RecoveryError
from sbp_lex.recovery.inventory import ArtifactSpec, build_inventory
from sbp_lex.recovery.restore import restore_backup, validate_authoritative_restore
from sbp_lex.runtime.operational_resilience import (
    FAILED_CLOSED,
    PROCESSING,
    QUARANTINED,
    READY,
    RECOVERY_REQUIRED,
    STOPPED,
    OperationalResilienceError,
    RuntimeLifecycleController,
    RuntimeOwnershipManager,
    SupervisedCanonicalRuntime,
    assess_recovery_record,
    build_recovery_record,
    persist_recovery_record,
    quarantine_recovery_record,
)
from sbp_lex.runtime.event_bus import RuntimeEventBus


COMMIT = "a" * 40
IDENTITY = "b" * 64
BASELINE = "DESKTOP_V1_PASS8_TEST_BASELINE_01"


def measurement(identity: str = IDENTITY) -> dict:
    return {
        "status": "MEASURED_STARTUP_APPROVED",
        "runtime_identity": identity,
        "approved_baseline_identifier": BASELINE,
        "measurement_digest": "c" * 64,
        "startup_attestation_digest": "d" * 64,
        "startup_sequence": 1,
    }


def recovery_record(
    *, stage: str = "hard_entry_pending", decision=None,
    execution_result=None, effect_status: str = "NOT_ATTEMPTED",
    identity: str = IDENTITY,
) -> dict:
    return build_recovery_record(
        request_fingerprint="request-pass8",
        runtime_identity=identity,
        repository_commit=COMMIT,
        stage=stage,
        decision=decision,
        execution_result=execution_result,
        effect_status=effect_status,
        state_hash=None,
    )


def test_process_supervision_blocks_duplicate_runtime(tmp_path: Path) -> None:
    lock = tmp_path / "runtime-owner.json"
    first = RuntimeOwnershipManager(
        lock, allowed_root=tmp_path, process_exists=lambda _: True,
    )
    claimed = first.claim(
        runtime_id="CANONICAL_RUNTIME", runtime_identity=IDENTITY,
        repository_commit=COMMIT, pid=101,
    )
    assert claimed["status"] == "RUNTIME_OWNERSHIP_CLAIMED"
    second = RuntimeOwnershipManager(
        lock, allowed_root=tmp_path, process_exists=lambda _: True,
    )
    with pytest.raises(OperationalResilienceError, match="duplicate_runtime_ownership"):
        second.claim(
            runtime_id="CANONICAL_RUNTIME", runtime_identity=IDENTITY,
            repository_commit=COMMIT, pid=202,
        )
    assert first.release()["status"] == "RUNTIME_OWNERSHIP_RELEASED"


def test_stale_runtime_lock_is_validated_and_preserved_before_recovery(tmp_path: Path) -> None:
    lock = tmp_path / "runtime-owner.json"
    original = RuntimeOwnershipManager(
        lock, allowed_root=tmp_path, process_exists=lambda _: True,
    )
    original.claim(
        runtime_id="CANONICAL_RUNTIME", runtime_identity=IDENTITY,
        repository_commit=COMMIT, pid=101,
    )
    replacement = RuntimeOwnershipManager(
        lock, allowed_root=tmp_path, process_exists=lambda _: False,
    )
    result = replacement.claim(
        runtime_id="CANONICAL_RUNTIME", runtime_identity=IDENTITY,
        repository_commit=COMMIT, pid=202,
    )
    assert result["stale_owner_recovered"] is True
    assert Path(result["stale_record"]["stale_lock_path"]).is_file()
    assert result["authority_granted"] is False
    replacement.release()


def test_corrupt_runtime_lock_fails_closed(tmp_path: Path) -> None:
    lock = tmp_path / "runtime-owner.json"
    lock.write_text("{corrupt", encoding="utf-8")
    manager = RuntimeOwnershipManager(
        lock, allowed_root=tmp_path, process_exists=lambda _: False,
    )
    with pytest.raises(OperationalResilienceError, match="runtime_lock_corrupt"):
        manager.claim(
            runtime_id="CANONICAL_RUNTIME", runtime_identity=IDENTITY,
            repository_commit=COMMIT,
        )


def test_lifecycle_startup_requires_measured_identity_and_has_no_authority() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    status = lifecycle.start(measurement())
    assert status["lifecycle_state"] == READY
    assert status["authority_granted"] is False
    assert status["resume_authority"] is False
    with pytest.raises(OperationalResilienceError, match="runtime_already_started"):
        lifecycle.start(measurement())


def test_invalid_measured_startup_fails_closed() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    invalid = measurement()
    invalid["status"] = "MEASURED_STARTUP_REJECTED"
    with pytest.raises(OperationalResilienceError, match="measured_startup_invalid"):
        lifecycle.start(invalid)
    assert lifecycle.state == FAILED_CLOSED
    assert lifecycle.status()["accepting_work"] is False


def test_idle_and_repeated_shutdown_are_deterministic() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    lifecycle.start(measurement())
    first = lifecycle.request_shutdown()
    second = lifecycle.request_shutdown()
    assert first["lifecycle_state"] == STOPPED
    assert second["lifecycle_state"] == STOPPED
    assert second["accepting_work"] is False


def test_lifecycle_events_use_existing_bounded_signed_event_bus() -> None:
    event_bus = RuntimeEventBus()
    lifecycle = RuntimeLifecycleController(
        "CANONICAL_RUNTIME",
        event_sink=event_bus.emit,
    )
    lifecycle.start(measurement())
    lifecycle.request_shutdown()
    valid, failures = event_bus.verify()
    assert valid is True, failures
    events = event_bus.latest()
    assert events
    assert all("payload" in event for event in events)


@pytest.mark.parametrize("stage", (
    "ingress", "root_of_trust", "procedural_truth", "governance",
    "domain", "aurion", "execution_gate", "audit_finalisation",
))
def test_mid_stage_shutdown_invalidates_incomplete_work_without_success(stage: str) -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    lifecycle.start(measurement())
    lifecycle.begin_traversal("request-mid-stage")
    lifecycle.advance_traversal("request-mid-stage", stage)
    lifecycle.register_pending_capability("pending-capability")
    result = lifecycle.request_shutdown(invalidate_active=True)
    assert result["lifecycle_state"] == STOPPED
    assert result["active_traversal_count"] == 0
    assert result["pending_capability_count"] == 0
    assert lifecycle.can_issue_capability() is False
    assert all(record["authority_granted"] is False for record in lifecycle.records())
    assert any(record["event_type"] == "traversal_invalidated" for record in lifecycle.records())


def test_draining_refuses_new_work_and_issues_no_capability() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    lifecycle.start(measurement())
    lifecycle.begin_traversal("active")
    result = lifecycle.request_shutdown(invalidate_active=False)
    assert result["lifecycle_state"] == "DRAINING"
    with pytest.raises(OperationalResilienceError, match="runtime_not_accepting_work"):
        lifecycle.begin_traversal("new")
    with pytest.raises(OperationalResilienceError, match="capability_issuance_blocked"):
        lifecycle.register_pending_capability("forbidden")
    lifecycle.complete_traversal("active", result="DENY:HALT")
    assert lifecycle.state == STOPPED


def test_crash_loop_and_recovery_attempts_are_bounded() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    lifecycle.start(measurement())
    for _ in range(3):
        lifecycle.unexpected_termination("synthetic_process_exit")
        assert lifecycle.state == RECOVERY_REQUIRED
        lifecycle.begin_recovery()
        recovered = lifecycle.complete_recovery(measurement(), recovery_record())
        assert recovered["lifecycle_state"] == READY
        assert recovered["recovery_assessment"]["resume_authority"] is False
    lifecycle.unexpected_termination("synthetic_process_exit")
    assert lifecycle.state == QUARANTINED
    assert lifecycle.status()["accepting_work"] is False


@pytest.mark.parametrize(("stage", "decision", "effect", "action"), (
    ("adapter", None, "NOT_ATTEMPTED", "FULL_INGRESS_REQUIRED"),
    ("state_construction", None, "NOT_ATTEMPTED", "FULL_PATH_REVALIDATION_REQUIRED"),
    ("procedural_truth", "DENY", "NOT_ATTEMPTED", "FULL_REENTRY_REQUIRED"),
    ("governance", "DENY", "NOT_ATTEMPTED", "FULL_REENTRY_REQUIRED"),
    ("governance", "ESCALATE", "NOT_ATTEMPTED", "FULL_REENTRY_REQUIRED"),
    ("domain_failed", None, "NOT_ATTEMPTED", "BOUNDED_NEW_CANDIDATE_REENTRY"),
    ("aurion_failed", None, "NOT_ATTEMPTED", "BOUNDED_NEW_CANDIDATE_REENTRY"),
    ("execution_gate_converged", "ALLOW", "NOT_ATTEMPTED", "CAPABILITY_INVALIDATE_AND_REVALIDATE"),
    ("synthetic_effect_attempt", "ALLOW", "UNKNOWN", "RECONCILIATION_REQUIRED_NO_RETRY"),
    ("audit_finalisation", "ALLOW", "SYNTHETIC_CONFIRMED", "EVIDENCE_REPAIR_NON_EXECUTING"),
))
def test_restart_matrix_never_restores_execution_authority(
    stage: str, decision: str | None, effect: str, action: str,
) -> None:
    record = recovery_record(
        stage=stage, decision=decision,
        execution_result="EXECUTE" if decision == "ALLOW" else "HALT",
        effect_status=effect,
    )
    result = assess_recovery_record(record, current_runtime_identity=IDENTITY)
    assert result["required_action"] == action
    assert result["resume_authority"] is False
    assert result["automatic_effect_retry"] is False
    assert result["authority_granted"] is False


def test_runtime_identity_mismatch_after_restart_blocks_recovery() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    lifecycle.start(measurement())
    lifecycle.unexpected_termination("synthetic_exit")
    lifecycle.begin_recovery()
    with pytest.raises(OperationalResilienceError, match="runtime_identity_mismatch"):
        lifecycle.complete_recovery(
            measurement("e" * 64),
            recovery_record(identity=IDENTITY),
        )
    assert lifecycle.state == FAILED_CLOSED


def test_pending_capability_cannot_be_reused_after_restart() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    lifecycle.start(measurement())
    lifecycle.register_pending_capability("pre-crash-capability")
    lifecycle.unexpected_termination("synthetic_exit")
    assert lifecycle.status()["pending_capability_count"] == 0
    lifecycle.begin_recovery()
    lifecycle.complete_recovery(measurement(), recovery_record())
    assert lifecycle.consume_pending_capability("pre-crash-capability") is False


def test_corrupted_recovery_record_is_quarantined_and_never_resumed(tmp_path: Path) -> None:
    record = recovery_record(stage="state_construction")
    record["record_digest"] = "0" * 64
    assessment = assess_recovery_record(record, current_runtime_identity=IDENTITY)
    assert assessment["quarantine_required"] is True
    assert assessment["authority_granted"] is False
    path = tmp_path / "recovery.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    result = quarantine_recovery_record(
        path, allowed_root=tmp_path, quarantine_root=tmp_path / "quarantine",
    )
    assert result["status"] == "QUARANTINED"
    assert result["authority_granted"] is False
    assert not path.exists()
    assert Path(result["quarantine_path"]).is_file()


def test_valid_recovery_record_is_atomically_persisted(tmp_path: Path) -> None:
    record = recovery_record(stage="terminal_complete", decision="DENY", execution_result="HALT")
    path = persist_recovery_record(
        tmp_path / "recovery.json", record, allowed_root=tmp_path,
    )
    assert json.loads(path.read_text("utf-8")) == record


class _FakeRuntime:
    def traverse(self, request, *, request_id, **kwargs):
        return {"state": {"decision": "DENY", "execution_result": "HALT"}}

    def issue_execution_capability(self, *args, **kwargs):
        return {"capability": "issued"}

    def replay(self, *args, **kwargs):
        return {"matched": True, "effect_authority": False}


def test_supervised_wrapper_never_changes_runtime_decision() -> None:
    lifecycle = RuntimeLifecycleController("CANONICAL_RUNTIME")
    lifecycle.start(measurement())
    wrapper = SupervisedCanonicalRuntime(_FakeRuntime(), lifecycle)
    result = wrapper.traverse({"action": "synthetic"}, request_id="request-1")
    assert result["state"] == {"decision": "DENY", "execution_result": "HALT"}
    assert lifecycle.state == READY
    lifecycle.request_shutdown()
    with pytest.raises(OperationalResilienceError, match="capability_issuance_blocked"):
        wrapper.issue_execution_capability("reference")


def _backup_fixture(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"mode":"desktop-v1"}\n', encoding="utf-8")
    spec = (
        ArtifactSpec(
            "configuration.foundation", "configuration", "config.json",
            "configuration/config.json", "REQUIRED", "PUBLIC_EVIDENCE",
            "json", 1, None, 100, "strict_json", "configuration_authority",
        ),
    )
    inventory = build_inventory(source, spec)
    backup = tmp_path / "backups" / "backup-1"
    create_backup(
        source, inventory, backup,
        repository_commit=COMMIT,
        measured_baseline_identifier=BASELINE,
        runtime_identity=IDENTITY,
        generation=1,
        approved_backup_root=tmp_path / "backups",
        creation_timestamp="2026-08-09T00:00:00+00:00",
    )
    return source, backup


def test_backup_manifest_and_separate_restore_validate(tmp_path: Path) -> None:
    _, backup = _backup_fixture(tmp_path)
    payload = validate_backup_package(backup)
    assert payload["repository_commit"] == COMMIT
    restore_root = tmp_path / "restore-root"
    result = restore_backup(
        backup, restore_root / "restored",
        approved_destination_root=restore_root,
        expected_repository_commit=COMMIT,
        expected_measured_baseline_identifier=BASELINE,
        expected_runtime_identity=IDENTITY,
        fresh_process_commands=((sys.executable, "-c", "raise SystemExit(0)"),),
    )
    assert result["status"] == "AUTHORITATIVE_RESTORE_VALID"
    assert validate_authoritative_restore(restore_root / "restored")["generation"] == 1


@pytest.mark.parametrize("mutation", ("missing", "mutated", "unexpected"))
def test_restore_rejects_missing_mutated_and_unexpected_artefacts(
    tmp_path: Path, mutation: str,
) -> None:
    _, backup = _backup_fixture(tmp_path)
    member = (
        backup
        / "domains"
        / "configuration"
        / "public_evidence"
        / "configuration"
        / "config.json"
    )
    if mutation == "missing":
        member.unlink()
    elif mutation == "mutated":
        member.write_text('{"mode":"substituted"}\n', encoding="utf-8")
    else:
        (backup / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(RecoveryError):
        validate_backup_package(backup)


def test_restore_rejects_commit_runtime_and_path_substitution(tmp_path: Path) -> None:
    _, backup = _backup_fixture(tmp_path)
    restore_root = tmp_path / "restore-root"
    with pytest.raises(RecoveryError, match="repository_commit_mismatch"):
        restore_backup(
            backup, restore_root / "restored",
            approved_destination_root=restore_root,
            expected_repository_commit="f" * 40,
            expected_measured_baseline_identifier=BASELINE,
            expected_runtime_identity=IDENTITY,
        )
    with pytest.raises(RecoveryError, match="runtime_identity_mismatch"):
        restore_backup(
            backup, restore_root / "restored",
            approved_destination_root=restore_root,
            expected_repository_commit=COMMIT,
            expected_measured_baseline_identifier=BASELINE,
            expected_runtime_identity="e" * 64,
        )
    with pytest.raises(RecoveryError):
        restore_backup(
            backup, tmp_path / "outside",
            approved_destination_root=restore_root,
            expected_repository_commit=COMMIT,
            expected_measured_baseline_identifier=BASELINE,
            expected_runtime_identity=IDENTITY,
        )
