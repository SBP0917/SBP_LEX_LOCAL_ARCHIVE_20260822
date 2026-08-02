from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import sbp_lex.api.server as server_module
import sbp_lex.runtime.canonical_runtime as runtime_module
import sbp_lex.runtime.measured_startup as measured_module
from sbp_lex.runtime.measured_startup import (
    DEFAULT_MEASUREMENT_POLICY,
    MeasuredStartupError,
    MeasuredStartupService,
    MeasurementPolicy,
    add_pending_baseline,
    approve_pending_baseline,
    baseline_record,
    compare_measurements,
    create_baseline_store,
    drift_class_for,
    load_baseline_store,
    measure_runtime,
    runtime_identity_for,
    validate_baseline_store,
    verify_startup_attestation,
    write_baseline_store,
)

FIXED_TIME = "2030-01-01T00:00:00+00:00"
POLICY = MeasurementPolicy(
    category_patterns={
        "software": ("software/*.py",),
        "configuration": ("config/*.json",),
        "policy": ("policy/*.json",),
        "schema": ("schemas/*.schema.json",),
        "trust_store": ("trust/*.json",),
        "documentation": ("docs/*.md",),
    },
    required_paths=(
        "software/app.py", "config/runtime.json", "policy/execution.json",
        "schemas/request.schema.json", "trust/root.json", "docs/lock.md",
        "requirements.txt",
    ),
    public_environment_names=("APP_MODE",),
    secret_environment_names=("APP_SECRET",),
)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    write(root / "software/app.py", "VALUE = 1\n")
    write(root / "config/runtime.json", '{"mode":"local"}\n')
    write(root / "policy/execution.json", '{"allow":"bounded"}\n')
    write(root / "schemas/request.schema.json", '{"type":"object"}\n')
    write(root / "trust/root.json", '{"trust":"approved"}\n')
    write(root / "docs/lock.md", "# Approved lock\n")
    write(root / "requirements.txt", "pytest>=8.0.0\n")
    return root


def approved_store(root: Path, environment=None, identifier="DESKTOP_V1_TEST_BASELINE_01"):
    measurement = measure_runtime(root, policy=POLICY, environ=environment or {})
    record = baseline_record(
        identifier, measurement, sequence=1, status="APPROVED",
        approval_reference="explicit-test-owner-approval", created_at=FIXED_TIME,
    )
    return create_baseline_store(record)


def service_for(tmp_path: Path, root: Path, environment=None) -> MeasuredStartupService:
    baseline_path = root / "approved_runtime_baselines.json"
    if not baseline_path.exists():
        write_baseline_store(baseline_path, approved_store(root, environment))
    return MeasuredStartupService(
        repository_root=root, baseline_path=baseline_path,
        state_root=tmp_path / "state", policy=POLICY, environ=environment or {},
    )


def assert_drift(service: MeasuredStartupService, expected_class="critical"):
    with pytest.raises(MeasuredStartupError) as captured:
        service.validate_startup(persist=False)
    assert captured.value.drift_class == expected_class


def test_default_policy_measures_trust_implementation_not_mutable_evidence():
    measured = {
        path
        for patterns in DEFAULT_MEASUREMENT_POLICY.category_patterns.values()
        for path in patterns
    }
    required = set(DEFAULT_MEASUREMENT_POLICY.required_paths)
    critical = {
        "sbp_lex/security/pqc.py",
        "sbp_lex/security/pqc_provider.py",
        "sbp_lex/local_trust/signing.py",
        "sbp_lex/supply_chain/provenance.py",
        "sbp_lex/ivvp/verifier.py",
        "sbp_lex/runtime/schemas/startup_attestation.schema.json",
        "sbp_lex/execution/schemas/execution_traversal_authority.schema.json",
        "sbp_lex/execution/schemas/adapter_completion_evidence.schema.json",
    }
    assert critical <= measured | required
    assert not any(path.startswith("outputs/") for path in measured | required)
    assert not any(path.startswith("reports/") for path in measured | required)


def test_approved_measured_startup_and_identity_are_deterministic(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    first = service.validate_startup(
        startup_time=datetime(2030, 1, 1, tzinfo=timezone.utc), persist=False,
    )
    second = service.validate_startup(
        startup_time=datetime(2031, 1, 1, tzinfo=timezone.utc), persist=False,
    )
    assert first["status"] == "MEASURED_STARTUP_APPROVED"
    assert first["drift_class"] == "approved"
    assert first["runtime_identity"] == second["runtime_identity"]
    assert first["startup_attestation_digest"] != second["startup_attestation_digest"]


@pytest.mark.linkage_assurance
def test_runtime_drift_checks_retain_specific_startup_attestation_binding(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    startup = service.validate_startup()
    checked = service.check_runtime_drift()

    assert checked["status"] == "MEASURED_STARTUP_APPROVED"
    assert checked["runtime_identity"] == startup["runtime_identity"]
    assert checked["approved_baseline_identifier"] == startup["approved_baseline_identifier"]
    assert checked["measurement_digest"] == startup["measurement_digest"]
    assert checked["startup_attestation_digest"] == startup["startup_attestation_digest"]
    assert checked["startup_sequence"] == startup["startup_sequence"]


@pytest.mark.linkage_assurance
def test_startup_binding_uses_the_complete_signed_attestation_wrapper(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    startup = service.validate_startup()
    attestation = measured_module._load_json(service.attestation_path)
    anchor = measured_module._validate_anchor(
        measured_module._load_json(service.anchor_path)
    )
    wrapper_digest = measured_module.generate_digest(attestation)
    assert startup["startup_attestation_digest"] == wrapper_digest
    assert anchor["last_attestation_digest"] == wrapper_digest
    assert wrapper_digest != attestation["payload_digest"]


@pytest.mark.linkage_assurance
def test_resigned_anchor_or_attestation_substitution_fails_during_runtime(
    tmp_path,
):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    service.validate_startup()

    anchor = measured_module._validate_anchor(
        measured_module._load_json(service.anchor_path)
    )
    substituted_anchor = {
        **anchor,
        "startup_sequence": anchor["startup_sequence"] + 1,
    }
    measured_module._atomic_write(
        service.anchor_path,
        measured_module._anchor_wrapper(substituted_anchor),
    )
    with pytest.raises(MeasuredStartupError):
        service.check_runtime_drift()

    replacement = service_for(tmp_path / "replacement", root)
    replacement.validate_startup()
    attestation = measured_module._load_json(replacement.attestation_path)
    substituted_attestation = measured_module._store_wrapper({
        **attestation["payload"],
        "startup_timestamp_evidence": "2031-01-01T00:00:00+00:00",
    })
    measured_module._atomic_write(
        replacement.attestation_path, substituted_attestation,
    )
    with pytest.raises(
        MeasuredStartupError, match="startup_attestation_anchor_mismatch",
    ):
        replacement.check_runtime_drift()


@pytest.mark.linkage_assurance
def test_coherently_resigned_anchor_and_attestation_cannot_replace_baseline_binding(
    tmp_path,
):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    service.validate_startup()
    attestation = measured_module._load_json(service.attestation_path)
    anchor = measured_module._validate_anchor(
        measured_module._load_json(service.anchor_path)
    )
    substituted_attestation = measured_module._store_wrapper({
        **attestation["payload"],
        "runtime_identity": "0" * 64,
        "measurement_digest": "1" * 64,
    })
    substituted_anchor = measured_module._anchor_wrapper({
        **anchor,
        "last_attestation_digest": measured_module.generate_digest(
            substituted_attestation
        ),
    })
    measured_module._atomic_write(
        service.attestation_path, substituted_attestation,
    )
    measured_module._atomic_write(service.anchor_path, substituted_anchor)

    restarted = service_for(tmp_path, root)
    with pytest.raises(
        MeasuredStartupError,
        match="startup_attestation_baseline_binding_invalid",
    ):
        restarted.validate_startup()


@pytest.mark.parametrize("missing", ["anchor", "attestation"])
@pytest.mark.linkage_assurance
def test_orphaned_startup_chain_components_fail_closed(tmp_path, missing):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    service.validate_startup()
    if missing == "anchor":
        service.anchor_path.unlink()
        expected = "startup_attestation_orphaned"
    else:
        service.attestation_path.unlink()
        expected = "startup_attestation_missing"
    restarted = service_for(tmp_path, root)
    with pytest.raises(MeasuredStartupError, match=expected):
        restarted.validate_startup()


@pytest.mark.parametrize(
    "relative,replacement",
    [
        ("config/runtime.json", '{"mode":"private"}\n'),
        ("policy/execution.json", '{"allow":"unbounded"}\n'),
        ("schemas/request.schema.json", '{"type":"array"}\n'),
        ("trust/root.json", '{"trust":"replaced"}\n'),
        ("docs/lock.md", "# Changed lock\n"),
        ("software/app.py", "VALUE = 2\n"),
    ],
)
def test_file_category_modifications_are_critical_drift(tmp_path, relative, replacement):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    write(root / relative, replacement)
    assert_drift(service)


def test_dependency_declaration_modification_is_detected(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    write(root / "requirements.txt", "pytest==0.0.1\n")
    assert_drift(service)


def test_deleted_measured_file_fails_closed(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    (root / "policy/execution.json").unlink()
    assert_drift(service, "unknown")


def test_unexpected_additional_module_is_detected(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    write(root / "software/injected.py", "ALLOW = True\n")
    assert_drift(service)


def test_baseline_measurement_hash_mismatch_is_rejected(tmp_path):
    root = fixture_root(tmp_path)
    store = approved_store(root)
    store["payload"]["baselines"][0]["measurement"]["measurement_digest"] = "0" * 64
    forged = measured_module._store_wrapper(store["payload"])
    path = root / "approved_runtime_baselines.json"
    measured_module._atomic_write(path, forged)
    with pytest.raises(MeasuredStartupError, match="baseline_measurement_digest_mismatch"):
        load_baseline_store(path)


def test_baseline_runtime_identity_mismatch_is_rejected(tmp_path):
    root = fixture_root(tmp_path)
    store = approved_store(root)
    store["payload"]["baselines"][0]["runtime_identity"] = "0" * 64
    forged = measured_module._store_wrapper(store["payload"])
    path = root / "approved_runtime_baselines.json"
    measured_module._atomic_write(path, forged)
    with pytest.raises(MeasuredStartupError, match="baseline_runtime_identity_mismatch"):
        load_baseline_store(path)


def test_requested_baseline_mismatch_fails_closed(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(
        tmp_path, root,
        {"SBP_LEX_APPROVED_RUNTIME_BASELINE": "DESKTOP_V1_OTHER_BASELINE"},
    )
    assert_drift(service)


def test_pending_baseline_is_not_automatically_accepted(tmp_path):
    root = fixture_root(tmp_path)
    store = approved_store(root)
    write(root / "config/runtime.json", '{"mode":"updated"}\n')
    pending = baseline_record(
        "DESKTOP_V1_TEST_BASELINE_02", measure_runtime(root, policy=POLICY, environ={}),
        sequence=2, status="PENDING", created_at=FIXED_TIME,
    )
    updated = add_pending_baseline(store, pending)
    path = root / "approved_runtime_baselines.json"
    write_baseline_store(path, updated)
    service = MeasuredStartupService(
        repository_root=root, baseline_path=path, state_root=tmp_path / "state",
        policy=POLICY, environ={},
    )
    assert_drift(service)


def test_startup_after_explicitly_approved_update_succeeds(tmp_path):
    root = fixture_root(tmp_path)
    path = root / "approved_runtime_baselines.json"
    original = approved_store(root)
    write_baseline_store(path, original)
    service = service_for(tmp_path, root)
    service.validate_startup()
    write(root / "config/runtime.json", '{"mode":"approved-update"}\n')
    pending = baseline_record(
        "DESKTOP_V1_TEST_BASELINE_02", measure_runtime(root, policy=POLICY, environ={}),
        sequence=2, status="PENDING", created_at=FIXED_TIME,
    )
    proposed = add_pending_baseline(original, pending)
    approved = approve_pending_baseline(
        proposed, "DESKTOP_V1_TEST_BASELINE_02",
        approval_reference="explicit-update-approval",
        retire_approved_identifier="DESKTOP_V1_TEST_BASELINE_01",
    )
    write_baseline_store(path, approved)
    result = service.validate_startup()
    assert result["approved_baseline_identifier"] == "DESKTOP_V1_TEST_BASELINE_02"


def test_startup_accepts_complete_intermediate_baseline_lineage(tmp_path):
    root = fixture_root(tmp_path)
    path = root / "approved_runtime_baselines.json"
    original = approved_store(root)
    write_baseline_store(path, original)
    service = service_for(tmp_path, root)
    service.validate_startup()

    write(root / "config/runtime.json", '{"mode":"approved-update-2"}\n')
    second = baseline_record(
        "DESKTOP_V1_TEST_BASELINE_02", measure_runtime(root, policy=POLICY, environ={}),
        sequence=2, status="PENDING", created_at=FIXED_TIME,
    )
    store_two = approve_pending_baseline(
        add_pending_baseline(original, second), "DESKTOP_V1_TEST_BASELINE_02",
        approval_reference="explicit-update-2-approval",
        retire_approved_identifier="DESKTOP_V1_TEST_BASELINE_01",
    )

    write(root / "config/runtime.json", '{"mode":"approved-update-3"}\n')
    third = baseline_record(
        "DESKTOP_V1_TEST_BASELINE_03", measure_runtime(root, policy=POLICY, environ={}),
        sequence=3, status="PENDING", created_at=FIXED_TIME,
    )
    store_three = approve_pending_baseline(
        add_pending_baseline(store_two, third), "DESKTOP_V1_TEST_BASELINE_03",
        approval_reference="explicit-update-3-approval",
        retire_approved_identifier="DESKTOP_V1_TEST_BASELINE_02",
    )
    write_baseline_store(path, store_three)

    result = service.validate_startup()
    assert result["approved_baseline_identifier"] == "DESKTOP_V1_TEST_BASELINE_03"


def test_environment_mutation_and_secret_mutation_are_detected(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root, {"APP_MODE": "local", "APP_SECRET": "secret-one"})
    changed = MeasuredStartupService(
        repository_root=root, baseline_path=root / "approved_runtime_baselines.json",
        state_root=tmp_path / "other-state", policy=POLICY,
        environ={"APP_MODE": "private", "APP_SECRET": "secret-two"},
    )
    assert_drift(changed)
    baseline_text = (root / "approved_runtime_baselines.json").read_text("utf-8")
    assert "secret-one" not in baseline_text


def test_duplicate_baseline_identifiers_are_rejected(tmp_path):
    root = fixture_root(tmp_path)
    store = approved_store(root)
    duplicate = json.loads(json.dumps(store["payload"]["baselines"][0]))
    duplicate["sequence"] = 2
    duplicate["status"] = "RETIRED"
    store["payload"]["baselines"].append(duplicate)
    forged = measured_module._store_wrapper(store["payload"])
    with pytest.raises(MeasuredStartupError, match="duplicate_baseline_identifier"):
        validate_baseline_store(forged)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("generation_bool", "baseline_store_generation_invalid"),
        ("sequence_bool", "baseline_sequence_invalid"),
        ("status_container", "baseline_record_state_invalid"),
        ("path_traversal", "baseline_file_measurement_invalid"),
        (
            "duplicate_environment",
            "baseline_environment_measurement_order_invalid",
        ),
        (
            "category_digest_missing",
            "baseline_category_digest_contract_invalid",
        ),
    ],
)
@pytest.mark.linkage_assurance
def test_resigned_malformed_baseline_contracts_fail_closed(
    mutation, expected, tmp_path,
):
    root = fixture_root(tmp_path)
    payload = deepcopy(approved_store(root)["payload"])
    record = payload["baselines"][0]
    measurement = record["measurement"]
    if mutation == "generation_bool":
        payload["generation"] = True
    elif mutation == "sequence_bool":
        record["sequence"] = True
    elif mutation == "status_container":
        record["status"] = ["APPROVED"]
    elif mutation == "path_traversal":
        measurement["categories"]["software"][0]["path"] = "../software/app.py"
    elif mutation == "duplicate_environment":
        measurement["environment"].append(
            deepcopy(measurement["environment"][0])
        )
    elif mutation == "category_digest_missing":
        measurement["category_digests"].pop("software")

    forged = measured_module._store_wrapper(payload)
    with pytest.raises(MeasuredStartupError, match=expected):
        validate_baseline_store(forged)


def test_corrupted_and_missing_baseline_fail_closed(tmp_path):
    root = fixture_root(tmp_path)
    path = root / "approved_runtime_baselines.json"
    path.write_text("{corrupt", encoding="utf-8")
    service = MeasuredStartupService(
        repository_root=root, baseline_path=path, state_root=tmp_path / "state",
        policy=POLICY, environ={},
    )
    assert_drift(service, "unknown")
    path.unlink()
    assert_drift(service, "unknown")


def test_measurement_anchor_corruption_fails_closed(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    service.validate_startup()
    service.anchor_path.write_text("{}", encoding="utf-8")
    replacement = service_for(tmp_path, root)
    with pytest.raises(MeasuredStartupError) as captured:
        replacement.validate_startup()
    assert captured.value.drift_class == "unknown"


def test_measurement_rollback_is_detected_against_anchor(tmp_path):
    root = fixture_root(tmp_path)
    path = root / "approved_runtime_baselines.json"
    original = approved_store(root)
    write_baseline_store(path, original)
    service = service_for(tmp_path, root)
    service.validate_startup()
    write(root / "config/runtime.json", '{"mode":"approved-update"}\n')
    pending = baseline_record(
        "DESKTOP_V1_TEST_BASELINE_02", measure_runtime(root, policy=POLICY, environ={}),
        sequence=2, created_at=FIXED_TIME,
    )
    updated = approve_pending_baseline(
        add_pending_baseline(original, pending), "DESKTOP_V1_TEST_BASELINE_02",
        approval_reference="explicit-update-approval",
        retire_approved_identifier="DESKTOP_V1_TEST_BASELINE_01",
    )
    write_baseline_store(path, updated)
    service.validate_startup()
    write_baseline_store(path, original)
    assert_drift(service_for(tmp_path, root))


def test_measurement_attestation_replay_is_rejected(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    service.validate_startup()
    attestation = measured_module._load_json(service.attestation_path)
    anchor = measured_module._validate_anchor(measured_module._load_json(service.anchor_path))
    assert not verify_startup_attestation(attestation, anchor)


@pytest.mark.linkage_assurance
def test_runtime_drift_after_validated_startup_fails_closed(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    service.validate_startup()
    write(root / "software/app.py", "VALUE = 999\n")
    with pytest.raises(MeasuredStartupError, match="runtime_measurement_drift"):
        service.check_runtime_drift()
    assert service.status() == {
        "status": "MEASURED_STARTUP_NOT_VALIDATED",
        "runtime_identity": None,
        "approved_baseline_identifier": None,
        "measurement_digest": None,
        "startup_attestation_digest": None,
        "startup_sequence": None,
    }


def test_unexpected_executable_measurement_change_is_detected(tmp_path, monkeypatch):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    original = measured_module._executable_record
    monkeypatch.setattr(
        measured_module, "_executable_record",
        lambda: {**original(), "sha256": "0" * 64},
    )
    assert_drift(service)


def test_drift_classification_supports_approved_warning_critical_unknown():
    assert drift_class_for([]) == "approved"
    assert drift_class_for([measured_module.DriftFinding("warning", "w", "c")]) == "warning"
    assert drift_class_for([measured_module.DriftFinding("critical", "c", "c")]) == "critical"
    assert drift_class_for([measured_module.DriftFinding("unknown", "u", "c")]) == "unknown"


def test_runtime_identity_contains_digests_not_secret_values(tmp_path):
    root = fixture_root(tmp_path)
    measurement = measure_runtime(
        root, policy=POLICY, environ={"APP_SECRET": "never-embed-this-secret"},
    )
    identity = runtime_identity_for(measurement, "DESKTOP_V1_TEST_BASELINE_01")
    assert len(identity) == 64
    assert "never-embed-this-secret" not in identity
    assert "never-embed-this-secret" not in json.dumps(measurement)


def test_runtime_identity_binds_every_measurement_category(tmp_path):
    root = fixture_root(tmp_path)
    measurement = measure_runtime(root, policy=POLICY, environ={})
    identifier = "DESKTOP_V1_TEST_BASELINE_01"
    original = runtime_identity_for(measurement, identifier)
    changed = deepcopy(measurement)
    changed["category_digests"]["future_assurance_surface"] = "f" * 64
    assert runtime_identity_for(changed, identifier) != original


def test_required_measurement_path_must_be_hash_scoped(tmp_path):
    root = fixture_root(tmp_path)
    unscoped_policy = replace(
        POLICY,
        required_paths=(*POLICY.required_paths, "unscoped.txt"),
    )
    write(root / "unscoped.txt", "must be measured\n")
    with pytest.raises(
        MeasuredStartupError,
        match="required_measurement_unscoped:unscoped.txt",
    ):
        measure_runtime(root, policy=unscoped_policy, environ={})


@pytest.mark.linkage_assurance
def test_default_policy_hashes_linkage_assurance_assets():
    root = Path(__file__).resolve().parents[1]
    measurement = measure_runtime(
        root,
        policy=DEFAULT_MEASUREMENT_POLICY,
        environ={},
    )
    measured_paths = {
        record["path"]
        for records in measurement["categories"].values()
        for record in records
    }
    assert {
        "scripts/run_tests.bat",
        "scripts/run_tests.sh",
        "scripts/run_linkage_assurance.bat",
        "scripts/run_linkage_assurance.sh",
        "docs/STARTUP_EXECUTION_LINKAGE_ASSURANCE.md",
        "tests/test_h7_deterministic_execution_integrity.py",
        "tests/test_h8_measured_startup_runtime_identity.py",
        "tests/test_r2_supply_chain_build_provenance.py",
        "tests/test_r4_independent_verification_package.py",
    }.issubset(measured_paths)


def test_startup_attestation_binds_timestamp_without_changing_identity(tmp_path):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    result = service.validate_startup(
        startup_time=datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    attestation = measured_module._load_json(service.attestation_path)
    assert attestation["payload"]["startup_timestamp_evidence"] == "2030-01-02T03:04:05+00:00"
    assert attestation["payload"]["runtime_identity"] == result["runtime_identity"]
    assert verify_startup_attestation(attestation)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("startup_sequence", True),
        ("startup_sequence", 0),
        ("startup_timestamp_evidence", "not-a-timestamp"),
        ("baseline_store_digest", "not-a-digest"),
        ("runtime_identity", "not-a-digest"),
        ("measurement_digest", "not-a-digest"),
    ],
)
@pytest.mark.linkage_assurance
def test_resigned_malformed_startup_attestation_is_rejected(
    field, replacement, tmp_path,
):
    root = fixture_root(tmp_path)
    service = service_for(tmp_path, root)
    service.validate_startup()
    attestation = measured_module._load_json(service.attestation_path)
    malformed_payload = {**attestation["payload"], field: replacement}
    malformed = measured_module._store_wrapper(malformed_payload)
    assert not verify_startup_attestation(malformed)


@pytest.mark.linkage_assurance
def test_startup_attestation_schema_matches_exact_runtime_contract():
    schema_path = (
        Path(measured_module.__file__).parent
        / "schemas"
        / "startup_attestation.schema.json"
    )
    schema = json.loads(schema_path.read_text("utf-8"))
    assert set(schema["required"]) == {
        "payload", "payload_digest", "integrity_signature",
    }
    assert (
        set(schema["properties"]["payload"]["required"])
        == measured_module.STARTUP_ATTESTATION_FIELDS
    )


def test_listener_does_not_bind_when_measured_startup_fails(monkeypatch):
    reached = []
    monkeypatch.setattr(
        server_module, "ensure_measured_startup",
        lambda: (_ for _ in ()).throw(MeasuredStartupError("test_drift", "critical")),
    )
    monkeypatch.setattr(
        server_module, "ThreadingHTTPServer",
        lambda *args, **kwargs: reached.append((args, kwargs)),
    )
    with pytest.raises(MeasuredStartupError, match="test_drift"):
        server_module.run_server(port=0)
    assert reached == []


def test_canonical_runtime_does_not_create_partial_state_on_measurement_failure(monkeypatch):
    runtime = runtime_module.CanonicalRuntime()
    before_events = runtime_module.RUNTIME_EVENTS.latest()
    monkeypatch.setattr(
        runtime_module, "ensure_measured_startup",
        lambda: (_ for _ in ()).throw(MeasuredStartupError("test_drift", "critical")),
    )
    with pytest.raises(MeasuredStartupError):
        runtime.traverse({"action": "must-not-run", "payload": {}})
    assert runtime.traversal_count == 0
    assert runtime.last_result is None
    assert runtime_module.RUNTIME_EVENTS.latest() == before_events


def test_baseline_store_has_one_approved_and_supports_pending_retired_states(tmp_path):
    root = fixture_root(tmp_path)
    store = approved_store(root)
    pending = baseline_record(
        "DESKTOP_V1_TEST_BASELINE_02", measure_runtime(root, policy=POLICY, environ={}),
        sequence=2, status="PENDING", created_at=FIXED_TIME,
    )
    proposed = add_pending_baseline(store, pending)
    approved = approve_pending_baseline(
        proposed, "DESKTOP_V1_TEST_BASELINE_02",
        approval_reference="explicit-owner-approval",
        retire_approved_identifier="DESKTOP_V1_TEST_BASELINE_01",
    )
    payload = validate_baseline_store(approved)
    statuses = {item["baseline_identifier"]: item["status"] for item in payload["baselines"]}
    assert statuses == {
        "DESKTOP_V1_TEST_BASELINE_01": "RETIRED",
        "DESKTOP_V1_TEST_BASELINE_02": "APPROVED",
    }


def test_new_baseline_cannot_be_approved_without_explicit_reference(tmp_path):
    root = fixture_root(tmp_path)
    store = approved_store(root)
    pending = baseline_record(
        "DESKTOP_V1_TEST_BASELINE_02", measure_runtime(root, policy=POLICY, environ={}),
        sequence=2, created_at=FIXED_TIME,
    )
    with pytest.raises(MeasuredStartupError, match="explicit_baseline_approval_required"):
        approve_pending_baseline(
            add_pending_baseline(store, pending), "DESKTOP_V1_TEST_BASELINE_02",
            approval_reference="", retire_approved_identifier="DESKTOP_V1_TEST_BASELINE_01",
        )
