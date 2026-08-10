from __future__ import annotations

import os

import pytest

from sbp_lex.api.schema_validation import (
    MAX_JSON_DEPTH,
    MAX_RUNTIME_REQUEST_BYTES,
    validate_runtime_request_schema,
)
from sbp_lex.runtime.fault_injection import (
    CRITICAL_SEAMS,
    FAULT_CLASSES,
    TEST_ENABLE_VARIABLE,
    FaultInjectionDisabled,
    FaultSpec,
    InjectedFault,
    TestFaultInjector as FaultInjector,
)
from sbp_lex.runtime.resilience_soak import (
    CASE_ORDER,
    EXTENDED_SOAK_MODES,
    _handle_count,
    _process_working_set_bytes,
    _retained_handle_growth_bounded,
    run_deterministic_soak,
)
from sbp_lex.runtime.resource_budgets import (
    USAGE_TO_BUDGET,
    BoundedLocalCapacity,
    ResourceBudgetPolicy,
    build_resource_budget_snapshot,
    validate_resource_usage,
)
from sbp_lex.security.pqc import generate_digest


def _fault(seam: str, fault_class: str = "exception") -> FaultSpec:
    return FaultSpec(
        fault_id=f"PASS8-{seam}-{fault_class}",
        seam=seam,
        fault_class=fault_class,
        request_fingerprint="f" * 64,
    )


def test_resource_policy_covers_every_declared_usage_and_accepts_exact_bounds() -> None:
    policy = ResourceBudgetPolicy()
    assert set(USAGE_TO_BUDGET.values()) == set(policy.as_dict())
    usage = {
        name: getattr(policy, budget_name)
        for name, budget_name in USAGE_TO_BUDGET.items()
    }
    result = validate_resource_usage(usage, policy=policy)
    assert result.allowed is True
    assert result.failures == ()


def test_resource_budget_snapshot_is_digest_bound_and_non_authoritative() -> None:
    snapshot = build_resource_budget_snapshot()
    payload = {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    assert snapshot["snapshot_digest"] == generate_digest(payload)
    assert snapshot["operational_authority"] is False
    assert snapshot["usage_metric_count"] == len(USAGE_TO_BUDGET)


def test_resource_snapshot_audit_limits_match_event_bus_enforcement() -> None:
    from sbp_lex.runtime.event_bus import (
        MAX_EVENT_PAYLOAD_KEYS,
        MAX_EVENT_PAYLOAD_STRING_LENGTH,
    )

    policy = ResourceBudgetPolicy()
    assert policy.maximum_audit_event_keys == MAX_EVENT_PAYLOAD_KEYS
    assert (
        policy.maximum_audit_event_string_length
        == MAX_EVENT_PAYLOAD_STRING_LENGTH
    )


@pytest.mark.parametrize("name", sorted(USAGE_TO_BUDGET))
def test_every_resource_budget_fails_closed_above_its_bound(name: str) -> None:
    policy = ResourceBudgetPolicy()
    maximum = getattr(policy, USAGE_TO_BUDGET[name])
    result = validate_resource_usage({name: maximum + 1}, policy=policy)
    assert result.allowed is False
    assert result.failures == (f"resource_limit_reached:{name}",)


@pytest.mark.parametrize(
    ("usage", "reason"),
    [
        ({"unknown": 1}, "resource_metric_unknown:unknown"),
        ({"request_bytes": -1}, "resource_metric_invalid:request_bytes"),
        ({"request_bytes": True}, "resource_metric_invalid:request_bytes"),
    ],
)
def test_resource_usage_rejects_unknown_or_invalid_measurements(usage, reason) -> None:
    result = validate_resource_usage(usage)
    assert result.allowed is False
    assert reason in result.failures


def test_bounded_local_capacity_rejects_duplicate_and_saturation() -> None:
    capacity = BoundedLocalCapacity(2)
    assert capacity.acquire("request-a") is True
    assert capacity.acquire("request-a") is False
    assert capacity.acquire("request-b") is True
    assert capacity.acquire("request-c") is False
    assert capacity.status() == {"active": 2, "maximum": 2}
    capacity.release("request-a")
    assert capacity.acquire("request-c") is True


@pytest.mark.parametrize("maximum", (0, -1, True))
def test_bounded_local_capacity_rejects_invalid_bounds(maximum) -> None:
    with pytest.raises(ValueError, match="local_capacity_bound_invalid"):
        BoundedLocalCapacity(maximum)


def test_existing_schema_validator_rejects_oversized_request() -> None:
    request = {"action": "PASS8", "objective": "x" * MAX_RUNTIME_REQUEST_BYTES}
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert "request_size_limit_exceeded" in failures


def test_existing_schema_validator_rejects_excessive_depth() -> None:
    nested: object = "value"
    for _ in range(MAX_JSON_DEPTH + 2):
        nested = {"level": nested}
    valid, failures = validate_runtime_request_schema(
        {"action": "PASS8", "payload": {"parameters": nested}}
    )
    assert valid is False
    assert any(reason.startswith("json_depth_exceeded:") for reason in failures)


def test_fault_injection_is_unavailable_in_normal_runtime() -> None:
    with pytest.raises(FaultInjectionDisabled, match="fault_injection_unavailable"):
        FaultInjector({}, explicitly_enabled=False, environ={})
    with pytest.raises(FaultInjectionDisabled, match="fault_injection_unavailable"):
        FaultInjector({}, explicitly_enabled=True, environ={})


@pytest.mark.parametrize("seam", sorted(CRITICAL_SEAMS))
def test_every_critical_seam_has_deterministic_fail_closed_injection(seam: str) -> None:
    events: list[tuple[str, object]] = []
    injector = FaultInjector(
        {seam: _fault(seam)},
        explicitly_enabled=True,
        environ={TEST_ENABLE_VARIABLE: "1"},
        event_sink=lambda event, payload: events.append((event, payload)),
    )
    with pytest.raises(InjectedFault) as caught:
        injector.trigger(seam, request_fingerprint="f" * 64)
    assert caught.value.record["authority_granted"] is False
    assert caught.value.record["execution_result"] == "HALT"
    assert events[0][0] == "fault_injection_activated"
    assert len(injector.records()) == 1


@pytest.mark.parametrize("fault_class", sorted(FAULT_CLASSES))
def test_every_fault_class_is_supported_without_authority(fault_class: str) -> None:
    seam = "execution_gate"
    injector = FaultInjector(
        {seam: _fault(seam, fault_class)},
        explicitly_enabled=True,
        environ={TEST_ENABLE_VARIABLE: "1"},
    )
    try:
        result = injector.trigger(seam, request_fingerprint="f" * 64)
    except InjectedFault as exc:
        record = exc.record
    else:
        record = result["fault_record"]
    assert record["authority_granted"] is False
    assert record["test_only"] is True
    assert record["fault_class"] == fault_class


def test_fault_identity_mismatch_does_not_activate_fault() -> None:
    injector = FaultInjector(
        {"execution_gate": _fault("execution_gate")},
        explicitly_enabled=True,
        environ={TEST_ENABLE_VARIABLE: "1"},
    )
    assert injector.trigger("execution_gate", request_fingerprint="0" * 64) is None
    assert injector.records() == []


def test_short_soak_is_balanced_bounded_and_replay_complete() -> None:
    result = run_deterministic_soak(
        duration_seconds=0.15,
        warmup_seconds=0.02,
        sample_interval_seconds=0.01,
        iteration_interval_seconds=0.001,
    )
    assert result["pass_status"] == "PASS"
    assert result["external_services_used"] is False
    assert result["live_effects_used"] is False
    assert result["workload_count"] >= len(CASE_ORDER)
    assert max(result["workload_mix"].values()) - min(result["workload_mix"].values()) <= 1
    assert all(result["assertions"].values())
    assert result["counters"]["audit_records"] == result["workload_count"]
    assert result["counters"]["integrity_ledger_records"] == result["workload_count"]
    assert result["counters"]["replay_records"] == result["workload_count"]
    assert result["counters"]["token_validations"] == result["workload_count"]
    assert result["wall_clock_case_latency_ms"]["bounded_sample_count"] > 0
    assert result["wall_clock_case_latency_ms"]["maximum"] >= 0
    assert (
        result["resource_summary"]["memory_growth_observation"]
        ["universal_threshold_used"]
        is False
    )
    assert "process_working_set_bytes" in result["resource_summary"]["baseline"]
    assert "open_file_count" in result["resource_summary"]["baseline"]
    assert (
        result["resource_summary"]["handle_growth_observation"]["reference"]
        == "warmup_end"
    )


@pytest.mark.parametrize(
    ("reference_count", "end_count", "expected"),
    [
        (216, 208, True),
        (216, 216, True),
        (216, 218, True),
        (216, 219, False),
        (None, None, True),
    ],
)
def test_handle_growth_assessment_measures_retained_upward_growth(
    reference_count: int | None,
    end_count: int | None,
    expected: bool,
) -> None:
    assert _retained_handle_growth_bounded(reference_count, end_count) is expected


def test_short_pass9_migration_aware_soak_binds_every_workload_and_checkpoint() -> None:
    result = run_deterministic_soak(
        duration_seconds=0.15,
        warmup_seconds=0.02,
        sample_interval_seconds=0.01,
        iteration_interval_seconds=0.001,
        migration_aware=True,
        trust_classification="ISOLATED_TEST_TRUST",
        migration_checkpoint_interval=2,
    )
    assert result["pass_status"] == "PASS"
    assert result["migration_aware"] is True
    assert result["migration_context"]["trust_classification"] == "ISOLATED_TEST_TRUST"
    assert result["migration_context"]["private_key_material_recorded"] is False
    assert result["counters"]["profile_bound_workloads"] == result["workload_count"]
    assert result["counters"]["migration_checkpoint_failures"] == 0
    assert result["counters"]["migration_checkpoint_passes"] > 0
    assert all(result["assertions"].values())


def test_windows_process_resource_adapters_return_real_measurements() -> None:
    if os.name != "nt":
        pytest.skip("Windows Desktop V1 resource adapter")
    handles = _handle_count()
    working_set = _process_working_set_bytes()
    assert isinstance(handles, int) and handles > 0
    assert isinstance(working_set, int) and working_set > 0


def test_extended_soak_modes_remain_available_but_are_not_implicitly_run() -> None:
    assert EXTENDED_SOAK_MODES == {
        "required_30m": 1800,
        "extended_2h": 7200,
        "extended_4h": 14400,
        "extended_8h": 28800,
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"duration_seconds": 0},
        {"duration_seconds": 1, "warmup_seconds": 1},
        {"duration_seconds": 1, "sample_interval_seconds": 0},
        {"duration_seconds": 1, "iteration_interval_seconds": -1},
        {
            "duration_seconds": 1,
            "migration_aware": True,
            "trust_classification": "NOT_APPLICABLE",
        },
        {"duration_seconds": 1, "migration_checkpoint_interval": 0},
    ],
)
def test_soak_rejects_unbounded_or_invalid_configuration(kwargs) -> None:
    with pytest.raises(ValueError):
        run_deterministic_soak(**kwargs)
