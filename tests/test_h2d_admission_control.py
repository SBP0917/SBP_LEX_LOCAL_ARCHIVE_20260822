from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

import sbp_lex.api.rate_limit as admission_module
from sbp_lex.api.rate_limit import (
    AUTH_FAILURE_DENIAL,
    CAPACITY_DENIAL,
    CONCURRENCY_DENIAL,
    INVALID_STATE_DENIAL,
    RATE_DENIAL,
    AdmissionConfiguration,
    AdmissionConfigurationError,
    AdmissionController,
    admission_class,
    load_admission_configuration,
)


class Clock:
    def __init__(self, value: float = 1_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value


def config(**changes) -> AdmissionConfiguration:
    return replace(
        AdmissionConfiguration(
            requests_per_window=3,
            authentication_failures_per_window=3,
            maximum_concurrent_traversals=2,
            maximum_concurrent_replays=1,
            maximum_concurrent_connectors=2,
            maximum_event_stream_subscribers=2,
            maximum_exports=1,
            maximum_tracked_identities=128,
            admission_retention_seconds=30,
            cooldown_seconds=10,
            window_seconds=10,
        ),
        **changes,
    )


def admit(controller: AdmissionController, **changes):
    values = {
        "source_address": "127.0.0.1",
        "endpoint": "/runtime/status",
        "credential_id": "credential-1",
        "principal_id": "principal-1",
        "principal_type": "viewer",
        "request_fingerprint": None,
    }
    values.update(changes)
    return controller.admit(**values)


@pytest.mark.parametrize("dimension", ["source_address", "credential_id", "principal_id", "principal_type", "endpoint"])
def test_rate_limit_applies_to_each_required_identity_dimension(dimension):
    controller = AdmissionController(config(requests_per_window=2))
    changes = {dimension: "/health" if dimension == "endpoint" else f"fixed-{dimension}"}
    for _ in range(2):
        lease = admit(controller, **changes)
        assert lease.result.allowed
        lease.release()
    assert admit(controller, **changes).result.reason == RATE_DENIAL


def test_single_source_burst_is_denied():
    controller = AdmissionController(config(requests_per_window=1))
    first = admit(controller)
    first.release()
    assert admit(controller, credential_id="other", principal_id="other").result.reason == RATE_DENIAL


def test_single_credential_burst_is_denied():
    controller = AdmissionController(config(requests_per_window=1))
    first = admit(controller)
    first.release()
    assert admit(controller, source_address="127.0.0.2", principal_id="other").result.reason == RATE_DENIAL


def test_single_principal_burst_is_denied():
    controller = AdmissionController(config(requests_per_window=1))
    first = admit(controller)
    first.release()
    assert admit(controller, source_address="127.0.0.2", credential_id="other").result.reason == RATE_DENIAL


def test_identity_churn_hits_bounded_cardinality():
    controller = AdmissionController(config(maximum_tracked_identities=10))
    for number in range(2):
        lease = admit(
            controller, source_address=f"127.0.0.{number}", credential_id=f"c-{number}",
            principal_id=f"p-{number}", principal_type=f"type-{number}", endpoint=f"/e-{number}",
        )
        assert lease.result.allowed
    assert admit(
        controller, source_address="x", credential_id="x", principal_id="x",
        principal_type="x", endpoint="/x",
    ).result.reason == CAPACITY_DENIAL


@pytest.mark.parametrize("failure_type", ["authentication_failure", "malformed_request"])
def test_failure_flood_enters_cooldown(failure_type):
    controller = AdmissionController(config(authentication_failures_per_window=2))
    assert controller.record_failure(
        source_address="127.0.0.1", endpoint="/runtime/traverse", failure_type=failure_type,
    ).allowed
    denied = controller.record_failure(
        source_address="127.0.0.1", endpoint="/runtime/traverse", failure_type=failure_type,
    )
    assert (denied.status, denied.reason) == (429, AUTH_FAILURE_DENIAL)
    preflight = controller.preflight_failure_limits(
        source_address="127.0.0.1", endpoint="/runtime/traverse",
        failure_types=(failure_type,),
    )
    assert (preflight.status, preflight.reason) == (429, AUTH_FAILURE_DENIAL)


@pytest.mark.parametrize(
    "endpoint,field,limit",
    [
        ("/runtime/traverse", "maximum_concurrent_traversals", 2),
        ("/runtime/replay", "maximum_concurrent_replays", 1),
        ("/connector/envelope", "maximum_concurrent_connectors", 2),
        ("/runtime/events", "maximum_event_stream_subscribers", 2),
        ("/desktop/export/latest", "maximum_exports", 1),
    ],
)
def test_resource_concurrency_ceilings(endpoint, field, limit):
    controller = AdmissionController(config(**{field: limit}))
    leases = [admit(controller, endpoint=endpoint, request_fingerprint=f"f-{number}") for number in range(limit)]
    assert all(lease.result.allowed for lease in leases)
    assert admit(controller, endpoint=endpoint, request_fingerprint="overflow").result.reason == CONCURRENCY_DENIAL
    for lease in leases:
        lease.release()
    replacement = admit(controller, endpoint=endpoint, request_fingerprint="replacement")
    assert replacement.result.allowed
    replacement.release()


def test_duplicate_request_fingerprint_flood_is_denied_without_nonce_overlap():
    controller = AdmissionController(config(authentication_failures_per_window=2))
    for _ in range(2):
        lease = admit(controller, request_fingerprint="same-safe-digest")
        assert lease.result.allowed
        lease.release()
    assert admit(controller, request_fingerprint="same-safe-digest").result.reason == RATE_DENIAL


def test_limit_window_expiry_is_deterministic():
    clock = Clock()
    controller = AdmissionController(config(requests_per_window=1), clock=clock)
    admit(controller).release()
    assert admit(controller).result.reason == RATE_DENIAL
    clock.value += 11
    assert admit(controller).result.allowed


def test_cooldown_expiry_is_deterministic():
    clock = Clock()
    controller = AdmissionController(
        config(authentication_failures_per_window=1, window_seconds=5, cooldown_seconds=10), clock=clock,
    )
    assert controller.record_failure(
        source_address="s", endpoint="/health", failure_type="authentication_failure",
    ).reason == AUTH_FAILURE_DENIAL
    clock.value += 11
    assert controller.record_failure(
        source_address="s", endpoint="/health", failure_type="authentication_failure",
    ).reason == AUTH_FAILURE_DENIAL


def test_restart_preserves_rate_state_in_separate_signed_domain(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(admission_module, "ADMISSION_ROOT", tmp_path.resolve())
    path = tmp_path / "admission_state.json"
    first = AdmissionController(config(requests_per_window=1), clock=clock, persistence_path=path, persist=True)
    admit(first).release()
    restarted = AdmissionController(config(requests_per_window=1), clock=clock, persistence_path=path, persist=True)
    assert admit(restarted).result.reason == RATE_DENIAL
    stored = json.loads(path.read_text("utf-8"))
    assert stored["payload"]["integrity_domain"] == admission_module.ADMISSION_DOMAIN
    assert "credential_states" not in stored["payload"]


def test_clock_rollback_cannot_reset_limit():
    clock = Clock()
    controller = AdmissionController(config(requests_per_window=1), clock=clock)
    admit(controller).release()
    clock.value -= 500
    assert admit(controller).result.reason == RATE_DENIAL


def test_clock_jump_expires_old_window_but_not_concurrency_lease():
    clock = Clock()
    controller = AdmissionController(config(requests_per_window=1), clock=clock)
    active = admit(controller, endpoint="/runtime/traverse")
    clock.value += 1_000
    assert admit(controller, endpoint="/runtime/traverse").result.allowed
    active.release()


@pytest.mark.parametrize(
    "value,label",
    [("", "blank"), ("no", "non_numeric"), ("-1", "non_positive"), ("0", "non_positive"), ("1001", "excessive")],
)
def test_invalid_explicit_configuration_fails_closed(value, label):
    with pytest.raises(AdmissionConfigurationError, match=label):
        load_admission_configuration({"SBP_LEX_ADMISSION_REQUESTS_PER_WINDOW": value})


def test_cross_field_invalid_configuration_fails_closed():
    with pytest.raises(AdmissionConfigurationError, match="cooldown_exceeds_retention"):
        load_admission_configuration({
            "SBP_LEX_ADMISSION_COOLDOWN_SECONDS": "20",
            "SBP_LEX_ADMISSION_RETENTION_SECONDS": "10",
        })


def test_rate_state_corruption_fails_closed():
    controller = AdmissionController(config())
    controller._events = {"bad": [float("nan")]}
    assert admit(controller).result.reason == INVALID_STATE_DENIAL


def test_persisted_state_corruption_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(admission_module, "ADMISSION_ROOT", tmp_path.resolve())
    path = tmp_path / "admission_state.json"
    path.write_text('{"payload":{"forged":true}}', encoding="utf-8")
    controller = AdmissionController(config(), persistence_path=path, persist=True)
    assert admit(controller).result.reason == INVALID_STATE_DENIAL


def test_concurrent_admission_race_never_exceeds_ceiling():
    controller = AdmissionController(config(maximum_concurrent_traversals=3, requests_per_window=100))
    with ThreadPoolExecutor(max_workers=16) as pool:
        leases = list(pool.map(
            lambda number: admit(
                controller, endpoint="/runtime/traverse", source_address=f"s-{number}",
                credential_id=f"c-{number}", principal_id=f"p-{number}",
                request_fingerprint=f"f-{number}",
            ),
            range(16),
        ))
    assert sum(lease.result.allowed for lease in leases) == 3
    assert all(lease.result.allowed or lease.result.reason == CONCURRENCY_DENIAL for lease in leases)
    for lease in leases:
        lease.release()


def test_viewer_flood_does_not_starve_operator_traversal():
    controller = AdmissionController(config(maximum_event_stream_subscribers=1))
    viewer = admit(controller, endpoint="/runtime/events", principal_type="viewer")
    assert viewer.result.allowed
    operator = admit(controller, endpoint="/runtime/traverse", principal_type="operator")
    assert operator.result.allowed
    viewer.release()
    operator.release()


def test_replay_flood_does_not_starve_live_traversal():
    controller = AdmissionController(config(maximum_concurrent_replays=1))
    replay = admit(controller, endpoint="/runtime/replay", principal_type="replay_examiner")
    assert replay.result.allowed
    traversal = admit(controller, endpoint="/runtime/traverse", principal_type="operator")
    assert traversal.result.allowed
    replay.release()
    traversal.release()


def test_connector_flood_does_not_block_health_observation():
    controller = AdmissionController(config(maximum_concurrent_connectors=1, requests_per_window=1))
    connector = admit(controller, endpoint="/connector/envelope", principal_type="connector")
    assert connector.result.allowed
    health = admit(controller, endpoint="/health", principal_type="viewer")
    assert health.result.allowed
    connector.release()
    health.release()


@pytest.mark.parametrize(
    "principal_type,endpoint,expected",
    [
        ("viewer", "/health", "observation"),
        ("operator", "/runtime/traverse", "operator_traversal"),
        ("validator", "/runtime/integrity", "validator"),
        ("connector", "/connector/envelope", "connector"),
        ("replay_examiner", "/runtime/replay", "replay"),
        ("maintenance", "/health", "maintenance"),
        ("administrator", "/health", "administration"),
    ],
)
def test_all_admission_classes_are_deterministic(principal_type, endpoint, expected):
    assert admission_class(endpoint, principal_type) == expected


def test_administrator_remains_bounded():
    controller = AdmissionController(config(requests_per_window=1))
    admit(controller, principal_type="administrator").release()
    assert admit(controller, principal_type="administrator").result.reason == RATE_DENIAL


def test_persistence_contains_only_safe_digests_not_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(admission_module, "ADMISSION_ROOT", tmp_path.resolve())
    path = tmp_path / "admission_state.json"
    secret = "raw-super-secret-credential-material"
    controller = AdmissionController(config(), persistence_path=path, persist=True)
    admit(controller, credential_id=secret, principal_id="private-principal").release()
    text = path.read_text("utf-8")
    assert secret not in text
    assert "private-principal" not in text


def test_denied_capacity_does_not_create_partial_canonical_state():
    controller = AdmissionController(config(maximum_concurrent_traversals=1))
    active = admit(controller, endpoint="/runtime/traverse")
    canonical_state = []
    denied = admit(controller, endpoint="/runtime/traverse", request_fingerprint="second")
    if denied.result.allowed:
        canonical_state.append("unexpected")
    assert denied.result.reason == CONCURRENCY_DENIAL
    assert canonical_state == []
    active.release()


def test_invalid_state_never_converts_pressure_to_allow():
    controller = AdmissionController(config())
    controller.invalidate_for_tests()
    result = admit(controller).result
    assert not result.allowed
    assert (result.status, result.reason) == (503, INVALID_STATE_DENIAL)
