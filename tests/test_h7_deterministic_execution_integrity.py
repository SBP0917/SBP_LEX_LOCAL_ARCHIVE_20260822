from __future__ import annotations

import json
import threading
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

import sbp_lex.execution.capability as capability_module
import sbp_lex.execution.capability_store as capability_store_module
import sbp_lex.runtime.canonical_runtime as runtime_module
from main import sample_request
from sbp_lex.execution.capability import (
    ATTESTATION_PAYLOAD_FIELDS,
    CAPABILITY_FIELDS,
    ExecutionIntegrityError,
    ExecutionIntegrityService,
    ExecutionSpecification,
    authorize_control,
    binding_context,
    build_execution_traversal_authority,
    canonical_parameters,
    constraints_preserved,
    verify_capability,
    verify_execution_traversal_authority,
    verify_post_execution_attestation,
)
from sbp_lex.execution.capability_store import (
    CAPABILITY_FIELDS as STORE_CAPABILITY_FIELDS,
    CapabilityLifecycleStore,
    CapabilityStoreError,
)
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.runtime.canonical_runtime import CanonicalRuntime
from sbp_lex.security.pqc import generate_digest, sign_payload


NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
MEASUREMENT = {
    "status": "MEASURED_STARTUP_APPROVED",
    "runtime_identity": "TEST-H8-RUNTIME-IDENTITY",
    "approved_baseline_identifier": "TEST-H8-APPROVED-BASELINE",
    "measurement_digest": "a" * 64,
}
DEFAULT_PARAMETERS = {"level": 1}
DEFAULT_ALLOWED_FIELDS = ("level",)
DEFAULT_REQUIRED_FIELDS = ("level",)
DEFAULT_CONSTRAINTS = {
    "max_steps": 3,
    "min_classification": 2,
    "allowed_regions": ["AU", "NZ"],
    "licence_scope": "observe",
    "governance_required": True,
}


def _specification(
    *, safe_cancellation_supported: bool = False, **overrides: Any,
) -> ExecutionSpecification:
    values = {
        "specification_id": "test-action-target-1",
        "target_identity": "target-1",
        "target_type": "device",
        "operation_identity": "test_action",
        "allowed_parameter_fields": DEFAULT_ALLOWED_FIELDS,
        "required_parameter_fields": DEFAULT_REQUIRED_FIELDS,
        "constraints": DEFAULT_CONSTRAINTS,
        "adapter_identity": "adapter-1",
        "safe_cancellation_supported": safe_cancellation_supported,
    }
    values.update(overrides)
    return ExecutionSpecification(**values)


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)

    def set(self, value: datetime) -> None:
        self.value = value


class RecordingAdapter:
    identity = "adapter-1"

    def __init__(
        self, *, safe_cancellation_supported: bool = False,
        fail: bool = False, invalid_result: bool = False,
        checkpoint_during_execution: bool = False,
        before_checkpoint: Any = None,
    ) -> None:
        self.identity = "adapter-1"
        self.safe_cancellation_supported = safe_cancellation_supported
        self.fail = fail
        self.invalid_result = invalid_result
        self.checkpoint_during_execution = checkpoint_during_execution
        self.before_checkpoint = before_checkpoint
        self.calls = 0
        self.arguments: list[tuple[Any, ...]] = []
        self._lock = threading.Lock()

    def __call__(
        self, target: str, target_type: str, operation: str,
        parameters: Mapping[str, Any], checkpoint: Any,
    ) -> Mapping[str, Any]:
        with self._lock:
            self.calls += 1
            self.arguments.append((target, target_type, operation, deepcopy(dict(parameters))))
        if self.before_checkpoint is not None:
            self.before_checkpoint()
        if self.checkpoint_during_execution:
            checkpoint()
        if self.fail:
            raise RuntimeError("adapter communication lost")
        if self.invalid_result:
            return None  # type: ignore[return-value]
        return {"status": "DONE", "target": target, "operation": operation}


class BlockingCancellableAdapter(RecordingAdapter):
    def __init__(self) -> None:
        super().__init__(safe_cancellation_supported=True)
        self.started = threading.Event()
        self.release = threading.Event()
        self.termination_calls = 0

    def __call__(
        self, target: str, target_type: str, operation: str,
        parameters: Mapping[str, Any], checkpoint: Any,
    ) -> Mapping[str, Any]:
        with self._lock:
            self.calls += 1
            self.arguments.append((target, target_type, operation, deepcopy(dict(parameters))))
        self.started.set()
        if not self.release.wait(timeout=10):
            raise RuntimeError("test adapter termination timeout")
        return {"status": "TERMINATED"}

    def terminate(self, capability_id: str) -> Mapping[str, Any]:
        self.termination_calls += 1
        return {
            "safe_termination": True,
            "capability_id": capability_id,
            "adapter_identity": self.identity,
        }


def _runtime_event(
    sequence: int, event_type: str, payload: Mapping[str, Any],
    *, previous_hash: str = "GENESIS",
) -> dict[str, Any]:
    body = {
        "sequence": sequence,
        "timestamp": f"CHRONOLOGY_EVENT_{sequence:012d}",
        "timestamp_authority": "CANONICAL_RUNTIME",
        "event_type": event_type,
        "payload": deepcopy(dict(payload)),
        "previous_hash": previous_hash,
    }
    return {
        **body,
        "event_hash": generate_digest(body),
        "signature": sign_payload(body),
    }


def _authority(
    state: Mapping[str, Any], *, request_id: str = "h7-request-1",
    first_sequence: int = 1,
) -> dict[str, Any]:
    started = _runtime_event(
        first_sequence, "traversal_started",
        {"request_id": request_id, "action": "test_action"},
    )
    completed = _runtime_event(
        first_sequence + 1, "traversal_completed",
        {
            "request_id": request_id,
            "request_fingerprint": state.get("request_fingerprint"),
            "decision": state.get("decision"),
            "execution_result": state.get("execution_result"),
            "pipeline_mode": state.get("pipeline_mode"),
            "audit_hash": state.get("audit_hash"),
            "traversal_started_event_hash": started["event_hash"],
        },
        previous_hash=started["event_hash"],
    )
    return build_execution_traversal_authority(
        state, runtime_id="SBP_LEX_V1_CANONICAL_RUNTIME", request_id=request_id,
        traversal_started_event=started, traversal_completed_event=completed,
    )


class H7Harness:
    def __init__(
        self, root: Path, state: Mapping[str, Any], *,
        safe_cancellation_supported: bool = False,
    ) -> None:
        self.root = root
        self.state = deepcopy(dict(state))
        self.clock = MutableClock()
        self.store = CapabilityLifecycleStore(root / "capabilities.jsonl", allowed_root=root)
        self.store.initialize()
        self.specification = _specification(
            safe_cancellation_supported=safe_cancellation_supported,
        )
        self.service = ExecutionIntegrityService(
            self.store, execution_specifications=(self.specification,), clock=self.clock,
        )
        self.sequence = 1
        self.request_number = 0

    def new_authority(self, request_id: str | None = None) -> dict[str, Any]:
        self.request_number += 1
        identifier = request_id or f"h7-request-{self.request_number}"
        authority = _authority(
            self.state, request_id=identifier, first_sequence=self.sequence,
        )
        self.sequence += 2
        return authority

    def issue(
        self, *, activate: bool = False, authority: Mapping[str, Any] | None = None,
        parameters: str | Mapping[str, Any] = DEFAULT_PARAMETERS,
        **temporal: Any,
    ) -> dict[str, Any]:
        traversal_authority = authority or self.new_authority()
        capability = self.service.issue(
            self.state, traversal_authority=traversal_authority,
            specification_id=self.specification.specification_id,
            parameters=parameters,
            **temporal,
        )
        if activate:
            self.service.activate(capability)
        return capability

    def context(
        self, capability: Mapping[str, Any], *, state: Mapping[str, Any] | None = None,
        parameters: str | Mapping[str, Any] = DEFAULT_PARAMETERS,
        constraints: Mapping[str, Any] = DEFAULT_CONSTRAINTS,
    ) -> dict[str, Any]:
        return self.service.build_execution_context(
            capability, state=state or self.state, parameters=parameters,
            constraints=constraints,
        )


@pytest.fixture(scope="session")
def mode2_state() -> dict[str, Any]:
    state = run_dual_pipeline(sample_request())
    assert state["pipeline_mode"] == "MODE_2_SPLIT_VALIDATOR"
    assert state["decision"] == "ALLOW"
    return state


@pytest.fixture(scope="session")
def mode3_state() -> dict[str, Any]:
    request = deepcopy(sample_request())
    request["payload"]["classification"].update({
        "ap_acf_class": "CLASS_2", "autonomy_level": 20, "autonomy_ceiling": 40,
    })
    request["context"]["financial_amount"] = 100
    request["safety_profile"] = {
        "human_safety": 1, "irreversibility": 1,
        "cascading_impact": 1, "financial_operational": 1,
    }
    state = run_dual_pipeline(request)
    assert state["pipeline_mode"] == "MODE_3_SINGLE_CONSTRAINED"
    assert state["decision"] == "ALLOW"
    return state


@pytest.fixture(autouse=True)
def approved_h8_measurement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        capability_module, "ensure_measured_startup", lambda: deepcopy(MEASUREMENT),
    )


@pytest.fixture
def h7_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode2_state: Mapping[str, Any]):
    counter = 0

    harnesses: list[H7Harness] = []

    def factory(
        *, state: Mapping[str, Any] = mode2_state,
        safe_cancellation_supported: bool = False,
    ) -> H7Harness:
        nonlocal counter
        counter += 1
        root = tmp_path / f"h7-{counter}"
        root.mkdir()
        harness = H7Harness(
            root, state, safe_cancellation_supported=safe_cancellation_supported,
        )
        harnesses.append(harness)
        return harness

    yield factory
    for harness in harnesses:
        harness.store.release_writer_lease()


def _start(harness: H7Harness, capability: Mapping[str, Any]) -> dict[str, Any]:
    context = harness.context(capability)
    harness.service.reserve(capability, context=context)
    harness.service.start(capability, context=context)
    return context


def _complete(harness: H7Harness, capability: Mapping[str, Any]) -> dict[str, Any]:
    context = _start(harness, capability)
    result = {"status": "DONE"}
    evidence = capability_module._completion_evidence(capability, result=result, now=harness.clock())
    return harness.service.complete(
        capability, context=context, completion_classification="COMPLETED",
        result=result, positive_completion_evidence=evidence,
    )


def test_capability_and_attestation_schemas_match_implementation() -> None:
    schema_root = Path(capability_module.__file__).parent / "schemas"
    capability_schema = json.loads((schema_root / "execution_capability.schema.json").read_text("utf-8"))
    attestation_schema = json.loads((schema_root / "post_execution_attestation.schema.json").read_text("utf-8"))
    lifecycle_schema = json.loads((schema_root / "capability_lifecycle_record.schema.json").read_text("utf-8"))
    assert set(capability_schema["required"]) == CAPABILITY_FIELDS == STORE_CAPABILITY_FIELDS
    assert set(attestation_schema["properties"]["payload"]["required"]) == ATTESTATION_PAYLOAD_FIELDS
    assert lifecycle_schema["properties"]["new_state"]["$ref"] == "#/$defs/state"


@pytest.mark.parametrize("state_fixture", ["mode2_state", "mode3_state"])
def test_valid_single_use_execution_all_authorized_modes(
    state_fixture: str, request: pytest.FixtureRequest, h7_factory: Any,
) -> None:
    harness = h7_factory(state=request.getfixturevalue(state_fixture))
    capability = harness.issue(activate=True)
    adapter = RecordingAdapter()
    outcome = harness.service.execute_once(
        capability, context_provider=lambda: harness.context(capability),
        parameters=DEFAULT_PARAMETERS, adapter=adapter,
    )
    assert harness.store.state(capability["capability_id"]) == "COMPLETED"
    assert adapter.calls == 1
    assert adapter.arguments == [("target-1", "device", "test_action", {"level": 1})]
    assert verify_post_execution_attestation(
        outcome["execution_attestation"], capability=capability,
        expected_result=outcome["result"],
    )
    harness.store.validate()


def test_mode1_parity_is_preserved_and_denied_execution_cannot_issue(mode2_state: Mapping[str, Any]) -> None:
    request = deepcopy(sample_request())
    request["payload"]["classification"]["ap_acf_class"] = "CLASS_5B"
    request["context"]["financial_amount"] = 100
    state = run_dual_pipeline(request)
    assert state["pipeline_mode"] == "MODE_1_FULL_MIRRORED"
    assert state["pipeline_convergence"]["matched"] is True
    assert state["decision"] != "ALLOW"
    started = _runtime_event(1, "traversal_started", {"request_id": "mode1", "action": "test_action"})
    completed = _runtime_event(
        2, "traversal_completed",
        {"request_id": "mode1"}, previous_hash=started["event_hash"],
    )
    with pytest.raises(ExecutionIntegrityError, match="canonical_execution_authority_invalid"):
        build_execution_traversal_authority(
            state, runtime_id="SBP_LEX_V1_CANONICAL_RUNTIME", request_id="mode1",
            traversal_started_event=started, traversal_completed_event=completed,
        )


def test_completed_capability_second_use_and_duplicate_completion_are_denied(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    attestation = _complete(harness, capability)
    adapter = RecordingAdapter()
    with pytest.raises(ExecutionIntegrityError, match="capability_state_conflict:COMPLETED") as error:
        harness.service.execute_once(
            capability, context_provider=lambda: harness.context(capability),
            parameters=DEFAULT_PARAMETERS, adapter=adapter,
        )
    assert error.value.evidence["decision"] == "DENY"
    assert error.value.evidence["execution_result"] == "HALT"
    assert adapter.calls == 0
    with pytest.raises(ExecutionIntegrityError, match="capability_not_executing"):
        harness.service.complete(
            capability, context=harness.context(capability),
            completion_classification="FAILED", result={"changed": True},
            positive_completion_evidence=None,
        )
    assert verify_post_execution_attestation(attestation, capability=capability)


def test_one_traversal_can_issue_only_one_capability(h7_factory: Any) -> None:
    harness = h7_factory()
    authority = harness.new_authority("one-traversal")
    first = harness.issue(authority=authority)
    with pytest.raises(ExecutionIntegrityError, match="execution_authority_already_consumed"):
        harness.issue(authority=authority)
    assert harness.store.state(first["capability_id"]) == "PENDING"


def test_issuance_uses_service_owned_operation_and_parameter_policy(h7_factory: Any) -> None:
    harness = h7_factory()
    authority = harness.new_authority("policy-bound")
    with pytest.raises(ExecutionIntegrityError, match="execution_specification_not_approved"):
        harness.service.issue(
            harness.state, traversal_authority=authority,
            specification_id="caller-invented-delete", parameters={"level": 1},
        )
    capability = harness.service.issue(
        harness.state, traversal_authority=authority,
        specification_id=harness.specification.specification_id,
        parameters={"level": 1},
    )
    assert capability["operation_identity"] == harness.state["action"] == "test_action"
    assert capability["execution_specification_digest"] == harness.specification.digest


def test_new_signed_traversal_receipt_is_required_after_ambiguity(h7_factory: Any) -> None:
    harness = h7_factory()
    authority = harness.new_authority("ambiguous-traversal")
    capability = harness.issue(authority=authority, activate=True)
    context = _start(harness, capability)
    attestation = harness.service.complete(
        capability, context=context, completion_classification="COMPLETED",
        result={"unknown": True}, positive_completion_evidence=None,
        communication_lost=True,
    )
    assert attestation["payload"]["completion_classification"] == "AMBIGUOUS"
    with pytest.raises(ExecutionIntegrityError, match="execution_authority_already_consumed"):
        harness.issue(authority=authority)
    replacement = harness.issue(authority=harness.new_authority("new-traversal"))
    assert replacement["capability_id"] != capability["capability_id"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("request_id", "other-request"),
        ("request_fingerprint", "1" * 64),
        ("eie_identifier", "other-eie"),
        ("eie_digest", "2" * 64),
        ("canonical_state_hash", "3" * 64),
        ("pipeline_mode", "MODE_3_SINGLE_CONSTRAINED"),
        ("pipeline_a_result_digest", "4" * 64),
        ("pipeline_b_result_digest", "5" * 64),
        ("convergence_result", "6" * 64),
        ("procedural_truth_token", "7" * 64),
        ("classification_token", "8" * 64),
        ("licensing_token", "9" * 64),
        ("governance_token", "a" * 64),
        ("grc_token", "b" * 64),
        ("domain_token", "c" * 64),
        ("aurion_result", "d" * 64),
        ("target_identity", "target-2"),
        ("target_type", "service"),
        ("operation_identity", "modify"),
        ("canonical_parameter_digest", "e" * 64),
        ("runtime_identity", "other-runtime"),
        ("approved_baseline_identifier", "other-baseline"),
        ("measurement_digest", "f" * 64),
        ("execution_adapter_identity", "adapter-2"),
        ("audit_lineage_identifier", "0" * 64),
    ],
)
def test_exact_binding_substitution_denies_before_adapter(
    field: str, replacement: Any, h7_factory: Any,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    context = harness.context(capability)
    context[field] = replacement
    adapter = RecordingAdapter()
    with pytest.raises(ExecutionIntegrityError, match=f"capability_binding_mismatch:{field}"):
        harness.service.execute_once(
            capability, context_provider=lambda: context,
            parameters=DEFAULT_PARAMETERS, adapter=adapter,
        )
    assert harness.store.state(capability["capability_id"]) == "ACTIVE"
    assert adapter.calls == 0


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"target_identity": "*"}, "target_identity_invalid"),
        ({"target_identity": "target/alias"}, "target_identity_invalid"),
        ({"target_identity": "target,other"}, "target_identity_invalid"),
        ({"target_type": "device*"}, "target_type_invalid"),
        ({"operation_identity": "observe?"}, "operation_identity_invalid"),
        ({"adapter_identity": "adapter/alias"}, "adapter_identity_invalid"),
        ({"parameters": '{"level":1,"level":2}'}, "parameter_json_invalid"),
        ({"parameters": {"unknown": 1}}, "unknown_parameter:unknown"),
        ({"parameters": {}}, "missing_required_parameter:level"),
        ({"parameters": {"level": {"unsupported"}}}, "unsupported_parameter_type"),
        ({"parameters": {"level": "x" * 65536}}, "parameter_package_oversized"),
    ],
)
def test_target_and_parameter_boundary_rejects_ambiguity(
    kwargs: Mapping[str, Any], reason: str, h7_factory: Any,
) -> None:
    if set(kwargs).intersection({"target_identity", "target_type", "operation_identity", "adapter_identity"}):
        with pytest.raises(ExecutionIntegrityError, match=reason):
            _specification(**dict(kwargs))
        return
    harness = h7_factory()
    authority = harness.new_authority()
    with pytest.raises(ExecutionIntegrityError, match=reason):
        harness.issue(authority=authority, **dict(kwargs))
    assert harness.store.history("not-issued") == []


def test_parameter_canonicalization_reorders_but_rejects_depth_and_bad_policy() -> None:
    left = canonical_parameters(
        '{"b":2,"a":1}', allowed_fields=("a", "b"), required_fields=("a", "b"),
    )
    right = canonical_parameters(
        {"a": 1, "b": 2}, allowed_fields=("a", "b"), required_fields=("a", "b"),
    )
    assert left == right
    assert generate_digest(left) == generate_digest(right)
    nested: Any = "leaf"
    for _ in range(17):
        nested = {"value": nested}
    with pytest.raises(ExecutionIntegrityError, match="parameter_nesting_limit_exceeded"):
        canonical_parameters({"level": nested}, allowed_fields=("level",))
    with pytest.raises(ExecutionIntegrityError, match="parameter_allowlist_required"):
        canonical_parameters({}, allowed_fields=())
    with pytest.raises(ExecutionIntegrityError, match="parameter_allowlist_duplicate"):
        canonical_parameters({}, allowed_fields=("a", "a"))
    with pytest.raises(ExecutionIntegrityError, match="required_parameter_not_allowed"):
        canonical_parameters({}, allowed_fields=("a",), required_fields=("b",))
    with pytest.raises(ExecutionIntegrityError, match="parameter_key_collision_after_normalization"):
        canonical_parameters(
            {"\u00e9": 1, "e\u0301": 2}, allowed_fields=("\u00e9",),
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.pop("max_steps"),
        lambda value: value.update(max_steps=4),
        lambda value: value.update(min_classification=1),
        lambda value: value.update(allowed_regions=["AU", "US"]),
        lambda value: value.update(licence_scope="admin"),
        lambda value: value.update(governance_required=False),
        lambda value: value.update(unrecognised_constraint=True),
    ],
)
def test_constraint_loss_or_broadening_fails_closed(mutator: Any, h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    context = harness.context(capability)
    changed = deepcopy(DEFAULT_CONSTRAINTS)
    mutator(changed)
    context["constraint_snapshot"] = changed
    context["constraint_digest"] = generate_digest(changed)
    with pytest.raises(ExecutionIntegrityError, match="execution_constraint_broadening_or_loss"):
        harness.service.reserve(capability, context=context)
    assert harness.store.state(capability["capability_id"]) == "ACTIVE"


def test_narrower_constraints_are_accepted_and_digest_is_authenticated(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    narrowed = deepcopy(DEFAULT_CONSTRAINTS)
    narrowed.update(max_steps=2, min_classification=3, allowed_regions=["AU"])
    context = harness.context(capability, constraints=narrowed)
    harness.service.reserve(capability, context=context)
    assert harness.store.state(capability["capability_id"]) == "RESERVED"

    other = h7_factory()
    other_capability = other.issue(activate=True)
    corrupt = other.context(other_capability)
    corrupt["constraint_digest"] = "0" * 64
    with pytest.raises(ExecutionIntegrityError, match="current_constraint_integrity_invalid"):
        other.service.reserve(other_capability, context=corrupt)


@pytest.mark.parametrize(
    ("original", "current", "preserved"),
    [
        ({"max_attempts": 1}, {"max_attempts": 1}, True),
        ({"max_attempts": 1}, {"max_attempts": 2}, False),
        ({"min_classification": 3}, {"min_classification": 4}, True),
        ({"required": True}, {"required": False}, False),
        ({"allowed_values": [{"a": 1}]}, {"allowed_values": [{"a": 1}]}, True),
    ],
)
def test_constraint_property_matrix(
    original: Mapping[str, Any], current: Mapping[str, Any], preserved: bool,
) -> None:
    assert constraints_preserved(original, current) is preserved


def test_parallel_double_reservation_allows_exactly_one(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    barrier = threading.Barrier(2)
    results: list[str] = []

    def reserve(service: ExecutionIntegrityService) -> None:
        barrier.wait()
        try:
            service.reserve(capability, context=harness.context(capability))
            results.append("RESERVED")
        except ExecutionIntegrityError as exc:
            results.append(exc.reason)

    threads = [threading.Thread(target=reserve, args=(harness.service,)) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("RESERVED") == 1
    assert harness.store.state(capability["capability_id"]) == "RESERVED"


def test_parallel_double_execution_invokes_adapter_once(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    adapter = RecordingAdapter()
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def execute(service: ExecutionIntegrityService) -> None:
        barrier.wait()
        try:
            service.execute_once(
                capability, context_provider=lambda: harness.context(capability),
                parameters=DEFAULT_PARAMETERS, adapter=adapter,
            )
            outcomes.append("COMPLETED")
        except ExecutionIntegrityError as exc:
            outcomes.append(exc.reason)

    threads = [threading.Thread(target=execute, args=(harness.service,)) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("COMPLETED") == 1
    assert adapter.calls == 1
    assert harness.store.state(capability["capability_id"]) == "COMPLETED"


@pytest.mark.parametrize("restart_state", ["RESERVED", "EXECUTING", "COMPLETED"])
def test_restart_state_is_durable_and_inflight_execution_becomes_ambiguous(
    restart_state: str, h7_factory: Any,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    context = harness.context(capability)
    harness.service.reserve(capability, context=context)
    if restart_state in {"EXECUTING", "COMPLETED"}:
        harness.service.start(capability, context=context)
    if restart_state == "COMPLETED":
        result = {"status": "DONE"}
        evidence = capability_module._completion_evidence(capability, result=result, now=harness.clock())
        harness.service.complete(
            capability, context=context, completion_classification="COMPLETED",
            result=result, positive_completion_evidence=evidence,
        )
    harness.service.close()
    restarted = ExecutionIntegrityService(
        CapabilityLifecycleStore(harness.store.path, allowed_root=harness.root),
        execution_specifications=(harness.specification,),
        clock=harness.clock,
    )
    expected = "AMBIGUOUS" if restart_state == "EXECUTING" else restart_state
    assert restarted.store.state(capability["capability_id"]) == expected
    if restart_state == "RESERVED":
        restarted.start(capability, context=context)
        assert restarted.store.state(capability["capability_id"]) == "EXECUTING"
    else:
        with pytest.raises(ExecutionIntegrityError):
            restarted.start(capability, context=context)
    restarted.close()


@pytest.mark.parametrize("initial_state", ["PENDING", "ACTIVE", "RESERVED"])
def test_authorized_cancellation_is_durable_before_execution(initial_state: str, h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=initial_state != "PENDING")
    if initial_state == "RESERVED":
        harness.service.reserve(capability, context=harness.context(capability))
    authorization = authorize_control(
        capability_id=capability["capability_id"], action="CANCEL",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="operator stop", now=harness.clock(),
    )
    harness.service.cancel(capability, authorization=authorization)
    assert harness.store.state(capability["capability_id"]) == "CANCELLED"
    with pytest.raises(ExecutionIntegrityError):
        harness.service.activate(capability)


@pytest.mark.parametrize("initial_state", ["ACTIVE", "RESERVED"])
def test_authorized_revocation_is_durable_before_execution(initial_state: str, h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    if initial_state == "RESERVED":
        harness.service.reserve(capability, context=harness.context(capability))
    authorization = authorize_control(
        capability_id=capability["capability_id"], action="REVOKE",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="authority withdrawn", now=harness.clock(),
    )
    harness.service.revoke(capability, authorization=authorization)
    assert harness.store.state(capability["capability_id"]) == "REVOKED"


def test_control_authorization_actor_action_and_expiry_fail_closed(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    wrong_actor = authorize_control(
        capability_id=capability["capability_id"], action="CANCEL",
        actor_id="UNAPPROVED_ADMIN", reason="bypass", now=harness.clock(),
    )
    with pytest.raises(ExecutionIntegrityError, match="cancellation_unauthorised"):
        harness.service.cancel(capability, authorization=wrong_actor)
    wrong_action = authorize_control(
        capability_id=capability["capability_id"], action="REVOKE",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="wrong action", now=harness.clock(),
    )
    with pytest.raises(ExecutionIntegrityError, match="cancellation_unauthorised"):
        harness.service.cancel(capability, authorization=wrong_action)
    expired = authorize_control(
        capability_id=capability["capability_id"], action="CANCEL",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="old", now=harness.clock(), lifetime_seconds=1,
    )
    harness.clock.advance(1)
    with pytest.raises(ExecutionIntegrityError, match="cancellation_unauthorised"):
        harness.service.cancel(capability, authorization=expired)
    assert harness.store.state(capability["capability_id"]) == "ACTIVE"


def test_safe_cancellation_during_execution_requires_adapter_termination_acknowledgement(h7_factory: Any) -> None:
    harness = h7_factory(safe_cancellation_supported=True)
    capability = harness.issue(activate=True)
    adapter = BlockingCancellableAdapter()
    execution_errors: list[str] = []

    def execute() -> None:
        try:
            harness.service.execute_once(
                capability, context_provider=lambda: harness.context(capability),
                parameters=DEFAULT_PARAMETERS, adapter=adapter,
            )
        except ExecutionIntegrityError as exc:
            execution_errors.append(exc.reason)

    thread = threading.Thread(target=execute)
    thread.start()
    assert adapter.started.wait(timeout=10)
    authorization = authorize_control(
        capability_id=capability["capability_id"], action="CANCEL",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="safe stop", now=harness.clock(),
    )
    record = harness.service.cancel(capability, authorization=authorization)
    adapter.release.set()
    thread.join(timeout=10)
    assert harness.store.state(capability["capability_id"]) == "CANCELLED"
    assert adapter.termination_calls == 1
    assert execution_errors
    assert record["details"]["execution_attestation"]["payload"]["completion_classification"] == "CANCELLED"


def test_unsafe_cancellation_and_inflight_revocation_fail_safely(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    _start(harness, capability)
    cancel = authorize_control(
        capability_id=capability["capability_id"], action="CANCEL",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="cannot stop", now=harness.clock(),
    )
    with pytest.raises(ExecutionIntegrityError, match="safe_cancellation_not_supported"):
        harness.service.cancel(capability, authorization=cancel)
    revoke = authorize_control(
        capability_id=capability["capability_id"], action="REVOKE",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="authority invalid", now=harness.clock(),
    )
    record = harness.service.revoke(capability, authorization=revoke)
    assert record["new_state"] == "FAILED"
    assert harness.store.state(capability["capability_id"]) == "FAILED"


def test_start_vs_revocation_race_reapplies_revocation_to_executing_state(
    h7_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    context = harness.context(capability)
    harness.service.reserve(capability, context=context)
    authorization = authorize_control(
        capability_id=capability["capability_id"], action="REVOKE",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="race revoke", now=harness.clock(),
    )
    original = harness.service._transition
    revocation_read_reserved = threading.Event()
    permit_revocation = threading.Event()

    def delayed_transition(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        if kwargs.get("event") == "CAPABILITY_REVOKED" and kwargs.get("expected") == "RESERVED":
            revocation_read_reserved.set()
            assert permit_revocation.wait(timeout=10)
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.service, "_transition", delayed_transition)
    failures: list[str] = []

    def revoke() -> None:
        try:
            harness.service.revoke(capability, authorization=authorization)
        except ExecutionIntegrityError as exc:
            failures.append(exc.reason)

    thread = threading.Thread(target=revoke)
    thread.start()
    assert revocation_read_reserved.wait(timeout=10)
    harness.service.start(capability, context=context)
    permit_revocation.set()
    thread.join(timeout=10)
    assert not failures
    assert harness.store.state(capability["capability_id"]) == "FAILED"


def test_start_vs_unsafe_cancel_race_never_claims_cancellation(
    h7_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    context = harness.context(capability)
    harness.service.reserve(capability, context=context)
    authorization = authorize_control(
        capability_id=capability["capability_id"], action="CANCEL",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="race cancel", now=harness.clock(),
    )
    original = harness.service._transition
    cancellation_read_reserved = threading.Event()
    permit_cancellation = threading.Event()

    def delayed_transition(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        if kwargs.get("event") == "CAPABILITY_CANCELLED" and kwargs.get("expected") == "RESERVED":
            cancellation_read_reserved.set()
            assert permit_cancellation.wait(timeout=10)
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.service, "_transition", delayed_transition)
    failures: list[str] = []

    def cancel() -> None:
        try:
            harness.service.cancel(capability, authorization=authorization)
        except ExecutionIntegrityError as exc:
            failures.append(exc.reason)

    thread = threading.Thread(target=cancel)
    thread.start()
    assert cancellation_read_reserved.wait(timeout=10)
    harness.service.start(capability, context=context)
    permit_cancellation.set()
    thread.join(timeout=10)
    assert failures == ["safe_cancellation_not_supported"]
    assert harness.store.state(capability["capability_id"]) == "EXECUTING"
    revoke = authorize_control(
        capability_id=capability["capability_id"], action="REVOKE",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="race cleanup", now=harness.clock(),
    )
    harness.service.revoke(capability, authorization=revoke)


def test_temporal_expiry_start_duration_report_deadline_and_clock_rollback(h7_factory: Any) -> None:
    expired = h7_factory()
    expired_capability = expired.issue(activate=True)
    expired.clock.advance(300)
    with pytest.raises(ExecutionIntegrityError, match="capability_expired"):
        expired.service.reserve(expired_capability, context=expired.context(expired_capability))
    expired.service.expire(expired_capability)
    assert expired.store.state(expired_capability["capability_id"]) == "EXPIRED"

    start_deadline = h7_factory()
    start_capability = start_deadline.issue(activate=True)
    start_deadline.service.reserve(start_capability, context=start_deadline.context(start_capability))
    start_deadline.clock.advance(30)
    with pytest.raises(ExecutionIntegrityError, match="execution_start_deadline_exceeded"):
        start_deadline.service.start(start_capability, context=start_deadline.context(start_capability))
    assert start_deadline.store.state(start_capability["capability_id"]) == "EXPIRED"

    duration = h7_factory()
    duration_capability = duration.issue(activate=True)
    context = _start(duration, duration_capability)
    duration.clock.advance(120)
    with pytest.raises(ExecutionIntegrityError, match="maximum_execution_duration_exceeded"):
        duration.service.revalidate(duration_capability, context=context)
    assert duration.store.state(duration_capability["capability_id"]) == "FAILED"

    report = h7_factory()
    report_capability = report.issue(
        activate=True, lifetime_seconds=100, reservation_timeout_seconds=5,
        execution_start_seconds=10, maximum_execution_seconds=20,
        completion_report_seconds=10,
    )
    report_context = _start(report, report_capability)
    result = {"status": "DONE"}
    evidence = capability_module._completion_evidence(report_capability, result=result, now=report.clock())
    report.clock.advance(10)
    attestation = report.service.complete(
        report_capability, context=report_context, completion_classification="COMPLETED",
        result=result, positive_completion_evidence=evidence,
    )
    assert attestation["payload"]["completion_classification"] == "AMBIGUOUS"

    rollback = h7_factory()
    rollback_capability = rollback.issue()
    rollback.clock.advance(10)
    rollback.service.activate(rollback_capability)
    rollback.clock.set(NOW + timedelta(seconds=5))
    with pytest.raises(ExecutionIntegrityError, match="capability_store_clock_rollback"):
        rollback.service.reserve(rollback_capability, context=rollback.context(rollback_capability))


def test_expiry_during_execution_transitions_to_failed_with_attestation(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(
        activate=True, lifetime_seconds=10, reservation_timeout_seconds=1,
        execution_start_seconds=2, maximum_execution_seconds=10,
        completion_report_seconds=10,
    )
    context = _start(harness, capability)
    harness.clock.advance(10)
    with pytest.raises(ExecutionIntegrityError, match="capability_expired"):
        harness.service.revalidate(capability, context=context)
    assert harness.store.state(capability["capability_id"]) == "FAILED"
    terminal = harness.store.history(capability["capability_id"])[-1]
    assert terminal["details"]["execution_attestation"]["payload"]["completion_classification"] == "FAILED"


def test_naive_clock_is_rejected(h7_factory: Any) -> None:
    harness = h7_factory()
    harness.clock.set(datetime(2026, 7, 11, 12, 0, 0))
    with pytest.raises(ExecutionIntegrityError, match="timezone_aware_timestamp_required"):
        harness.issue()


def test_runtime_measurement_change_between_receipt_and_issuance_is_denied(
    h7_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = h7_factory()
    authority = harness.new_authority("old-measured-runtime")
    changed = {**MEASUREMENT, "measurement_digest": "b" * 64}
    monkeypatch.setattr(capability_module, "ensure_measured_startup", lambda: deepcopy(changed))
    with pytest.raises(ExecutionIntegrityError, match="traversal_runtime_binding_changed:measurement_digest"):
        harness.issue(authority=authority)


@pytest.mark.parametrize(
    "field",
    [
        "request_fingerprint", "eie_digest", "canonical_state_hash", "pipeline_mode",
        "convergence_result", "governance_token", "grc_token", "domain_token",
        "aurion_result", "target_identity", "constraint_digest",
        "runtime_identity", "measurement_digest", "execution_adapter_identity",
    ],
)
def test_mid_execution_binding_change_stops_before_later_step(field: str, h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    current = harness.context(capability)
    adapter = RecordingAdapter(
        checkpoint_during_execution=True,
        before_checkpoint=lambda: current.__setitem__(field, "0" * 64),
    )
    with pytest.raises(ExecutionIntegrityError):
        harness.service.execute_once(
            capability, context_provider=lambda: current,
            parameters=DEFAULT_PARAMETERS, adapter=adapter,
        )
    assert adapter.calls == 1
    assert harness.store.state(capability["capability_id"]) == "FAILED"
    assert any(item["new_state"] == "FAILED" for item in harness.store.history(capability["capability_id"]))


def test_measured_state_drift_during_execution_fails_and_cannot_complete(
    h7_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    context = _start(harness, capability)
    drifted = {**MEASUREMENT, "measurement_digest": "b" * 64}
    monkeypatch.setattr(capability_module, "ensure_measured_startup", lambda: deepcopy(drifted))
    with pytest.raises(ExecutionIntegrityError, match="measured_runtime_binding_changed:measurement_digest"):
        harness.service.record_checkpoint(capability, context=context)
    assert harness.store.state(capability["capability_id"]) == "FAILED"
    with pytest.raises(ExecutionIntegrityError, match="capability_not_executing"):
        harness.service.complete(
            capability, context=context, completion_classification="COMPLETED",
            result={"status": "DONE"}, positive_completion_evidence=None,
        )


def test_missing_evidence_and_communication_loss_never_become_success(h7_factory: Any) -> None:
    missing = h7_factory()
    missing_capability = missing.issue(activate=True)
    missing_context = _start(missing, missing_capability)
    attestation = missing.service.complete(
        missing_capability, context=missing_context, completion_classification="COMPLETED",
        result={"claimed": "success"}, positive_completion_evidence=None,
    )
    assert attestation["payload"]["completion_classification"] == "AMBIGUOUS"

    lost = h7_factory()
    lost_capability = lost.issue(activate=True)
    lost_context = _start(lost, lost_capability)
    result = {"status": "DONE"}
    evidence = capability_module._completion_evidence(lost_capability, result=result, now=lost.clock())
    lost_attestation = lost.service.complete(
        lost_capability, context=lost_context, completion_classification="COMPLETED",
        result=result, positive_completion_evidence=evidence, communication_lost=True,
    )
    assert lost_attestation["payload"]["completion_classification"] == "AMBIGUOUS"


@pytest.mark.parametrize(("fail", "invalid_result"), [(True, False), (False, True)])
def test_adapter_exception_or_invalid_result_is_durably_ambiguous(
    fail: bool, invalid_result: bool, h7_factory: Any,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    adapter = RecordingAdapter(fail=fail, invalid_result=invalid_result)
    with pytest.raises(ExecutionIntegrityError):
        harness.service.execute_once(
            capability, context_provider=lambda: harness.context(capability),
            parameters=DEFAULT_PARAMETERS, adapter=adapter,
        )
    assert adapter.calls == 1
    assert harness.store.state(capability["capability_id"]) == "AMBIGUOUS"


def test_final_context_failure_after_adapter_effect_is_durably_ambiguous(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    adapter = RecordingAdapter()
    context = harness.context(capability)
    calls = 0

    def provider() -> Mapping[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise RuntimeError("final context unavailable")
        return context

    with pytest.raises(ExecutionIntegrityError, match="post_effect_completion_ambiguous"):
        harness.service.execute_once(
            capability, context_provider=provider,
            parameters=DEFAULT_PARAMETERS, adapter=adapter,
        )
    assert adapter.calls == 1
    assert harness.store.state(capability["capability_id"]) == "AMBIGUOUS"


def test_adapter_identity_and_safe_cancellation_policy_are_enforced_before_execution(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    wrong_identity = RecordingAdapter()
    wrong_identity.identity = "adapter-2"
    with pytest.raises(ExecutionIntegrityError, match="execution_adapter_identity"):
        harness.service.execute_once(
            capability, context_provider=lambda: harness.context(capability),
            parameters=DEFAULT_PARAMETERS, adapter=wrong_identity,
        )
    assert wrong_identity.calls == 0
    wrong_policy = RecordingAdapter(safe_cancellation_supported=True)
    with pytest.raises(ExecutionIntegrityError, match="adapter_cancellation_policy_mismatch"):
        harness.service.execute_once(
            capability, context_provider=lambda: harness.context(capability),
            parameters=DEFAULT_PARAMETERS, adapter=wrong_policy,
        )
    assert wrong_policy.calls == 0


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("attestation_hash",), "0" * 64),
        (("payload", "capability_id"), "0" * 64),
        (("payload", "target_identity"), "target-2"),
        (("payload", "result_digest"), "1" * 64),
        (("payload", "completion_classification"), "FAILED"),
        (("payload", "adapter_identity"), "adapter-2"),
    ],
)
def test_attestation_tampering_is_detected(
    path: tuple[str, ...], replacement: Any, h7_factory: Any,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    attestation = _complete(harness, capability)
    tampered = deepcopy(attestation)
    target: dict[str, Any] = tampered
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    assert not verify_post_execution_attestation(tampered, capability=capability)


def test_attestation_exact_schema_capability_match_and_global_chain(h7_factory: Any) -> None:
    harness = h7_factory()
    first = harness.issue(activate=True)
    first_attestation = _complete(harness, first)
    second = harness.issue(activate=True)
    second_attestation = _complete(harness, second)
    assert first_attestation["payload"]["previous_attestation_hash"] == "GENESIS"
    assert second_attestation["payload"]["previous_attestation_hash"] == first_attestation["attestation_hash"]
    extra = deepcopy(second_attestation)
    extra["unexpected"] = True
    assert not verify_post_execution_attestation(extra, capability=second)
    other = h7_factory()
    other_capability = other.issue(authority=other.new_authority("other-capability"))
    assert not verify_post_execution_attestation(first_attestation, capability=other_capability)
    harness.store.validate()


def test_parallel_completion_attestations_are_atomically_chained(h7_factory: Any) -> None:
    harness = h7_factory()
    capabilities = [harness.issue(activate=True), harness.issue(activate=True)]
    contexts = [_start(harness, capability) for capability in capabilities]
    results = [{"status": "DONE", "index": index} for index in range(2)]
    evidences = [
        capability_module._completion_evidence(capability, result=result, now=harness.clock())
        for capability, result in zip(capabilities, results)
    ]
    barrier = threading.Barrier(2)
    attestations: list[dict[str, Any]] = []

    def complete(index: int) -> None:
        barrier.wait()
        attestations.append(harness.service.complete(
            capabilities[index], context=contexts[index], completion_classification="COMPLETED",
            result=results[index], positive_completion_evidence=evidences[index],
        ))

    threads = [threading.Thread(target=complete, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(attestations) == 2
    previous_values = {item["payload"]["previous_attestation_hash"] for item in attestations}
    hashes = {item["attestation_hash"] for item in attestations}
    assert "GENESIS" in previous_values
    assert previous_values.intersection(hashes)
    harness.store.validate()


def test_atomic_replace_retries_transient_permission_error(
    h7_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = h7_factory()
    destination = harness.store.path.parent / "replace-retry.bin"
    original_replace = capability_store_module.os.replace
    attempts = 0

    def transient_replace(source: Path, target: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(13, "transient replace denial")
        original_replace(source, target)

    monkeypatch.setattr(capability_store_module.os, "replace", transient_replace)
    harness.store._atomic_bytes(destination, b"durable")

    assert attempts == 2
    assert destination.read_bytes() == b"durable"


@pytest.mark.parametrize("corruption", ["truncate", "reorder", "duplicate"])
def test_lifecycle_store_corruption_is_detected(corruption: str, h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    raw = harness.store.path.read_bytes()
    lines = raw.splitlines(keepends=True)
    if corruption == "truncate":
        harness.store.path.write_bytes(raw[:-1])
    elif corruption == "reorder":
        harness.store.path.write_bytes(b"".join(reversed(lines)))
    else:
        harness.store.path.write_bytes(raw + lines[0])
    with pytest.raises(CapabilityStoreError):
        harness.store.validate()
    assert capability["capability_id"]


@pytest.mark.parametrize("component", ["checkpoint", "anchor"])
def test_checkpoint_and_anchor_rollback_are_detected(component: str, h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue()
    path = harness.store.checkpoint_path if component == "checkpoint" else harness.store.anchor_path
    old = path.read_bytes()
    harness.service.activate(capability)
    path.write_bytes(old)
    with pytest.raises(CapabilityStoreError):
        harness.store.validate()


def test_ambiguous_store_startup_missing_corrupt_intent_and_second_writer_fail_closed(
    tmp_path: Path, h7_factory: Any,
) -> None:
    missing_root = tmp_path / "missing"
    missing_root.mkdir()
    missing_store = CapabilityLifecycleStore(missing_root / "missing.jsonl", allowed_root=missing_root)
    with pytest.raises(ExecutionIntegrityError, match="capability_store_ambiguous_missing_component"):
        ExecutionIntegrityService(
            missing_store, execution_specifications=(_specification(),), clock=MutableClock(),
        )

    corrupt = h7_factory()
    corrupt.service.close()
    corrupt.store.intent_path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ExecutionIntegrityError, match="capability_store_intent_corrupted"):
        ExecutionIntegrityService(
            CapabilityLifecycleStore(corrupt.store.path, allowed_root=corrupt.root),
            execution_specifications=(corrupt.specification,),
            clock=corrupt.clock,
        )

    locked = h7_factory()
    capability = locked.issue()
    second_store = CapabilityLifecycleStore(locked.store.path, allowed_root=locked.root)
    with pytest.raises(ExecutionIntegrityError, match="capability_store_second_writer_denied"):
        ExecutionIntegrityService(
            second_store, execution_specifications=(locked.specification,), clock=locked.clock,
        )
    with locked.store._writer():
        with pytest.raises(CapabilityStoreError, match="capability_store_second_writer_denied"):
            second_store.append_transition(
                capability_id=capability["capability_id"],
                capability_digest=capability["capability_digest"],
                event_type="CAPABILITY_ACTIVATED", expected_state="PENDING",
                new_state="ACTIVE", occurred_at=NOW.isoformat().replace("+00:00", "Z"),
            )


@pytest.mark.parametrize(
    ("crash_window", "recovery_result", "expected_state"),
    [
        ("intent_before_ledger", "RECOVERED_INTENT_BEFORE_LEDGER", "PENDING"),
        ("ledger_before_metadata", "RECOVERED_LEDGER_BEFORE_METADATA", "ACTIVE"),
        ("checkpoint_before_anchor", "RECOVERED_CHECKPOINT_BEFORE_ANCHOR", "ACTIVE"),
    ],
)
def test_lifecycle_store_recovers_only_explainable_atomic_crash_windows(
    crash_window: str, recovery_result: str, expected_state: str,
    h7_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = h7_factory()
    capability = harness.issue()
    if crash_window == "intent_before_ledger":
        original = harness.store._atomic_bytes

        def fail_ledger(path: Path, data: bytes) -> None:
            if path == harness.store.path and harness.store.intent_path.exists():
                raise CapabilityStoreError("simulated_ledger_failure")
            original(path, data)

        monkeypatch.setattr(harness.store, "_atomic_bytes", fail_ledger)
    elif crash_window == "ledger_before_metadata":
        original_metadata = harness.store._write_metadata

        def fail_metadata(records: Any, generation: int) -> None:
            raise CapabilityStoreError("simulated_metadata_failure")

        monkeypatch.setattr(harness.store, "_write_metadata", fail_metadata)
    else:
        original_json = harness.store._atomic_json

        def fail_anchor(path: Path, value: Mapping[str, Any]) -> None:
            if path == harness.store.anchor_path:
                raise CapabilityStoreError("simulated_anchor_failure")
            original_json(path, value)

        monkeypatch.setattr(harness.store, "_atomic_json", fail_anchor)
    with pytest.raises(ExecutionIntegrityError):
        harness.service.activate(capability)
    monkeypatch.undo()
    assert harness.store.validate_and_recover() == recovery_result
    assert harness.store.state(capability["capability_id"]) == expected_state
    harness.store.validate()


def test_store_recovers_metadata_written_before_intent_cleanup(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue()
    harness.service.activate(capability)
    records = harness.store._read_records()
    checkpoint = json.loads(harness.store.checkpoint_path.read_text("utf-8"))
    generation = checkpoint["payload"]["generation"]
    last = records[-1]
    intent = capability_store_module._bound({
        "intent_version": "H7_EXECUTION_CAPABILITY_INTENT_V1",
        "sequence": last["sequence"],
        "record_hash": last["record_hash"],
        "previous_record_hash": last["previous_record_hash"],
        "prior_generation": generation - 1,
    })
    harness.store._atomic_json(harness.store.intent_path, intent)
    assert harness.store.validate_and_recover() == "RECOVERED_METADATA_BEFORE_INTENT_CLEANUP"
    assert harness.store.state(capability["capability_id"]) == "ACTIVE"


def test_terminal_attestation_head_recovers_after_ledger_before_metadata_crash(
    h7_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    context = _start(harness, capability)
    result = {"status": "DONE"}
    evidence = capability_module._completion_evidence(capability, result=result, now=harness.clock())
    original_metadata = harness.store._write_metadata

    def fail_metadata(records: Any, generation: int) -> None:
        raise CapabilityStoreError("simulated_terminal_metadata_failure")

    monkeypatch.setattr(harness.store, "_write_metadata", fail_metadata)
    with pytest.raises(ExecutionIntegrityError, match="simulated_terminal_metadata_failure"):
        harness.service.complete(
            capability, context=context, completion_classification="COMPLETED",
            result=result, positive_completion_evidence=evidence,
        )
    monkeypatch.setattr(harness.store, "_write_metadata", original_metadata)
    assert harness.store.validate_and_recover() == "RECOVERED_LEDGER_BEFORE_METADATA"
    assert harness.store.state(capability["capability_id"]) == "COMPLETED"
    history = harness.store.history(capability["capability_id"])
    attestation = history[-1]["details"]["execution_attestation"]
    assert harness.store.previous_attestation_hash() == attestation["attestation_hash"]
    harness.store.validate()


def test_capability_store_contains_no_raw_parameters_or_reusable_secrets(h7_factory: Any) -> None:
    harness = h7_factory()
    marker = "DO-NOT-PERSIST-RAW-SECRET-MARKER"
    capability = harness.issue(parameters={"level": marker})
    authorization = authorize_control(
        capability_id=capability["capability_id"], action="CANCEL",
        actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason=marker, now=harness.clock(),
    )
    harness.service.cancel(capability, authorization=authorization)
    stored = "\n".join(
        path.read_text("utf-8", errors="ignore")
        for path in harness.root.iterdir() if path.is_file() and path != harness.store.lock_path
    )
    assert marker not in stored
    assert "private_key" not in json.dumps(capability).lower()
    assert capability["canonical_parameter_digest"] == generate_digest({"level": marker})
    with pytest.raises(ExecutionIntegrityError, match="secret_bearing_execution_field_denied"):
        _specification(constraints={"api_key": marker})


def test_replay_is_observational_and_does_not_consume_capability_state(
    h7_factory: Any,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    before = {
        path.name: path.read_bytes()
        for path in harness.root.iterdir() if path.is_file() and path != harness.store.lock_path
    }
    replay = run_replay_check(request=sample_request(), replay_count=2)
    after = {
        path.name: path.read_bytes()
        for path in harness.root.iterdir() if path.is_file() and path != harness.store.lock_path
    }
    assert replay["matched"] is True
    assert before == after
    assert harness.store.state(capability["capability_id"]) == "ACTIVE"


def test_traversal_authority_tampering_and_event_substitution_are_denied(mode2_state: Mapping[str, Any]) -> None:
    authority = _authority(mode2_state)
    assert verify_execution_traversal_authority(authority, mode2_state)
    tampered = deepcopy(authority)
    tampered["payload"]["request_id"] = "substituted"
    assert not verify_execution_traversal_authority(tampered, mode2_state)
    started = _runtime_event(1, "traversal_started", {"request_id": "expected", "action": "test_action"})
    completed = _runtime_event(
        2, "traversal_completed", {"request_id": "other"},
        previous_hash=started["event_hash"],
    )
    with pytest.raises(ExecutionIntegrityError, match="traversal_completed_evidence_invalid"):
        build_execution_traversal_authority(
            mode2_state, runtime_id="SBP_LEX_V1_CANONICAL_RUNTIME", request_id="expected",
            traversal_started_event=started, traversal_completed_event=completed,
        )
    valid_completed = _runtime_event(
        2, "traversal_completed",
        {
            "request_id": "expected",
            "request_fingerprint": mode2_state["request_fingerprint"],
            "decision": mode2_state["decision"],
            "execution_result": mode2_state["execution_result"],
            "pipeline_mode": mode2_state["pipeline_mode"],
            "audit_hash": mode2_state["audit_hash"],
            "traversal_started_event_hash": started["event_hash"],
        },
        previous_hash=started["event_hash"],
    )
    with pytest.raises(ExecutionIntegrityError, match="canonical_runtime_identity_invalid"):
        build_execution_traversal_authority(
            mode2_state, runtime_id="ATTACKER_RUNTIME", request_id="expected",
            traversal_started_event=started, traversal_completed_event=valid_completed,
        )


def test_canonical_runtime_keeps_receipts_internal_and_concurrent_traversals_remain_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_module, "ensure_measured_startup", lambda: deepcopy(MEASUREMENT))
    runtime = CanonicalRuntime()
    results: list[dict[str, Any]] = []
    failures: list[Exception] = []
    barrier = threading.Barrier(2)

    def traverse(index: int) -> None:
        barrier.wait()
        try:
            results.append(runtime.traverse(sample_request(), request_id=f"runtime-h7-{index}"))
        except Exception as exc:  # pragma: no cover - asserted empty below
            failures.append(exc)

    threads = [threading.Thread(target=traverse, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not failures
    assert len(results) == 2
    root = tmp_path / "runtime-issuance"
    root.mkdir()
    store = CapabilityLifecycleStore(root / "capabilities.jsonl", allowed_root=root)
    store.initialize()
    specification = _specification()
    service = ExecutionIntegrityService(
        store, execution_specifications=(specification,), clock=MutableClock(),
    )
    for result in results:
        assert "execution_authority" not in result
        reference = result["execution_authority_reference"]
        assert isinstance(reference, str) and len(reference) == 64
        capability = runtime.issue_execution_capability(
            reference, execution_service=service,
            specification_id=specification.specification_id,
            parameters=DEFAULT_PARAMETERS,
        )
        assert capability["request_id"] == result["request_id"]
        with pytest.raises(ValueError, match="execution_authority_reference_unavailable"):
            runtime.issue_execution_capability(
                reference, execution_service=service,
                specification_id=specification.specification_id,
                parameters=DEFAULT_PARAMETERS,
            )

    first = results[0]
    assert first["state"]["integration_stage_order"] == results[1]["state"]["integration_stage_order"]
    service.close()


def test_illegal_unknown_and_terminal_transitions_fail_closed(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue()
    with pytest.raises(ExecutionIntegrityError, match="illegal_capability_transition"):
        harness.service._transition(
            capability, expected="UNKNOWN", new="ACTIVE", event="CAPABILITY_ACTIVATED",
        )
    with pytest.raises(ExecutionIntegrityError, match="illegal_capability_transition"):
        harness.service._transition(
            capability, expected="PENDING", new="COMPLETED", event="EXECUTION_COMPLETED",
        )
    harness.service.activate(capability)
    context = harness.context(capability)
    harness.service.reserve(capability, context=context)
    harness.service.start(capability, context=context)
    harness.service.complete(
        capability, context=context, completion_classification="FAILED",
        result={"failure": "known"}, positive_completion_evidence=None,
    )
    harness.service.retire(capability)
    assert harness.store.state(capability["capability_id"]) == "RETIRED"
    with pytest.raises(ExecutionIntegrityError):
        harness.service.activate(capability)


@pytest.mark.parametrize(
    "nonusable_state",
    ["PENDING", "CANCELLED", "REVOKED", "EXPIRED", "FAILED", "AMBIGUOUS", "RETIRED"],
)
def test_every_nonusable_state_denies_adapter_execution(
    nonusable_state: str, h7_factory: Any,
) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=nonusable_state not in {"PENDING", "CANCELLED", "RETIRED"})
    if nonusable_state in {"CANCELLED", "RETIRED"}:
        authorization = authorize_control(
            capability_id=capability["capability_id"], action="CANCEL",
            actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="terminal test", now=harness.clock(),
        )
        harness.service.cancel(capability, authorization=authorization)
        if nonusable_state == "RETIRED":
            harness.service.retire(capability)
    elif nonusable_state == "REVOKED":
        authorization = authorize_control(
            capability_id=capability["capability_id"], action="REVOKE",
            actor_id="SBP_LEX_DESKTOP_V1_OPERATOR", reason="terminal test", now=harness.clock(),
        )
        harness.service.revoke(capability, authorization=authorization)
    elif nonusable_state == "EXPIRED":
        harness.clock.advance(300)
        harness.service.expire(capability)
    elif nonusable_state in {"FAILED", "AMBIGUOUS"}:
        context = _start(harness, capability)
        harness.service.complete(
            capability, context=context, completion_classification=nonusable_state,
            result={"status": nonusable_state}, positive_completion_evidence=None,
        )
    adapter = RecordingAdapter()
    with pytest.raises(ExecutionIntegrityError):
        harness.service.execute_once(
            capability, context_provider=lambda: harness.context(capability),
            parameters=DEFAULT_PARAMETERS, adapter=adapter,
        )
    assert adapter.calls == 0
    assert harness.store.state(capability["capability_id"]) == nonusable_state


def test_store_rejects_execution_terminal_transition_without_attestation(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue(activate=True)
    _start(harness, capability)
    with pytest.raises(CapabilityStoreError, match="execution_terminal_attestation_missing"):
        harness.store.append_transition(
            capability_id=capability["capability_id"],
            capability_digest=capability["capability_digest"],
            event_type="EXECUTION_COMPLETED", expected_state="EXECUTING",
            new_state="COMPLETED", occurred_at=NOW.isoformat().replace("+00:00", "Z"),
        )


def test_capability_integrity_mutation_and_regeneration_are_denied(h7_factory: Any) -> None:
    harness = h7_factory()
    capability = harness.issue()
    mutated = deepcopy(capability)
    mutated["target_identity"] = "target-2"
    assert not verify_capability(mutated)
    with pytest.raises(ExecutionIntegrityError, match="capability_integrity_invalid"):
        harness.service.activate(mutated)
    with pytest.raises(CapabilityStoreError, match="capability_identity_regeneration_denied"):
        harness.store.append_transition(
            capability_id=capability["capability_id"], capability_digest="0" * 64,
            event_type="CAPABILITY_ACTIVATED", expected_state="ACTIVE", new_state="ACTIVE",
            occurred_at=NOW.isoformat().replace("+00:00", "Z"),
        )
