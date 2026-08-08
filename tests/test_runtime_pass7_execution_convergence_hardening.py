from __future__ import annotations

import threading
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import pytest

import sbp_lex.execution.execution_gate as execution_gate_module
import sbp_lex.pipeline.runner as pipeline_runner_module
import sbp_lex.runtime.canonical_runtime as canonical_runtime_module
from main import main, sample_request
from sbp_lex.audit.audit_finalisation import verify_audit_record
from sbp_lex.classification.environment_modifiers import (
    normalize_environment_modifiers,
)
from sbp_lex.execution.capability import (
    ExecutionIntegrityError,
    ExecutionIntegrityService,
    ExecutionSpecification,
    verify_capability,
)
from sbp_lex.execution.capability_store import CapabilityLifecycleStore
from sbp_lex.execution.execution_gate import (
    SUCCESS_ONLY_TOKENS,
    TERMINAL_SUCCESS_TOKENS,
    enforce_execution_boundary,
    evaluate_strict_execution_security,
    run_execution_gate,
)
from sbp_lex.execution.terminal_assurance import verify_terminal_state_seal
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.replay_runner import run_replay_check, verify_replay_result
from sbp_lex.runtime.canonical_runtime import CanonicalRuntime
from sbp_lex.runtime.measured_startup import ensure_measured_startup
from sbp_lex.runtime.traversal_receipt import (
    NON_OPERATIONAL_REPLAY,
    OPERATIONAL_TRAVERSAL,
    verify_traversal_receipt,
)
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.security.threshold_tokens import (
    required_threshold_token_names,
    verify_threshold_bundle,
)
from sbp_lex.security.token_stack import (
    TOKEN_SIGNED_FIELDS,
    verify_token,
    verify_token_trace,
)
from sbp_lex.shared.hash_chain import (
    append_hash_entry,
    verify_hash_chain,
    verify_success_terminal_hash_chain,
)


CORE_PASS7_TOKENS = {
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain",
    "aurion",
    "execution_boundary",
    "execution_attestation",
    "threshold_bundle",
    "token_bundle",
    "master_convergence",
}
PARAMETERS = {"level": 1}
CONSTRAINTS = {
    "max_steps": 3,
    "min_classification": 2,
    "allowed_regions": ["AU", "NZ"],
    "licence_scope": "observe",
    "governance_required": True,
}


def _assert_terminal_rejected(state: Mapping[str, Any]) -> list[str]:
    result = evaluate_strict_execution_security(state)
    assert result["valid"] is False, result
    assert result["allowed"] is False, result
    boundary = enforce_execution_boundary(state)
    assert boundary["allowed"] is False, boundary
    assert boundary["decision"] == "DENY", boundary
    return list(result["failures"])


def _assert_gate_denied(state: Mapping[str, Any]) -> dict[str, Any]:
    result = run_execution_gate(state)
    assert result["decision"] == "DENY", result
    assert result["execution_result"] == "HALT", result
    assert result.get("execution_verified") is False
    assert result.get("effect_confirmed_success") is False
    assert not SUCCESS_ONLY_TOKENS.intersection(result.get("tokens", {}))
    return result


def _resign_token(token: Mapping[str, Any]) -> dict[str, Any]:
    updated = deepcopy(dict(token))
    signed = {name: deepcopy(updated[name]) for name in TOKEN_SIGNED_FIELDS}
    updated["digest"] = generate_digest(signed)
    updated["signature"] = sign_payload(signed)
    updated["verified"] = True
    return updated


@pytest.fixture(scope="session")
def operational_state() -> dict[str, Any]:
    state = main(deepcopy(sample_request()))
    security = evaluate_strict_execution_security(state)
    assert security == {"valid": True, "allowed": True, "failures": []}
    return state


@pytest.fixture(scope="session")
def same_request_later_state(
    operational_state: Mapping[str, Any],
) -> dict[str, Any]:
    state = main(deepcopy(sample_request()))
    assert state["request_fingerprint"] == operational_state[
        "request_fingerprint"
    ]
    assert state["runtime_traversal_receipt"]["receipt_digest"] != (
        operational_state["runtime_traversal_receipt"]["receipt_digest"]
    )
    assert evaluate_strict_execution_security(state)["allowed"] is True
    return state


@pytest.fixture(scope="session")
def different_request_state() -> dict[str, Any]:
    request = deepcopy(sample_request())
    request["context"]["evidence"][0]["content"] = (
        "pass7-distinct-request-evidence"
    )
    state = main(request)
    assert evaluate_strict_execution_security(state)["allowed"] is True
    return state


def _specification() -> ExecutionSpecification:
    return ExecutionSpecification(
        specification_id="pass7-test-action-target-1",
        target_identity="target-1",
        target_type="device",
        operation_identity="test_action",
        allowed_parameter_fields=("level",),
        required_parameter_fields=("level",),
        constraints=CONSTRAINTS,
        adapter_identity="adapter-1",
    )


@pytest.fixture
def capability_harness(tmp_path: Path) -> dict[str, Any]:
    runtime = CanonicalRuntime()
    request_id = "pass7-" + generate_digest({"root": str(tmp_path)})[:16]
    traversal = runtime.traverse(
        deepcopy(sample_request()), request_id=request_id
    )
    store = CapabilityLifecycleStore(
        tmp_path / "capabilities.jsonl", allowed_root=tmp_path
    )
    store.initialize()
    specification = _specification()
    service = ExecutionIntegrityService(
        store, execution_specifications=(specification,)
    )
    reference = traversal["execution_authority_reference"]
    assert isinstance(reference, str) and reference
    capability = runtime.issue_execution_capability(
        reference,
        execution_service=service,
        specification_id=specification.specification_id,
        parameters=PARAMETERS,
    )
    service.activate(capability)
    harness = {
        "runtime": runtime,
        "state": traversal["state"],
        "reference": reference,
        "service": service,
        "store": store,
        "capability": capability,
    }
    yield harness
    service.close()


class _AcknowledgingAdapter:
    identity = "adapter-1"
    safe_cancellation_supported = False

    def __init__(self, status: str = "DONE") -> None:
        self.status = status
        self.calls = 0

    def __call__(
        self,
        target: str,
        target_type: str,
        operation: str,
        parameters: Mapping[str, Any],
        checkpoint: Any,
    ) -> dict[str, Any]:
        del target_type, parameters, checkpoint
        self.calls += 1
        return {
            "status": self.status,
            "target": target,
            "operation": operation,
        }


def _context(harness: Mapping[str, Any], state: Mapping[str, Any] | None = None):
    return harness["service"].build_execution_context(
        harness["capability"],
        state=state or harness["state"],
        parameters=PARAMETERS,
        constraints=CONSTRAINTS,
    )


# A: positive terminal convergence, exact token set, audit, seal and receipt.
def test_a_positive_operational_convergence_is_exactly_terminally_bound(
    operational_state: Mapping[str, Any],
) -> None:
    state = operational_state
    expected_tokens = CORE_PASS7_TOKENS | set(required_threshold_token_names())
    assert set(state["tokens"]) == expected_tokens == set(
        TERMINAL_SUCCESS_TOKENS
    )
    assert state["decision"] == "ALLOW"
    assert state["execution_result"] == "EXECUTE"
    assert state["effect_phase"] == "AUTHORISED_TO_ATTEMPT"
    assert state["effect_confirmed_success"] is False
    assert state["effect_authority_eligible"] is True
    assert verify_hash_chain(state)
    chain_ok, chain_failures = verify_success_terminal_hash_chain(state)
    assert chain_ok, chain_failures
    assert verify_audit_record(state["audit_record"])
    seal_ok, seal_failures = verify_terminal_state_seal(
        state,
        expected_receipt_purpose=OPERATIONAL_TRAVERSAL,
    )
    assert seal_ok, seal_failures
    receipt_ok, receipt_failures = verify_traversal_receipt(
        state["runtime_traversal_receipt"],
        expected_purpose=OPERATIONAL_TRAVERSAL,
        current_measurement=ensure_measured_startup(),
    )
    assert receipt_ok, receipt_failures


# B: every mandatory core and configured conditional component is required.
@pytest.mark.parametrize(
    "token_name", sorted(CORE_PASS7_TOKENS | set(required_threshold_token_names()))
)
def test_b_missing_any_mandatory_or_conditional_token_is_rejected(
    token_name: str, operational_state: Mapping[str, Any]
) -> None:
    state = deepcopy(dict(operational_state))
    state["tokens"].pop(token_name)
    failures = _assert_terminal_rejected(state)
    assert failures
    if token_name in required_threshold_token_names() or token_name == "threshold_bundle":
        threshold_ok, threshold_failures = verify_threshold_bundle(state)
        assert not threshold_ok
        assert threshold_failures


# C/D plus exact type/name/stage/temporal checks.
@pytest.mark.parametrize(
    ("case", "mutator"),
    [
        ("digest", lambda token: token.__setitem__("digest", "0" * 64)),
        ("signature", lambda token: token.__setitem__("signature", {})),
        ("wrong_type", lambda token: token.__setitem__("version", 7)),
        ("name", lambda token: token.__setitem__("name", "licensing")),
        ("stage", lambda token: token.__setitem__("issued_at_stage", "audit")),
        ("temporal_index", lambda token: token.__setitem__("issued_at", 0)),
    ],
)
def test_c_d_token_digest_signature_type_name_stage_and_time_fail_closed(
    case: str,
    mutator: Any,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    token = deepcopy(state["tokens"]["governance"])
    mutator(token)
    if case not in {"digest", "signature"}:
        token = _resign_token(token)
    state["tokens"]["governance"] = token
    assert not verify_token(
        token,
        expected_name="governance",
        expected_stage="governance",
        expected_request_fingerprint=state["request_fingerprint"],
    )
    _assert_terminal_rejected(state)


# E-H and the cross-state collective/provider/target binding matrix.
@pytest.mark.parametrize(
    ("case", "mutate"),
    [
        (
            "request_fingerprint",
            lambda state: state.__setitem__("request_fingerprint", "1" * 64),
        ),
        ("eie_digest", lambda state: state.__setitem__("eie_hash", "2" * 64)),
        ("eie_identity", lambda state: state.__setitem__("traversal_id", "stale-eie")),
        ("state_hash", lambda state: state.__setitem__("state_hash", "3" * 64)),
        (
            "tier_downgrade",
            lambda state: state["safety_profile"].__setitem__(
                "computed_tier", "TIER_1"
            ),
        ),
        (
            "collective_signal",
            lambda state: state["collective_attachment"].__setitem__(
                "attachment_hash", "4" * 64
            ),
        ),
        ("target_action", lambda state: state.__setitem__("action", "other_action")),
        (
            "live_provider",
            lambda state: state["verified_substrate_references"].__setitem__(
                "provider_mode", "live_external"
            ),
        ),
    ],
)
def test_e_to_h_terminal_identity_state_tier_collective_and_provider_mutations_fail(
    case: str,
    mutate: Any,
    operational_state: Mapping[str, Any],
) -> None:
    del case
    state = deepcopy(dict(operational_state))
    mutate(state)
    _assert_terminal_rejected(state)


@pytest.mark.parametrize(
    ("token_name", "field", "replacement"),
    [
        ("governance", "request_fingerprint", "5" * 64),
        ("governance", "state_hash", "6" * 64),
        ("governance", "tier", "TIER_1"),
    ],
)
def test_e_g_h_resigned_token_binding_substitution_is_still_rejected(
    token_name: str,
    field: str,
    replacement: str,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    token = deepcopy(state["tokens"][token_name])
    token[field] = replacement
    state["tokens"][token_name] = _resign_token(token)
    _assert_terminal_rejected(state)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("eie_digest", "7" * 64),
        ("traversal_id", "stale-eie-identifier"),
        ("collective_attachment_hash", "8" * 64),
    ],
)
def test_f_resigned_execution_boundary_identity_bindings_cannot_be_changed(
    field: str,
    replacement: str,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    token = deepcopy(state["tokens"]["execution_boundary"])
    token["payload"][field] = replacement
    state["tokens"]["execution_boundary"] = _resign_token(token)
    _assert_terminal_rejected(state)


# I-L and the extended denial-conservation matrix.
@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("authority_first_result", "DENY"),
        ("procedural_truth_result", "FAIL"),
        ("procedural_truth_outcome", "PT_FAIL"),
        ("corroboration_met", False),
        ("classification_result", "DENY"),
        ("licensing_result", "DENY"),
        ("governance_result", "DENY"),
        ("governance_result", "ESCALATE"),
        ("grc_result", "FAIL"),
        ("domain_result", "fail"),
        ("domain_result", "escalate"),
        ("aurion15_result", "fail"),
    ],
)
def test_i_to_l_upstream_invalidity_cannot_be_restored_by_direct_gate_reentry(
    field: str,
    invalid: Any,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    state[field] = invalid
    state["decision"] = "ALLOW"
    state["execution_result"] = "EXECUTE"
    _assert_terminal_rejected(state)
    _assert_gate_denied(state)


def test_gate_reentry_cannot_reissue_terminal_success_material(
    operational_state: Mapping[str, Any],
) -> None:
    _assert_gate_denied(deepcopy(dict(operational_state)))


# M: removed/reordered/duplicate/rewired/tampered/truncated/fake chain attacks.
@pytest.mark.parametrize(
    "attack",
    [
        "removed",
        "reordered",
        "duplicate",
        "prior_hash",
        "payload_digest",
        "entry_hash",
        "truncated",
        "fake_success",
    ],
)
def test_m_hash_chain_attack_matrix_prevents_terminal_execution(
    attack: str,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    chain = state["hash_chain"]
    if attack == "removed":
        chain.pop(4)
    elif attack == "reordered":
        chain[4], chain[5] = chain[5], chain[4]
    elif attack == "duplicate":
        chain.insert(5, deepcopy(chain[4]))
    elif attack == "prior_hash":
        chain[5]["previous_hash"] = "9" * 64
    elif attack == "payload_digest":
        chain[5]["payload_hash"] = "a" * 64
    elif attack == "entry_hash":
        chain[5]["hash"] = "b" * 64
    elif attack == "truncated":
        state["hash_chain"] = chain[:-1]
    elif attack == "fake_success":
        state = append_hash_entry(
            state,
            stage="controlled_return",
            payload={"decision": "ALLOW", "forged": True},
        )
    assert not verify_hash_chain(state)
    terminal_ok, _ = verify_success_terminal_hash_chain(state)
    assert not terminal_ok
    _assert_terminal_rejected(state)


def test_m_chain_copied_between_requests_is_rejected(
    operational_state: Mapping[str, Any],
    different_request_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(different_request_state))
    state["hash_chain"] = deepcopy(operational_state["hash_chain"])
    assert not verify_hash_chain(state)
    _assert_terminal_rejected(state)


# N and cross-request/cross-traversal token transplantation.
def test_n_cross_request_token_and_complete_stack_transplants_fail(
    operational_state: Mapping[str, Any],
    different_request_state: Mapping[str, Any],
) -> None:
    token_transplant = deepcopy(dict(operational_state))
    token_transplant["tokens"]["governance"] = deepcopy(
        different_request_state["tokens"]["governance"]
    )
    _assert_terminal_rejected(token_transplant)

    stack_transplant = deepcopy(dict(operational_state))
    stack_transplant["tokens"] = deepcopy(different_request_state["tokens"])
    stack_transplant["token_trace"] = deepcopy(
        different_request_state["token_trace"]
    )
    _assert_terminal_rejected(stack_transplant)


def test_n_prior_attestation_from_same_request_new_traversal_fails(
    operational_state: Mapping[str, Any],
    same_request_later_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(same_request_later_state))
    state["tokens"]["execution_attestation"] = deepcopy(
        operational_state["tokens"]["execution_attestation"]
    )
    state["execution_attestation"] = deepcopy(
        operational_state["execution_attestation"]
    )
    _assert_terminal_rejected(state)


def test_operational_receipt_replay_and_cross_request_transplant_are_rejected(
    operational_state: Mapping[str, Any],
) -> None:
    receipt = deepcopy(operational_state["runtime_traversal_receipt"])
    with pytest.raises(
        ValueError,
        match="operational_traversal_receipt_replay_detected",
    ):
        run_dual_pipeline(
            deepcopy(sample_request()),
            runtime_traversal_receipt=receipt,
            runtime_receipt_purpose=OPERATIONAL_TRAVERSAL,
        )

    other_request = deepcopy(sample_request())
    other_request["context"]["evidence"][0]["content"] = (
        "receipt-transplant-target"
    )
    with pytest.raises(
        ValueError,
        match="runtime_traversal_receipt_request_fingerprint_mismatch",
    ):
        run_dual_pipeline(
            other_request,
            runtime_traversal_receipt=receipt,
            runtime_receipt_purpose=OPERATIONAL_TRAVERSAL,
        )


def test_operational_receipt_transplant_between_completed_states_is_rejected(
    operational_state: Mapping[str, Any],
    same_request_later_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(same_request_later_state))
    state["runtime_traversal_receipt"] = deepcopy(
        operational_state["runtime_traversal_receipt"]
    )
    _assert_terminal_rejected(state)


def test_exact_token_set_rejects_excess_names_duplicate_trace_and_key_name_collision(
    operational_state: Mapping[str, Any],
) -> None:
    excess = deepcopy(dict(operational_state))
    for index in range(64):
        excess["tokens"][f"unexpected_{index}"] = deepcopy(
            operational_state["tokens"]["governance"]
        )
    _assert_terminal_rejected(excess)

    duplicate_trace = deepcopy(dict(operational_state))
    duplicate_trace["token_trace"].append(
        deepcopy(duplicate_trace["token_trace"][0])
    )
    _assert_terminal_rejected(duplicate_trace)

    collision = deepcopy(dict(operational_state))
    collision["tokens"]["governance"] = deepcopy(
        collision["tokens"]["licensing"]
    )
    _assert_terminal_rejected(collision)


@pytest.mark.parametrize("attack", ["reordered", "duplicate_index"])
def test_token_trace_reorder_or_duplicate_issue_index_is_rejected(
    attack: str,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    if attack == "reordered":
        state["token_trace"][0], state["token_trace"][1] = (
            state["token_trace"][1],
            state["token_trace"][0],
        )
    else:
        state["token_trace"][1]["issued_at"] = state["token_trace"][0][
            "issued_at"
        ]
    trace_ok, trace_failures = verify_token_trace(
        state,
        expected_names=TERMINAL_SUCCESS_TOKENS,
        exact=True,
    )
    assert not trace_ok
    assert any(
        "token_trace_index_invalid" in failure
        or "token_trace_issue_sequence_invalid" in failure
        for failure in trace_failures
    )
    _assert_terminal_rejected(state)


def test_threshold_modifier_normalization_and_defaults_are_semantically_bound(
    operational_state: Mapping[str, Any],
) -> None:
    state = operational_state
    threshold_ok, threshold_failures = verify_threshold_bundle(state)
    assert threshold_ok, threshold_failures
    assert state["tokens"]["escalation_threshold"]["payload"]["value"] == (
        "NONE"
    )
    assert state["tokens"]["environment_modifier"]["payload"]["value"] == (
        normalize_environment_modifiers(state["context"])
    )
    assert state["tokens"]["environment_modifier"]["payload"]["value"][
        "geographic_isolation"
    ] == "UNDECLARED"


@pytest.mark.parametrize(
    ("field", "value", "component"),
    [
        ("geographic_isolation", "remote", "environment_modifier"),
        ("escalation_threshold", "HUMAN_REVIEW", "escalation_threshold"),
    ],
)
def test_post_issuance_threshold_modifier_or_default_substitution_is_rejected(
    field: str,
    value: str,
    component: str,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    state["context"][field] = value
    threshold_ok, threshold_failures = verify_threshold_bundle(state)
    assert not threshold_ok
    assert f"threshold_component_value_mismatch:{component}" in (
        threshold_failures
    )
    _assert_terminal_rejected(state)


# Q and terminal audit/evidence continuity.
@pytest.mark.parametrize(
    "mutation",
    [
        "readiness_missing",
        "readiness_digest",
        "audit_missing",
        "audit_finalisation",
        "controlled_outcome",
        "final_outcome",
    ],
)
def test_q_terminal_execution_requires_complete_audit_readiness_and_outcome(
    mutation: str,
    operational_state: Mapping[str, Any],
) -> None:
    state = deepcopy(dict(operational_state))
    if mutation == "readiness_missing":
        state.pop("audit_readiness")
    elif mutation == "readiness_digest":
        state["audit_readiness"]["readiness_digest"] = "c" * 64
    elif mutation == "audit_missing":
        state.pop("audit_record")
    elif mutation == "audit_finalisation":
        state["audit_finalisation"]["audit_complete"] = False
    elif mutation == "controlled_outcome":
        state.pop("controlled_outcome")
    elif mutation == "final_outcome":
        state["final_outcome"]["allowed"] = False
    _assert_terminal_rejected(state)


def test_q_false_audit_readiness_at_the_pre_gate_boundary_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, Any]] = []
    canonical_gate = pipeline_runner_module.run_execution_gate

    def capture_pre_gate(state: Mapping[str, Any]) -> dict[str, Any]:
        captured.append(deepcopy(dict(state)))
        return canonical_gate(state)

    monkeypatch.setattr(
        pipeline_runner_module, "run_execution_gate", capture_pre_gate
    )
    baseline = run_dual_pipeline(deepcopy(sample_request()))
    assert baseline["decision"] == "ALLOW"
    assert captured

    canonical_readiness_builder = (
        execution_gate_module._build_audit_readiness
    )

    def false_readiness(state: Mapping[str, Any]) -> dict[str, Any]:
        readiness = canonical_readiness_builder(state)
        readiness["ready"] = False
        payload = {
            field: deepcopy(value)
            for field, value in readiness.items()
            if field != "readiness_digest"
        }
        readiness["readiness_digest"] = generate_digest(payload)
        return readiness

    monkeypatch.setattr(
        execution_gate_module, "_build_audit_readiness", false_readiness
    )
    result = run_execution_gate(captured[0])
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert any(
        "audit_readiness" in failure
        for failure in result.get("token_verification_failures", [])
    )
    assert not SUCCESS_ONLY_TOKENS.intersection(result.get("tokens", {}))


# R: replay is exact and observational, never operationally effect-eligible.
def test_r_replay_is_deterministic_and_cannot_issue_effect_authority() -> None:
    replay = run_replay_check(request=deepcopy(sample_request()), replay_count=2)
    replay_ok, replay_failures = verify_replay_result(replay)
    assert replay_ok, replay_failures
    assert replay["matched"] is True
    assert replay["mismatches"] == []
    assert all(
        run["runtime_receipt_purpose"] == NON_OPERATIONAL_REPLAY
        and run["effect_authority_eligible"] is False
        and run["effect_phase"] == "NOT_AUTHORISED"
        for run in replay["runs"]
    )

    replay_state = run_dual_pipeline(
        deepcopy(sample_request()),
        runtime_receipt_purpose=NON_OPERATIONAL_REPLAY,
    )
    security = evaluate_strict_execution_security(replay_state)
    assert security["valid"] is True, security
    assert security["allowed"] is False, security
    assert replay_state["effect_authority_eligible"] is False
    assert replay_state["effect_phase"] == "NOT_AUTHORISED"


# S: a post-startup measurement change remains relevant at terminal authority.
def test_s_measured_runtime_drift_after_traversal_blocks_effect_authority(
    monkeypatch: pytest.MonkeyPatch,
    operational_state: Mapping[str, Any],
) -> None:
    measurement = ensure_measured_startup()
    drifted = {**measurement, "runtime_identity": "d" * 64}
    monkeypatch.setattr(
        execution_gate_module,
        "ensure_measured_startup",
        lambda: deepcopy(drifted),
    )
    failures = _assert_terminal_rejected(operational_state)
    assert any("runtime" in failure or "receipt" in failure for failure in failures)


# O/U: successful capability is single-use; its authority reference is consumed.
def test_o_u_capability_and_authority_reference_are_single_use(
    capability_harness: Mapping[str, Any],
) -> None:
    harness = capability_harness
    context = _context(harness)
    adapter = _AcknowledgingAdapter()
    outcome = harness["service"].execute_once(
        harness["capability"],
        context_provider=lambda: deepcopy(context),
        parameters=PARAMETERS,
        adapter=adapter,
    )
    assert outcome["effect_status"] == "CONFIRMED_SUCCESS"
    assert adapter.calls == 1
    assert harness["store"].state(harness["capability"]["capability_id"]) == (
        "COMPLETED"
    )

    with pytest.raises(ExecutionIntegrityError):
        harness["service"].execute_once(
            harness["capability"],
            context_provider=lambda: deepcopy(context),
            parameters=PARAMETERS,
            adapter=adapter,
        )
    assert adapter.calls == 1

    with pytest.raises(ValueError, match="execution_authority_reference_unavailable"):
        harness["runtime"].issue_execution_capability(
            harness["reference"],
            execution_service=harness["service"],
            specification_id="pass7-test-action-target-1",
            parameters=PARAMETERS,
        )


# P: a valid capability cannot be transferred to another request/state.
def test_p_cross_request_capability_reuse_is_rejected_before_effect(
    capability_harness: Mapping[str, Any],
    different_request_state: Mapping[str, Any],
) -> None:
    harness = capability_harness
    cross_context = _context(harness, different_request_state)
    with pytest.raises(ExecutionIntegrityError, match="capability_binding_mismatch"):
        harness["service"].reserve(
            harness["capability"], context=cross_context
        )
    assert harness["store"].state(harness["capability"]["capability_id"]) == (
        "ACTIVE"
    )


# T: unknown/timeout/mismatched local acknowledgement is never success.
@pytest.mark.parametrize("status", ["TIMEOUT", "UNKNOWN", "PARTIAL"])
def test_t_ambiguous_synthetic_effect_is_durably_ambiguous_not_success(
    status: str,
    capability_harness: Mapping[str, Any],
) -> None:
    harness = capability_harness
    context = _context(harness)
    adapter = _AcknowledgingAdapter(status=status)
    with pytest.raises(ExecutionIntegrityError, match="acknowledgement"):
        harness["service"].execute_once(
            harness["capability"],
            context_provider=lambda: deepcopy(context),
            parameters=PARAMETERS,
            adapter=adapter,
        )
    assert adapter.calls == 1
    assert harness["store"].state(harness["capability"]["capability_id"]) == (
        "AMBIGUOUS"
    )


def test_corrupted_capability_is_rejected_before_adapter_call(
    capability_harness: Mapping[str, Any],
) -> None:
    harness = capability_harness
    corrupted = deepcopy(harness["capability"])
    corrupted["capability_digest"] = "e" * 64
    assert not verify_capability(corrupted)
    adapter = _AcknowledgingAdapter()
    with pytest.raises(ExecutionIntegrityError):
        harness["service"].execute_once(
            corrupted,
            context_provider=lambda: _context(harness),
            parameters=PARAMETERS,
            adapter=adapter,
        )
    assert adapter.calls == 0


def test_same_request_concurrent_traversal_is_blocked_without_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = CanonicalRuntime()
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def blocked_pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        entered.set()
        assert release.wait(timeout=30)
        raise RuntimeError("synthetic_interrupted_terminal_processing")

    monkeypatch.setattr(
        canonical_runtime_module, "run_dual_pipeline", blocked_pipeline
    )

    def first_traversal() -> None:
        try:
            runtime.traverse(
                deepcopy(sample_request()), request_id="pass7-race-request"
            )
        except BaseException as exc:  # noqa: BLE001 - captured for thread assertion
            errors.append(exc)

    thread = threading.Thread(target=first_traversal)
    thread.start()
    assert entered.wait(timeout=10)
    try:
        with pytest.raises(
            ValueError, match="duplicate_active_traversal_denied"
        ):
            runtime.traverse(
                deepcopy(sample_request()), request_id="pass7-race-request"
            )
        with pytest.raises(
            ValueError, match="replay_during_active_traversal_denied"
        ):
            runtime.replay(deepcopy(sample_request()), replay_count=2)
    finally:
        release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], RuntimeError)
    assert runtime.last_result is None
    assert runtime.traversal_count == 0
    assert runtime._pending_execution_authorities == {}

    replay = runtime.replay(deepcopy(sample_request()), replay_count=2)
    replay_ok, replay_failures = verify_replay_result(replay)
    assert replay_ok, replay_failures
    assert replay["matched"] is True
    assert all(
        run["runtime_receipt_purpose"] == NON_OPERATIONAL_REPLAY
        and run["effect_authority_eligible"] is False
        and run["effect_phase"] == "NOT_AUTHORISED"
        for run in replay["runs"]
    )


# V and assurance-critical failure injection.
@pytest.mark.parametrize(
    "malformed",
    [None, [], {}, {"tokens": []}, {"hash_chain": "not-a-chain"}],
)
def test_v_malformed_gate_input_never_raises_or_executes(malformed: Any) -> None:
    result = run_execution_gate(malformed)
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result.get("execution_verified") is False


def test_v_token_verifier_exception_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    operational_state: Mapping[str, Any],
) -> None:
    def explode(*args: Any, **kwargs: Any):
        del args, kwargs
        raise RuntimeError("synthetic_token_verifier_failure")

    monkeypatch.setattr(
        execution_gate_module, "verify_threshold_bundle", explode
    )
    _assert_gate_denied(deepcopy(dict(operational_state)))

    monkeypatch.setattr(execution_gate_module, "verify_required_tokens", explode)
    security = evaluate_strict_execution_security(operational_state)
    assert security["valid"] is False
    assert security["allowed"] is False
    assert security["failures"] == ["terminal_security_exception:RuntimeError"]


def test_v_hash_verifier_exception_fails_closed_without_escaping(
    monkeypatch: pytest.MonkeyPatch,
    operational_state: Mapping[str, Any],
) -> None:
    def explode(*args: Any, **kwargs: Any):
        del args, kwargs
        raise RuntimeError("synthetic_hash_verifier_failure")

    monkeypatch.setattr(execution_gate_module, "verify_hash_chain", explode)
    result = run_execution_gate(deepcopy(dict(operational_state)))
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result.get("execution_verified") is False


@pytest.mark.parametrize("failure", ["audit", "replay_ledger", "persistence"])
def test_v_terminal_evidence_failure_never_commits_effect_authority(
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = CanonicalRuntime()

    def explode(*args: Any, **kwargs: Any):
        del args, kwargs
        raise RuntimeError(f"synthetic_{failure}_failure")

    if failure == "audit":
        monkeypatch.setattr(pipeline_runner_module, "run_audit", explode)
    elif failure == "replay_ledger":
        monkeypatch.setattr(
            canonical_runtime_module.PIPELINE_REPLAY_LEDGER, "append", explode
        )
    else:
        monkeypatch.setattr(
            canonical_runtime_module.RUNTIME_INTEGRITY_STORE,
            "append_state_summary",
            explode,
        )

    with pytest.raises(RuntimeError, match=f"synthetic_{failure}_failure"):
        runtime.traverse(
            deepcopy(sample_request()), request_id=f"pass7-{failure}-failure"
        )
    assert runtime.last_result is None
    assert runtime.traversal_count == 0
    assert runtime._pending_execution_authorities == {}
