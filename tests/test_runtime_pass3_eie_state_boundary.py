from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from external_substrates.shared.canonical_json import canonical_dumps
from main import sample_request
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.collective.context_interface import (
    attach_collective_signals,
    prepare_pre_context_signals,
)
from sbp_lex.pipeline import hard_ingress
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.hard_ingress import (
    adapt_external_request,
    run_hard_ingress,
)
from sbp_lex.pipeline.replay_runner import run_replay_check
from sbp_lex.pipeline.runner import (
    PreparedPipelineBoundary,
    _run_admitted_pipeline,
    prepare_pipeline_boundary,
    run_pipeline,
)
from sbp_lex.runtime.boundary_types import EIEReplayRegistry
from sbp_lex.runtime.synthetic_substrates import (
    FIXTURE_VALIDATION_TIME,
    build_synthetic_fixture_chain,
    prepare_synthetic_substrate_signals,
    validate_raw_synthetic_chain,
)
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.shared.hash_chain import verify_hash_chain
from sbp_lex.shared.state_builder import (
    build_state,
    validate_boundary_protection,
)


ROOT = Path(__file__).resolve().parents[1]


def _request(action: str = "pass3_test_action") -> dict:
    request = sample_request()
    request["action"] = action
    request["objective"] = "prove deterministic Pass 3 boundary traversal"
    request["actor"] = {
        "id": "pass3-actor",
        "type": "local_operator",
        "role": "requester",
    }
    request["principal"] = {
        "id": "pass3-principal",
        "type": "desktop_identity",
        "role": "principal",
    }
    request["authority_claims"] = {
        "claimed_authority": "test_authority",
        "scope": "controlled_test",
    }
    return request


def _resign(signals: dict) -> dict:
    payload = {
        key: deepcopy(value)
        for key, value in signals.items()
        if key not in {"digest", "signature"}
    }
    signals["digest"] = generate_digest(payload)
    signals["signature"] = sign_payload(payload)
    return signals


def _initial_state(request: dict | None = None) -> tuple[dict, dict]:
    current = request or _request()
    result = run_hard_ingress(request=current)
    assert result.accepted and result.admission is not None
    return build_state(result.admission), result.admission.collective_signals()


def test_valid_boundary_traversal_and_runtime_evidence_are_complete() -> None:
    state = run_dual_pipeline(_request())
    parity = state["pipeline_initial_parity"]
    assert state["hard_entry_gate"]["accepted"] is True
    assert state["collective_signal_status"] == "ATTACHED"
    assert state["decision"] == "ALLOW"
    assert state["execution_result"] == "EXECUTE"
    assert parity["exact_parity_result"] is True
    assert parity["near_match_reconciliation_used"] is False
    assert parity["pipeline_a_initial_hash"] == parity[
        "pipeline_b_initial_hash"
    ]
    assert all(parity["field_matches"].values())
    assert verify_hash_chain(state)


@pytest.mark.parametrize(
    "invalid",
    [None, "not-a-request", ["not", "a", "mapping"]],
)
def test_malformed_request_rejection_forms_no_state(invalid: object) -> None:
    denial = run_pipeline(invalid)  # type: ignore[arg-type]
    assert denial["accepted"] is False
    assert denial["governed_state_formed"] is False
    assert denial["authority_token_issued"] is False
    assert denial["governance_result_issued"] is False
    assert denial["downstream_stage_reached"] is False
    assert "state_version" not in denial
    assert "governance_result" not in denial


def test_oversized_input_rejection_forms_no_state() -> None:
    request = _request()
    request["payload"]["metadata"] = {"blob": "x" * 70_000}
    denial = run_pipeline(request)
    assert "request_size_limit_exceeded" in denial["failures"]
    assert denial["governed_state_formed"] is False


def test_unknown_field_and_state_injection_are_rejected() -> None:
    unknown = _request()
    unknown["undeclared"] = True
    assert "unknown_field:request.undeclared" in run_pipeline(unknown)[
        "failures"
    ]
    injected = _request()
    injected["payload"]["metadata"] = {"state_hash": "attacker"}
    denial = run_pipeline(injected)
    assert "direct_internal_state_injection_rejected" in denial["failures"]
    assert denial["governed_state_formed"] is False


def test_adapter_normalization_and_request_fingerprint_are_immutable() -> None:
    request = _request()
    adapter, failures = adapt_external_request(request)
    assert failures == [] and adapter is not None
    original = adapter.normalized_request()
    request["action"] = "mutated_after_fingerprinting"
    request["payload"]["classification"]["autonomy_level"] = 999
    assert adapter.normalized_request() == original
    assert adapter.request_fingerprint == generate_digest(original)
    assert adapter.validate() == (True, [])


def test_eie_is_constructed_once_and_contains_no_authority_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    original = hard_ingress.build_execution_intent_envelope

    def counted(request: dict) -> dict:
        nonlocal calls
        calls += 1
        return original(request)

    monkeypatch.setattr(
        hard_ingress, "build_execution_intent_envelope", counted
    )
    result = hard_ingress.run_hard_ingress(request=_request())
    assert result.accepted
    assert calls == 1
    assert result.admission is not None
    eie = result.admission.eie()
    assert {
        "governance_result",
        "execution_result",
        "classification_result",
        "licensing_result",
        "root_of_trust_anchorage",
        "procedural_truth_certification",
    }.isdisjoint(eie)
    assert eie["authority_claim_inputs"]["validation_status"] == (
        "UNVALIDATED_INPUT"
    )


def test_eie_tamper_after_digest_is_rejected_before_state() -> None:
    result = run_hard_ingress(request=_request())
    assert result.admission is not None
    tampered_eie = result.admission.eie()
    tampered_eie["objective"] = "mutated"
    tampered = replace(
        result.admission, eie_json=canonical_dumps(tampered_eie)
    )
    with pytest.raises(ValueError, match="hard_entry_admission_invalid"):
        build_state(tampered)


def test_stale_and_replayed_eie_are_rejected() -> None:
    first = run_hard_ingress(request=_request())
    assert first.admission is not None
    issued_at = first.admission.eie()["freshness"]["issued_at"]
    stale = run_hard_ingress(
        request=_request(), validation_logical_time=issued_at + 301
    )
    assert stale.accepted is False
    assert "stale_eie" in stale.evidence()["failures"]
    registry = EIEReplayRegistry()
    assert run_hard_ingress(
        request=_request(), replay_registry=registry
    ).accepted
    replayed = run_hard_ingress(
        request=_request(), replay_registry=registry
    )
    assert replayed.accepted is False
    assert {
        "replayed_eie_nonce",
        "replayed_eie_digest",
    }.issubset(replayed.evidence()["failures"])


def test_request_mismatch_and_substrate_status_rejection_form_no_state() -> None:
    wrong_signals = prepare_pre_context_signals(_request("other_action"))
    mismatch = run_pipeline(_request(), wrong_signals)
    assert mismatch["governed_state_formed"] is False
    assert "signal_request_fingerprint_mismatch" in mismatch["failures"]

    substrate = prepare_synthetic_substrate_signals(_request())
    assert substrate.signals is not None
    signals = deepcopy(substrate.signals)
    signals["synthetic_substrate_evidence"][
        "skg_validation_status"
    ] = "REJECTED"
    denial = run_pipeline(_request(), _resign(signals))
    assert denial["governed_state_formed"] is False
    assert "skg_validation_status_rejected" in denial["failures"]


def test_bridge_failure_and_package_replacement_are_rejected() -> None:
    substrate = prepare_synthetic_substrate_signals(_request())
    assert substrate.signals is not None
    signals = deepcopy(substrate.signals)
    evidence = signals["synthetic_substrate_evidence"]
    evidence["bridge_validation_status"] = "FAIL"
    bridge_payload = {
        "bridge_validation_status": evidence["bridge_validation_status"],
        "request_fingerprint": evidence["request_fingerprint"],
        "eie_digest": evidence["eie_digest"],
        "skg_package_digest": evidence["skg_package_digest"],
        "dtn_package_digest": evidence["dtn_package_digest"],
    }
    evidence["bridge_result_digest"] = generate_digest(bridge_payload)
    denial = run_pipeline(_request(), _resign(signals))
    assert denial["governed_state_formed"] is False
    assert "bridge_validation_status_rejected" in denial["failures"]

    eie_a, skg_a, _ = build_synthetic_fixture_chain(_request())
    _, _, dtn_b = build_synthetic_fixture_chain(_request("other_action"))
    replaced = validate_raw_synthetic_chain(
        request=_request(),
        raw_skg=canonical_dumps(skg_a),
        raw_dtn=canonical_dumps(dtn_b),
        validation_time=FIXTURE_VALIDATION_TIME,
        eie=eie_a,
    )
    assert replaced.accepted is False
    assert replaced.signals is None


def test_state_construction_is_deterministic_and_contains_only_references() -> None:
    first = run_hard_ingress(request=_request())
    second = run_hard_ingress(request=_request())
    assert first.admission is not None and second.admission is not None
    state_a = build_state(first.admission)
    state_b = build_state(second.admission)
    assert state_a == state_b
    assert state_a["state_construction_hash"] == state_b[
        "state_construction_hash"
    ]
    assert state_a["collective_signal_status"] == "UNATTACHED"
    assert state_a["collective_signals"] == {}
    references = state_a["verified_substrate_references"]
    assert references["skg_validation_status"] == "VALID"
    assert references["dtn_validation_status"] == "VALID"
    assert "authority_hierarchy" not in canonical_dumps(state_a)
    assert "feasibility_constraints" not in canonical_dumps(state_a)


def test_protected_field_overwrite_and_double_attachment_are_rejected() -> None:
    state, signals = _initial_state()
    state["request_fingerprint"] = "attacker"
    with pytest.raises(
        ValueError, match="protected_state_invalid_before_attachment"
    ):
        attach_collective_signals(state, signals)

    clean_state, clean_signals = _initial_state()
    attached = attach_collective_signals(clean_state, clean_signals)
    with pytest.raises(ValueError, match="collective_signal_already_attached"):
        attach_collective_signals(attached, clean_signals)


def test_stale_and_cross_request_attachment_fail_closed() -> None:
    state, signals = _initial_state()
    issued = signals["timestamp"]
    stale = attach_collective_signals(
        state, signals, validation_logical_time=issued + 301
    )
    assert stale["collective_signal_status"] == "REJECTED"
    assert "stale_collective_signal" in stale["governance_feedback"][
        "collective_signal_failures"
    ]

    other_signals = prepare_pre_context_signals(_request("other_action"))
    cross_state, _ = _initial_state()
    cross = attach_collective_signals(cross_state, other_signals)
    assert cross["collective_signal_status"] == "REJECTED"
    assert "collective_signal_request_fingerprint_mismatch" in cross[
        "governance_feedback"
    ]["collective_signal_failures"]


def test_attachment_is_minimal_bound_and_hash_chain_recorded() -> None:
    prepared = prepare_pipeline_boundary(_request())
    assert isinstance(prepared, PreparedPipelineBoundary)
    state = prepared.materialize()
    attached = state["collective_signals"]
    assert {"skg_context", "dtn_context", "synthetic_substrate_evidence"}.isdisjoint(
        attached
    )
    evidence = state["collective_signal_evidence"]
    assert evidence["request_bound"] is True
    assert evidence["eie_bound"] is True
    assert evidence["digest_bound"] is True
    assert evidence["freshness_bound"] is True
    assert state["collective_attachment"]["attachment_hash"] == (
        prepared.collective_attachment_hash
    )
    assert state["hash_chain"][-1]["stage"] == "collective_attach"
    assert validate_boundary_protection(state) == (True, [])


def test_hard_entry_and_downstream_bypass_are_rejected() -> None:
    with pytest.raises(TypeError, match="hard_entry_admission_required"):
        build_state(_request())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="prepared_pipeline_boundary_required"):
        _run_admitted_pipeline({})  # type: ignore[arg-type]
    direct = run_root_of_trust({"hard_entry_gate": {"accepted": False}})
    assert direct["authority_first_result"] == "FAIL"
    assert direct.get("tokens", {}).get("authority") is None
    assert "hard_entry_not_accepted" in direct[
        "root_of_trust_evidence_anchor"
    ]["failures"]


def test_sole_state_builder_enforcement() -> None:
    production_roots = [ROOT / "sbp_lex", ROOT / "external_substrates"]
    definitions: list[tuple[Path, str]] = []
    calls: list[Path] = []
    for source_root in production_roots:
        for path in source_root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == "build_state":
                        definitions.append((path, node.name))
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "build_state"
                ):
                    calls.append(path)
    assert definitions == [(ROOT / "sbp_lex/shared/state_builder.py", "build_state")]
    assert calls == [ROOT / "sbp_lex/pipeline/runner.py"]


def test_repeated_run_and_replay_parity_are_exact() -> None:
    first = run_dual_pipeline(_request())
    second = run_dual_pipeline(_request())
    for field in (
        "eie_hash",
        "state_construction_hash",
        "collective_attachment",
        "verified_substrate_references",
        "pipeline_initial_parity",
    ):
        assert first[field] == second[field]
    replay = run_replay_check(request=_request(), replay_count=3)
    assert replay["matched"] is True
    assert replay["mismatches"] == []
    assert all(
        run["pipeline_initial_exact_parity"] is True
        for run in replay["runs"]
    )
