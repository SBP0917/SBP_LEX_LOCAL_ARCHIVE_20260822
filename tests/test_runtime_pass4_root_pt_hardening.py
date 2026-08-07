from __future__ import annotations

from copy import deepcopy
from typing import Callable

import pytest

from main import sample_request
from sbp_lex.authority_first.root_of_trust_runner import (
    ROOT_OF_TRUST_ORDER,
    run_root_of_trust,
)
from sbp_lex.aurion15.runtime.runner import run_aurion_runtime
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.classification.engine import run_classification
from sbp_lex.collective.context_interface import prepare_pre_context_signals
from sbp_lex.config.thresholds import (
    LOW,
    MEDIUM,
    TOP,
    apply_thresholds,
    calculate_financial_factor,
    calculate_financial_tier,
)
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.execution.execution_gate import (
    evaluate_strict_execution_security,
    run_execution_gate,
)
from sbp_lex.governance.governance_runner import run_governance_pipeline
from sbp_lex.governance.grc import run_grc
from sbp_lex.governance.procedural_truth_engine import (
    validate_procedural_truth_evidence,
)
from sbp_lex.governance.procedural_truth_runner import (
    run_procedural_truth_pipeline,
)
from sbp_lex.licensing.engine import run_licensing
from sbp_lex.pipeline import dual_runner as dual_pipeline_runner
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.replay_runner import (
    run_replay_check,
    verify_replay_result,
)
from sbp_lex.pipeline.runner import (
    PreparedPipelineBoundary,
    prepare_pipeline_boundary,
    run_pipeline,
)
from sbp_lex.security.authority_boundary import validate_root_pt_eligibility
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.security.threshold_tokens import (
    required_threshold_token_names,
    verify_threshold_bundle,
)
from sbp_lex.shared.control_chain_validation import (
    validate_root_of_trust_evidence,
)
from sbp_lex.shared.convergence import build_pipeline_convergence_proof
from sbp_lex.shared.hash_chain import (
    append_hash_entry,
    rebuild_state_hash,
    verify_hash_chain,
)


def _source(index: int, **overrides: object) -> dict[str, object]:
    source = {
        "source": f"pass4_source_{index}",
        "source_id": f"pass4_source_{index}",
        "source_uri": f"fixture:/pass4/source/{index}",
        "content": f"pass4_evidence_{index}",
        "claim_id": "primary_intent_claim",
        "verified": True,
        "attested": True,
        "freshness_valid": True,
        "consistency_valid": True,
    }
    source.update(overrides)
    return source


def _request(tier: str = MEDIUM, count: int | None = None) -> dict:
    request = sample_request()
    factor = {LOW: 1, MEDIUM: 2, TOP: 3}[tier]
    required = {LOW: 2, MEDIUM: 3, TOP: 5}[tier]
    request["action"] = f"pass4_{tier.lower()}_action"
    request["safety_profile"] = {
        "human_safety": factor,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 0,
    }
    request["context"]["financial_amount"] = 0
    request["context"]["evidence"] = [
        _source(index) for index in range(count if count is not None else required)
    ]
    return request


def _root_ready_state(request: dict | None = None, signals: dict | None = None) -> dict:
    current = request or _request()
    prepared = prepare_pipeline_boundary(current, signals)
    assert isinstance(prepared, PreparedPipelineBoundary)
    return run_ap_acf_precheck(prepared.materialize())


def _resign_root_control_signals(signals: dict) -> dict:
    skg = signals["skg_context"]
    skg_payload = {
        key: deepcopy(value)
        for key, value in skg.items()
        if key not in {"skg_digest", "skg_signature"}
    }
    skg_digest = generate_digest(skg_payload)
    skg["skg_digest"] = skg_digest
    skg["skg_signature"] = sign_payload({**skg_payload, "skg_digest": skg_digest})
    signals["skg_context"] = skg
    signals["authority_link_signal"] = deepcopy(skg["authority_link_signal"])
    signals["jurisdiction_signal"] = deepcopy(skg["jurisdiction_signal"])
    signals["policy_conflict_signal"] = deepcopy(skg["policy_conflict_signal"])
    signals["precedence_signal"] = deepcopy(skg["precedence_signal"])
    signals["skg_digest"] = skg_digest

    dtn = signals["dtn_context"]
    dtn["skg_constraint_digest"] = skg_digest
    dtn_payload = {
        key: deepcopy(value)
        for key, value in dtn.items()
        if key not in {"dtn_digest", "dtn_signature"}
    }
    dtn_digest = generate_digest(dtn_payload)
    dtn["dtn_digest"] = dtn_digest
    dtn["dtn_signature"] = sign_payload({**dtn_payload, "dtn_digest": dtn_digest})
    signals["dtn_context"] = dtn
    signals["dtn_digest"] = dtn_digest

    payload = {
        key: deepcopy(value)
        for key, value in signals.items()
        if key not in {"digest", "signature"}
    }
    signals["digest"] = generate_digest(payload)
    signals["signature"] = sign_payload(payload)
    return signals


def _resign_token(token: dict) -> dict:
    signed_payload = {
        key: deepcopy(value)
        for key, value in token.items()
        if key not in {"digest", "signature", "verified"}
    }
    token["digest"] = generate_digest(signed_payload)
    token["signature"] = sign_payload(signed_payload)
    token["verified"] = True
    return token


def _root_failure_signals(request: dict, failure: str) -> dict:
    signals = prepare_pre_context_signals(request)
    authority = signals["skg_context"]["authority_link_signal"]
    truth = signals["skg_context"]["precedence_signal"]
    timestamp = signals["timestamp"]
    if failure == "invalid_authority":
        authority["legitimacy_status"] = "INVALID"
    elif failure == "invalid_attestation":
        authority["attestation_status"] = "INVALID"
    elif failure == "inconsistent_consensus":
        authority["attestation_consensus_statement_digest"] = "wrong-statement"
    elif failure == "invalid_truth_anchor":
        truth["truth_status"] = "INVALID"
    elif failure == "broken_continuity":
        truth["truth_continuity_reference"] = "wrong-predecessor"
    elif failure == "expired_authority":
        authority["authority_valid_until"] = timestamp - 1
    elif failure == "expired_attestation":
        authority["attestation_valid_until"] = timestamp - 1
    elif failure == "expired_truth":
        truth["truth_valid_until"] = timestamp - 1
    elif failure == "future_authority":
        authority["authority_valid_from"] = timestamp + 1
    elif failure == "future_attestation":
        authority["attestation_issued_at"] = timestamp + 1
    elif failure == "future_truth":
        truth["truth_issued_at"] = timestamp + 1
    elif failure == "revoked_authority":
        authority["authority_revoked"] = True
    elif failure == "revoked_attestation":
        authority["attestation_revoked"] = True
    elif failure == "revoked_truth":
        truth["truth_revoked"] = True
    else:  # pragma: no cover - test helper guard
        raise AssertionError(f"unknown Root failure control: {failure}")
    return _resign_root_control_signals(signals)


def _pt_invalid_state() -> dict:
    state = run_pipeline(_request(MEDIUM, 3))
    assert state["procedural_truth_result"] == "PASS"
    state["procedural_truth_result"] = "FAIL"
    state["procedural_truth_outcome"] = "PT_FAIL"
    state["state_hash"] = rebuild_state_hash(state)
    return state


def test_valid_root_chain_is_exact_complete_and_signed() -> None:
    state = run_pipeline(_request())
    evidence = state["root_of_trust_evidence"]
    payload = evidence["payload"]
    assert [engine.__name__.replace("run_", "") for engine in ROOT_OF_TRUST_ORDER] == [
        "anchor_validation",
        "attestation",
        "attestation_consensus",
        "truth_anchor",
        "truth_continuity",
        "truth_expiry",
        "truth_revocation",
    ]
    assert list(payload["stage_results"]) == [
        "anchor_validation",
        "attestation",
        "attestation_consensus",
        "truth_anchor",
        "truth_continuity",
        "truth_expiry",
        "truth_revocation",
    ]
    assert set(payload["stage_results"].values()) == {"PASS"}
    assert payload["stopped_stage"] is None
    assert evidence["valid"] is True
    assert validate_root_of_trust_evidence(state) == (True, [])


@pytest.mark.parametrize(
    ("failure", "stopped_stage"),
    [
        ("invalid_authority", "anchor_validation"),
        ("invalid_attestation", "attestation"),
        ("inconsistent_consensus", "attestation_consensus"),
        ("invalid_truth_anchor", "truth_anchor"),
        ("broken_continuity", "truth_continuity"),
        ("expired_authority", "truth_expiry"),
        ("expired_attestation", "truth_expiry"),
        ("expired_truth", "truth_expiry"),
        ("future_authority", "truth_expiry"),
        ("future_attestation", "truth_expiry"),
        ("future_truth", "truth_expiry"),
        ("revoked_authority", "truth_revocation"),
        ("revoked_attestation", "truth_revocation"),
        ("revoked_truth", "truth_revocation"),
    ],
)
def test_each_root_failure_isolated_before_pt(failure: str, stopped_stage: str) -> None:
    request = _request()
    state = run_pipeline(request, _root_failure_signals(request, failure))
    evidence = state["root_of_trust_evidence"]
    assert state["authority_first_result"] == "FAIL"
    assert evidence["payload"]["stopped_stage"] == stopped_stage
    assert state["procedural_truth_result"] == "UNSET"
    assert "procedural_truth" not in state.get("tokens", {})
    assert "procedural_truth" not in state["integration_stage_order"]
    assert state["classification_result"] == "UNSET"
    assert state["execution_result"] == "HALT"
    assert state["persistent_inoperability"] is True
    direct_pt = run_procedural_truth_pipeline(state)
    assert direct_pt["procedural_truth_result"] == "FAIL"
    assert "procedural_truth" not in direct_pt.get("tokens", {})
    direct_classification = run_classification(direct_pt)
    assert direct_classification["classification_result"] != "ALLOW"


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_state_hash",
        "missing_attachment",
        "attachment_replacement",
        "collective_replacement",
        "authority_substitution",
        "attestation_substitution",
        "malformed_attestation",
    ],
)
def test_root_input_mutation_fails_closed(mutation: str) -> None:
    state = _root_ready_state()
    if mutation == "wrong_state_hash":
        state["state_hash"] = "0" * 64
    elif mutation == "missing_attachment":
        state["collective_attachment"] = {}
        state["state_hash"] = rebuild_state_hash(state)
    elif mutation == "attachment_replacement":
        state["collective_attachment"]["attachment_hash"] = "1" * 64
        state["state_hash"] = rebuild_state_hash(state)
    elif mutation == "collective_replacement":
        state["collective_signals"]["digest"] = "2" * 64
        state["state_hash"] = rebuild_state_hash(state)
    elif mutation == "authority_substitution":
        state["collective_attachment"]["root_trust_material"]["authority"][
            "authority_identity"
        ] = "substituted_authority"
        state["state_hash"] = rebuild_state_hash(state)
    elif mutation == "attestation_substitution":
        state["collective_attachment"]["root_trust_material"]["attestations"][0][
            "attestation_identity"
        ] = "substituted_attestation"
        state["state_hash"] = rebuild_state_hash(state)
    else:
        state["collective_attachment"]["root_trust_material"]["attestations"] = [
            "malformed_attestation"
        ]
        state["state_hash"] = rebuild_state_hash(state)
    result = run_root_of_trust(state)
    assert result["authority_first_result"] == "FAIL"
    assert result["root_of_trust_evidence"]["payload"]["stopped_stage"] == (
        "root_input_validation"
    )
    assert "procedural_truth" not in result.get("tokens", {})


def test_wrong_request_and_eie_bindings_fail_root() -> None:
    for field in ("request_fingerprint", "eie_hash"):
        state = _root_ready_state()
        state[field] = "3" * 64
        state["state_hash"] = rebuild_state_hash(state)
        result = run_root_of_trust(state)
        assert result["authority_first_result"] == "FAIL"
        assert result["root_of_trust_evidence"]["valid"] is False


def test_truth_anchor_and_continuity_tamper_are_detected() -> None:
    state = run_pipeline(_request())
    tampered_anchor = deepcopy(state)
    tampered_anchor["root_of_trust_evidence"]["payload"]["truth_anchor_digest"] = "tampered"
    tampered_anchor["root_of_trust_evidence_anchor"] = deepcopy(
        tampered_anchor["root_of_trust_evidence"]
    )
    assert validate_root_of_trust_evidence(tampered_anchor)[0] is False

    tampered_chain = deepcopy(state)
    tampered_chain["hash_chain"][0]["previous_hash"] = "tampered"
    assert verify_hash_chain(tampered_chain) is False
    assert evaluate_strict_execution_security(tampered_chain)["valid"] is False


def test_cross_request_root_reuse_and_root_token_mutation_fail() -> None:
    state_a = run_pipeline(_request(MEDIUM, 3))
    request_b = _request(MEDIUM, 3)
    request_b["action"] = "pass4_other_request"
    state_b = run_pipeline(request_b)
    reused = deepcopy(state_b)
    reused["root_of_trust_evidence"] = deepcopy(state_a["root_of_trust_evidence"])
    reused["root_of_trust_evidence_anchor"] = deepcopy(
        state_a["root_of_trust_evidence_anchor"]
    )
    assert validate_root_of_trust_evidence(reused)[0] is False
    direct_pt = run_procedural_truth_pipeline(reused)
    assert direct_pt["procedural_truth_result"] == "FAIL"
    assert "procedural_truth" not in direct_pt.get("tokens", {})

    mutated = deepcopy(state_a)
    mutated["tokens"]["authority"]["digest"] = "tampered"
    assert validate_root_pt_eligibility(mutated)[0] is False


def test_missing_root_evidence_cannot_enter_pt_or_classification() -> None:
    rooted = run_root_of_trust(_root_ready_state())
    rooted.pop("root_of_trust_evidence", None)
    rooted.pop("root_of_trust_evidence_anchor", None)
    direct_pt = run_procedural_truth_pipeline(rooted)
    assert direct_pt["procedural_truth_result"] == "FAIL"
    assert "procedural_truth" not in direct_pt.get("tokens", {})
    assert run_classification(direct_pt)["classification_result"] != "ALLOW"


def test_post_root_evidence_substitution_cannot_enter_pt() -> None:
    rooted = run_root_of_trust(_root_ready_state())
    rooted["pt_evidence_envelope"]["source_records"][0]["content"] = "replacement"
    rooted["pt_evidence_envelope_digest"] = generate_digest(
        rooted["pt_evidence_envelope"]
    )
    rooted["state_hash"] = rebuild_state_hash(rooted)
    result = run_procedural_truth_pipeline(rooted)
    assert result["procedural_truth_result"] == "FAIL"
    assert result["procedural_truth_outcome"] == "PT_FAIL"
    assert "procedural_truth" not in result.get("tokens", {})


def test_post_root_state_hash_mutation_cannot_enter_pt() -> None:
    rooted = run_root_of_trust(_root_ready_state())
    rooted["state_hash"] = "0" * 64
    result = run_procedural_truth_pipeline(rooted)
    assert result["procedural_truth_result"] == "FAIL"
    assert result["procedural_truth_outcome"] == "PT_FAIL"
    assert (
        "root_preflight:pt_entry_state_hash_mismatch"
        in result["procedural_truth_failure_reasons"]
    )
    assert "procedural_truth" not in result.get("tokens", {})


def test_pt_evidence_and_tokens_cannot_be_grafted_across_rooted_states() -> None:
    rooted = run_root_of_trust(_root_ready_state())
    first = run_procedural_truth_pipeline(rooted)
    second_basis = append_hash_entry(
        rooted,
        stage="procedural_truth",
        payload={"substage": "pre_pt_state_transition", "result": "PASS"},
    )
    second = run_procedural_truth_pipeline(second_basis)
    assert validate_procedural_truth_evidence(first) == (True, [])
    assert validate_procedural_truth_evidence(second) == (True, [])

    grafted = deepcopy(second)
    grafted["procedural_truth_evidence"] = deepcopy(
        first["procedural_truth_evidence"]
    )
    grafted["procedural_truth_certification"] = deepcopy(
        first["procedural_truth_certification"]
    )
    for name in (*required_threshold_token_names(), "threshold_bundle", "procedural_truth"):
        grafted["tokens"][name] = deepcopy(first["tokens"][name])
    assert validate_procedural_truth_evidence(grafted)[0] is False
    assert validate_root_pt_eligibility(grafted)[0] is False


@pytest.mark.parametrize(
    ("tier", "count", "outcome"),
    [
        (LOW, 2, "PT_PASS"),
        (LOW, 1, "PT_REFINE"),
        (MEDIUM, 3, "PT_PASS"),
        (MEDIUM, 2, "PT_REFINE"),
        (TOP, 5, "PT_PASS"),
        (TOP, 4, "PT_ESCALATE"),
    ],
)
def test_locked_unique_corroboration_results(tier: str, count: int, outcome: str) -> None:
    state = run_pipeline(_request(tier, count))
    assert state["procedural_truth_outcome"] == outcome
    assert state["procedural_truth_result"] == ("PASS" if outcome == "PT_PASS" else "FAIL")


def test_duplicate_and_alias_sources_cannot_inflate_top() -> None:
    duplicate = _request(TOP, 5)
    duplicate["context"]["evidence"] = [deepcopy(_source(0)) for _ in range(5)]
    duplicate_state = run_pipeline(duplicate)
    duplicate_assessment = duplicate_state["pt_evidence_envelope"]["source_assessment"]
    assert duplicate_assessment["source_count_qualifying"] == 1
    assert duplicate_assessment["source_count_duplicates"] == 4
    assert duplicate_assessment["source_independence_result"] == "INVALID"
    assert duplicate_state["procedural_truth_outcome"] == "PT_ESCALATE"

    aliases = _request(TOP, 5)
    for index, source in enumerate(aliases["context"]["evidence"]):
        source["source"] = f"alias_{index}"
        source["source_id"] = f"alias_{index}"
        source["source_uri"] = "fixture:/same-provenance"
    alias_state = run_pipeline(aliases)
    alias_assessment = alias_state["pt_evidence_envelope"]["source_assessment"]
    assert alias_assessment["source_count_qualifying"] == 1
    assert alias_state["procedural_truth_outcome"] == "PT_ESCALATE"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("freshness_valid", False),
        ("attested", False),
        ("verified", False),
        ("consistency_valid", False),
        ("provenance_valid", False),
        ("relevance_valid", False),
        ("source_independent", False),
    ],
)
def test_invalid_evidence_dimension_does_not_count(field: str, value: object) -> None:
    request = _request(TOP, 5)
    request["context"]["evidence"][4][field] = value
    state = run_pipeline(request)
    assessment = state["pt_evidence_envelope"]["source_assessment"]
    assert assessment["source_count_qualifying"] == 4
    if field == "source_independent":
        assert assessment["source_independence_result"] == "INVALID"
    assert state["procedural_truth_outcome"] == "PT_ESCALATE"


@pytest.mark.parametrize(
    "binding_field",
    ["request_fingerprint", "eie_digest", "collective_signal_digest", "action_digest"],
)
def test_explicit_source_binding_mismatch_does_not_count(binding_field: str) -> None:
    request = _request(LOW, 2)
    request["context"]["evidence"][0][binding_field] = "mismatched-binding"
    state = run_pipeline(request)
    assessment = state["pt_evidence_envelope"]["source_assessment"]
    assert assessment["source_count_qualifying"] == 1
    assert any(
        "source_binding_mismatch" in reason
        for reason in assessment["rejection_reasons"]
    )
    assert state["procedural_truth_outcome"] == "PT_REFINE"


def test_malformed_source_is_rejected_at_hard_entry() -> None:
    request = _request(LOW, 2)
    request["context"]["evidence"][0]["source"] = ""
    denial = run_pipeline(request)
    assert denial["accepted"] is False
    assert "invalid_evidence_source:0" in denial["failures"]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("source_id", {"alias": "one"}, "invalid_evidence_source_id:0"),
        ("source_uri", ["fixture:/bad"], "invalid_evidence_source_uri:0"),
        ("source_type", ["report"], "invalid_evidence_source_type:0"),
        ("claim_id", {"claim": "primary"}, "invalid_evidence_claim_id:0"),
    ],
)
def test_malformed_source_identity_is_rejected_at_hard_entry(
    field: str, value: object, reason: str
) -> None:
    request = _request(LOW, 2)
    request["context"]["evidence"][0][field] = value
    denial = run_pipeline(request)
    assert denial["accepted"] is False
    assert reason in denial["failures"]


def test_count_sufficient_but_incomplete_evidence_is_not_certified() -> None:
    request = _request(TOP, 6)
    request["context"]["evidence"][5]["chain_of_custody_valid"] = False
    state = run_pipeline(request)
    assessment = state["pt_evidence_envelope"]["source_assessment"]
    assert assessment["source_count_qualifying"] == 5
    assert assessment["source_floor_met"] is True
    assert assessment["evidence_completeness_result"] == "FAIL"
    assert assessment["evidentiary_sufficiency_result"] == "INSUFFICIENT"
    assert state["procedural_truth_result"] == "FAIL"
    assert "threshold_bundle" not in state.get("tokens", {})
    assert all(
        name not in state.get("tokens", {})
        for name in required_threshold_token_names()
    )


def test_factor_range_and_malformed_financial_input_fail_at_entry() -> None:
    invalid_requests = []
    factor_too_high = _request()
    factor_too_high["safety_profile"]["human_safety"] = 4
    invalid_requests.append((factor_too_high, "safety_profile_human_safety_out_of_range"))
    boolean_factor = _request()
    boolean_factor["safety_profile"]["irreversibility"] = True
    invalid_requests.append((boolean_factor, "safety_profile_irreversibility_must_be_int"))
    negative_financial = _request()
    negative_financial["context"]["financial_amount"] = -1
    invalid_requests.append((negative_financial, "context_financial_amount_must_be_non_negative"))
    malformed_financial = _request()
    malformed_financial["context"]["financial_amount"] = "AUD 500"
    invalid_requests.append((malformed_financial, "context_financial_amount_must_be_finite_number"))
    huge_financial = _request()
    huge_financial["context"]["financial_amount"] = 10**500
    invalid_requests.append((huge_financial, "context_financial_amount_must_be_finite_number"))
    for request, reason in invalid_requests:
        denial = run_pipeline(request)
        assert denial["accepted"] is False
        assert reason in denial["failures"]

    direct = apply_thresholds(
        {
            "safety_profile": {
                "human_safety": 0,
                "irreversibility": 0,
                "cascading_impact": 0,
                "financial_operational": 0,
            },
            "context": {"financial_amount": 10**500},
        }
    )
    threshold_payload = direct["threshold_conditioning_state"]["payload"]
    assert threshold_payload["financial_input_status"] == "INVALID"
    assert "financial_amount_must_be_finite_number" in threshold_payload[
        "validation_failures"
    ]


def test_locked_financial_bands_and_maximum_factor_rule() -> None:
    assert calculate_financial_factor(499.99) == 1
    assert calculate_financial_factor(500.00) == 2
    assert calculate_financial_factor(49_999.99) == 2
    assert calculate_financial_factor(50_000.00) == 3
    assert calculate_financial_tier(499.99) == LOW
    assert calculate_financial_tier(500.00) == MEDIUM
    assert calculate_financial_tier(50_000.00) == TOP
    state = apply_thresholds(
        {
            "safety_profile": {
                "human_safety": 3,
                "irreversibility": 0,
                "cascading_impact": 0,
                "financial_operational": 0,
            },
            "context": {"financial_amount": 0},
        }
    )
    assert state["safety_profile"]["computed_tier"] == TOP


@pytest.mark.parametrize(
    ("start_factor", "raised_factor", "expected_transition"),
    [(1, 2, "LOW_TO_MEDIUM"), (1, 3, "LOW_TO_TOP"), (2, 3, "MEDIUM_TO_TOP")],
)
def test_dynamic_tier_escalation(
    start_factor: int, raised_factor: int, expected_transition: str
) -> None:
    state = apply_thresholds(
        {
            "safety_profile": {
                "human_safety": start_factor,
                "irreversibility": 0,
                "cascading_impact": 0,
                "financial_operational": 0,
            },
            "context": {"financial_amount": 0},
        }
    )
    state["safety_profile"]["human_safety"] = raised_factor
    escalated = apply_thresholds(state)
    payload = escalated["threshold_conditioning_state"]["payload"]
    assert payload["tier_transition"] == expected_transition
    assert payload["tier_monotonic"] is True


@pytest.mark.parametrize(
    ("previous", "lower_factor", "attempted"),
    [(MEDIUM, 1, "MEDIUM_TO_LOW"), (TOP, 2, "TOP_TO_MEDIUM"), (TOP, 1, "TOP_TO_LOW")],
)
def test_tier_downgrade_attempt_is_preserved_and_rejected(
    previous: str, lower_factor: int, attempted: str
) -> None:
    state = {
        "safety_profile": {
            "human_safety": lower_factor,
            "irreversibility": 0,
            "cascading_impact": 0,
            "financial_operational": 0,
            "computed_tier": previous,
            "financial_tier": LOW,
        },
        "context": {"financial_amount": 0},
    }
    conditioned = apply_thresholds(state)
    payload = conditioned["threshold_conditioning_state"]["payload"]
    assert conditioned["safety_profile"]["computed_tier"] == previous
    assert payload["tier_downgrade_attempted"] is True
    assert payload["tier_monotonic"] is False
    assert f"tier_downgrade_attempt:{attempted}" in payload["validation_failures"]


def test_pt_and_threshold_token_tamper_and_tier_mutation_fail() -> None:
    state = run_pipeline(_request())
    assert validate_root_pt_eligibility(state) == (True, [])
    pt_tamper = deepcopy(state)
    pt_tamper["tokens"]["procedural_truth"]["payload"]["tier"] = LOW
    assert validate_root_pt_eligibility(pt_tamper)[0] is False

    historical_hash_tamper = deepcopy(state)
    historical_token = historical_hash_tamper["tokens"]["procedural_truth"]
    historical_token["state_hash"] = "0" * 64
    _resign_token(historical_token)
    assert validate_procedural_truth_evidence(historical_hash_tamper)[0] is False

    semantic_token_tamper = deepcopy(state)
    semantic_token = semantic_token_tamper["tokens"]["procedural_truth"]
    semantic_token["issued_at_stage"] = "classification"
    semantic_token["payload"]["issuing_stage"] = "classification"
    semantic_token["payload"]["procedural_truth_result"] = "FAIL"
    semantic_token["payload"]["procedural_truth_outcome"] = "PT_FAIL"
    _resign_token(semantic_token)
    assert validate_procedural_truth_evidence(semantic_token_tamper)[0] is False

    threshold_tamper = deepcopy(state)
    threshold_tamper["tokens"]["corroboration_threshold"]["payload"]["value"] = 2
    assert verify_threshold_bundle(threshold_tamper)[0] is False

    tier_tamper = deepcopy(state)
    tier_tamper["safety_profile"]["computed_tier"] = LOW
    tier_tamper["corroboration_required"] = 2
    tier_tamper["state_hash"] = rebuild_state_hash(tier_tamper)
    assert validate_root_pt_eligibility(tier_tamper)[0] is False
    assert evaluate_strict_execution_security(tier_tamper)["valid"] is False


def test_pt_token_has_complete_pass4_bindings_and_failure_has_no_token() -> None:
    state = run_pipeline(_request())
    token = state["tokens"]["procedural_truth"]
    payload = token["payload"]
    for field in (
        "procedural_truth_result",
        "procedural_truth_outcome",
        "pt_evidence_envelope_digest",
        "eie_digest",
        "collective_signal_digest",
        "root_evidence_digest",
        "tier",
        "corroboration_required",
        "corroboration_observed",
        "pt_evidence_digest",
        "source_assessment_digest",
        "evidentiary_sufficiency_result",
        "evidentiary_sufficiency_digest",
        "human_safety",
        "irreversibility",
        "cascading_impact",
        "financial_operational",
        "threshold_state_digest",
        "threshold_bundle_digest",
        "threshold_token_digests",
        "prior_hash_chain_head",
        "issuing_stage",
        "timestamp",
        "nonce",
    ):
        assert payload[field] not in (None, "")
    assert token["issued_at_stage"] == "procedural_truth"
    assert token["verified"] is True
    pt_evidence_payload = state["procedural_truth_evidence"]["payload"]
    for field in (
        "evidentiary_sufficiency_digest",
        "human_safety",
        "irreversibility",
        "cascading_impact",
        "financial_operational",
        "prior_hash_chain_head",
    ):
        assert pt_evidence_payload[field] == payload[field]
    threshold_payload = state["threshold_conditioning_state"]["payload"]
    threshold_bindings = {
        field: threshold_payload[field]
        for field in (
            "request_fingerprint",
            "eie_digest",
            "collective_signal_digest",
            "root_evidence_digest",
            "source_assessment_digest",
            "pre_root_threshold_state_digest",
        )
    }
    assert all(value not in (None, "") for value in threshold_bindings.values())
    assert threshold_payload["threshold_binding_digest"] == generate_digest(
        threshold_bindings
    )

    failed = run_pipeline(_request(LOW, 1))
    assert "procedural_truth" not in failed.get("tokens", {})
    assert "threshold_bundle" not in failed.get("tokens", {})


@pytest.mark.parametrize(
    ("runner", "result_field", "allowed_values"),
    [
        (run_classification, "classification_result", {"DENY"}),
        (run_licensing, "licensing_result", {"DENY"}),
        (run_governance_pipeline, "governance_result", {"DENY", "ESCALATE"}),
        (run_grc, "grc_result", {"DENY", "ESCALATE"}),
        (run_domain_wrap, "domain_result", {"fail", "escalate"}),
        (run_aurion_runtime, "aurion15_result", {"fail"}),
    ],
)
def test_downstream_stage_cannot_restore_pt_invalid_state(
    runner: Callable[[dict], dict], result_field: str, allowed_values: set[str]
) -> None:
    result = runner(_pt_invalid_state())
    assert result[result_field] in allowed_values
    assert result.get("execution_result") != "EXECUTE"


def test_genuine_pt_escalation_cannot_reach_classification_allow() -> None:
    escalated = run_pipeline(_request(TOP, 4))
    assert escalated["procedural_truth_outcome"] == "PT_ESCALATE"
    assert escalated["classification_result"] == "UNSET"
    direct = run_classification(escalated)
    assert direct["classification_result"] != "ALLOW"
    assert direct.get("execution_result") != "EXECUTE"


def test_execution_gate_rejects_pt_corroboration_tier_and_token_invariants() -> None:
    valid = run_pipeline(_request())
    mutations = []
    pt_fail = deepcopy(valid)
    pt_fail["procedural_truth_result"] = "FAIL"
    mutations.append(pt_fail)
    corroboration_fail = deepcopy(valid)
    corroboration_fail["corroboration_met"] = False
    mutations.append(corroboration_fail)
    tier_inconsistent = deepcopy(valid)
    tier_inconsistent["safety_profile"]["computed_tier"] = LOW
    mutations.append(tier_inconsistent)
    missing_token = deepcopy(valid)
    del missing_token["tokens"]["procedural_truth"]
    mutations.append(missing_token)
    invalid_token = deepcopy(valid)
    invalid_token["tokens"]["procedural_truth"]["digest"] = "tampered"
    mutations.append(invalid_token)
    request_mismatch = deepcopy(valid)
    request_mismatch["request_fingerprint"] = "wrong"
    mutations.append(request_mismatch)
    eie_mismatch = deepcopy(valid)
    eie_mismatch["eie_hash"] = "wrong"
    mutations.append(eie_mismatch)
    state_hash_mismatch = deepcopy(valid)
    state_hash_mismatch["state_hash"] = "wrong"
    mutations.append(state_hash_mismatch)
    for mutation in mutations:
        result = run_execution_gate(mutation)
        assert result["execution_result"] == "HALT"
        assert result["execution_verified"] is False


def test_repeated_run_replay_and_exact_root_pt_parity() -> None:
    request = _request(TOP, 5)
    first = run_dual_pipeline(request)
    second = run_dual_pipeline(request)
    first_root = first["root_of_trust_evidence"]
    second_root = second["root_of_trust_evidence"]
    assert first_root["payload"] == second_root["payload"]
    assert first_root["root_evidence_digest"] == second_root["root_evidence_digest"]
    first_pt = first["procedural_truth_evidence"]
    second_pt = second["procedural_truth_evidence"]
    assert first_pt["payload"] == second_pt["payload"]
    assert first_pt["pt_evidence_digest"] == second_pt["pt_evidence_digest"]
    parity = first["pipeline_root_pt_parity"]
    assert parity["applicable"] is True
    assert parity["root_parity"] is True
    assert parity["pt_parity"] is True
    assert parity["tier_parity"] is True
    assert parity["corroboration_parity"] is True
    assert parity["exact_parity_result"] is True
    assert parity["near_match_reconciliation_used"] is False
    initial = first["pipeline_initial_parity"]
    for field in (
        "canonical_eie",
        "validated_substrate_references",
        "initial_canonical_state",
        "collective_signal_package",
        "state_hash_basis",
        "authority_material",
        "source_evidence_set",
        "safety_factors",
        "computed_initial_tier",
        "initial_corroboration_requirement",
    ):
        assert initial["field_matches"][field] is True
    assert initial["authority_material_digest"]
    assert initial["source_evidence_set_digest"]
    assert initial["safety_factors"] == {
        "human_safety": 3,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 0,
    }
    assert initial["computed_initial_tier"] == TOP
    assert initial["initial_corroboration_requirement"] == 5

    replay = run_replay_check(request=request, replay_count=3)
    assert replay["matched"] is True
    assert replay["mismatches"] == []
    assert verify_replay_result(replay) == (True, [])


def test_failed_root_and_pt_replay_are_exact() -> None:
    root_request = _request()
    root_replay = run_replay_check(
        request=root_request,
        pre_context_signals=_root_failure_signals(root_request, "revoked_truth"),
        replay_count=3,
    )
    assert root_replay["matched"] is True
    assert root_replay["mismatches"] == []
    assert root_replay["reference"]["authority_first_result"] == "FAIL"
    assert root_replay["reference"]["authority_first_reason"]

    pt_replay = run_replay_check(request=_request(TOP, 4), replay_count=3)
    assert pt_replay["matched"] is True
    assert pt_replay["mismatches"] == []
    assert pt_replay["reference"]["procedural_truth_result"] == "FAIL"
    assert pt_replay["reference"]["procedural_truth_outcome"] == "PT_ESCALATE"
    assert pt_replay["reference"]["procedural_truth_reason"]


def test_root_pt_convergence_mismatch_is_exact_and_fail_closed() -> None:
    state_a = run_pipeline(_request())
    state_b = deepcopy(state_a)
    state_b["procedural_truth_evidence"]["pt_evidence_digest"] = "different"
    proof = build_pipeline_convergence_proof(
        pipeline_a=state_a,
        pipeline_b=state_b,
        mode="MODE_2_SPLIT_VALIDATOR",
    )
    assert proof["matched"] is False
    assert proof["root_pt_matched"] is False
    assert "pt_evidence_digest" in proof["mismatches"]
    assert proof["near_match_reconciliation_used"] is False


def test_dual_runner_root_pt_mismatch_halts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = dual_pipeline_runner._run_admitted_pipeline
    calls = 0

    def divergent(prepared: PreparedPipelineBoundary) -> dict:
        nonlocal calls
        calls += 1
        state = original(prepared)
        if calls == 2:
            state["procedural_truth_evidence"]["pt_evidence_digest"] = "different"
        return state

    monkeypatch.setattr(
        dual_pipeline_runner, "_run_admitted_pipeline", divergent
    )
    result = dual_pipeline_runner.run_dual_pipeline(_request())
    assert result["pipeline_convergence"]["matched"] is False
    assert result["pipeline_root_pt_parity"]["exact_parity_result"] is False
    assert result["decision"] == "ESCALATE"
    assert result["execution_result"] == "HALT"
    assert result["execution_verified"] is False


def test_root_pt_hash_chain_and_audit_lineage_are_complete() -> None:
    state = run_pipeline(_request())
    assert verify_hash_chain(state)
    assert validate_procedural_truth_evidence(state) == (True, [])
    for index, entry in enumerate(state["hash_chain"]):
        expected_previous = (
            "GENESIS" if index == 0 else state["hash_chain"][index - 1]["hash"]
        )
        assert entry["previous_hash"] == expected_previous
    root_entries = [
        entry for entry in state["hash_chain"] if entry["stage"] == "root_of_trust"
    ]
    pt_entries = [
        entry for entry in state["hash_chain"] if entry["stage"] == "procedural_truth"
    ]
    assert len(root_entries) >= 8
    assert len(pt_entries) >= 5
    integration = state["audit_record"]["payload"]["integration_evidence"]
    root_lineage = integration["root_of_trust_lineage"]
    pt_lineage = integration["procedural_truth_lineage"]
    assert root_lineage["root_result"] == "PASS"
    assert root_lineage["root_evidence_digest"] == state["root_of_trust_evidence"][
        "root_evidence_digest"
    ]
    assert root_lineage["request_fingerprint"] == state["request_fingerprint"]
    assert root_lineage["eie_digest"] == state["eie_hash"]
    assert root_lineage["state_hash_entering_root"] == state[
        "root_of_trust_evidence"
    ]["payload"]["state_hash_entering_root"]
    assert root_lineage["collective_signal_digest"] == state[
        "collective_signals"
    ]["digest"]
    assert pt_lineage["procedural_truth_result"] == "PASS"
    assert pt_lineage["pt_evidence_digest"] == state["procedural_truth_evidence"][
        "pt_evidence_digest"
    ]
    assert pt_lineage["source_count_qualifying"] == 3
    assert pt_lineage["corroboration_required"] == 3
    assert pt_lineage["corroboration_observed"] == 3
    assert pt_lineage["evidentiary_sufficiency_result"] == "SUFFICIENT"
    assert pt_lineage["computed_tier"] == MEDIUM
    assert pt_lineage["request_fingerprint"] == state["request_fingerprint"]
    assert pt_lineage["eie_digest"] == state["eie_hash"]
    assert pt_lineage["state_hash"] == state["procedural_truth_evidence"][
        "payload"
    ]["state_hash"]
    assert root_entries[-1]["previous_hash"]
    assert pt_entries[-1]["previous_hash"]


def test_pt_failure_remains_inoperable_and_requires_full_retraversal() -> None:
    state = run_pipeline(_request(LOW, 1))
    assert state["execution_result"] == "HALT"
    assert state["execution_verified"] is False
    assert state["persistent_inoperability"] is True
    assert state["governed_reentry"]["reentry_permitted"] is False
    assert state["governed_reentry"]["required_action"] == (
        "full_retraversal_after_correction"
    )
