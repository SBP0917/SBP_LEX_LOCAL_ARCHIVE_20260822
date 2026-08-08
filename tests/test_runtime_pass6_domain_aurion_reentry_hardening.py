from __future__ import annotations

from copy import deepcopy
import inspect
from typing import Any, Callable

import pytest

from external_substrates.shared.canonical_json import canonical_dumps
from main import main, sample_request
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.aurion15 import candidate_resolution
from sbp_lex.aurion15.candidate.generator import generate_candidates
from sbp_lex.aurion15.runtime import runner as aurion_runner
from sbp_lex.aurion15.runtime.constraint_validator import (
    validate_candidate_constraints,
)
from sbp_lex.aurion15.runtime.runner import run_aurion_runtime
from sbp_lex.aurion15 import runtime_constraint_engine
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.classification.engine import run_classification
from sbp_lex.domains import runner as domain_runner
from sbp_lex.domains.base_domain import (
    DOMAIN_PASS,
    DOMAIN_REQUIRE_NEXT_CANDIDATE,
    make_domain_result,
)
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.governance.governance_runner import run_governance_pipeline
from sbp_lex.governance.procedural_truth_runner import (
    run_procedural_truth_pipeline,
)
from sbp_lex.licensing.engine import run_licensing
from sbp_lex.pipeline.replay_runner import (
    REPLAY_COMPARISON_FIELDS,
    build_replay_summary,
    run_replay_check,
)
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.runner import (
    PreparedPipelineBoundary,
    _mark_stage,
    prepare_pipeline_boundary,
    run_pipeline,
)
from sbp_lex.runtime.measured_startup import reset_measured_startup_for_tests
from sbp_lex.security.authority_boundary import (
    validate_canonical_upstream,
    validate_domain_handoff_to_aurion,
    validate_execution_convergence_handoff,
)
from sbp_lex.security.domain_admissibility import (
    build_domain_admissibility,
    evaluate_domain,
    verify_domain,
)
from sbp_lex.security.domain_aurion_evidence import (
    build_execution_convergence_handoff,
    constraint_snapshot,
    domain_effective_scope,
    validate_handoff_evidence,
    validate_stage_evidence,
)
from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.convergence import build_pipeline_convergence_proof
from sbp_lex.shared.hash_chain import append_hash_entry, rebuild_state_hash


def _governed_state(request: dict[str, Any] | None = None) -> dict[str, Any]:
    prepared = prepare_pipeline_boundary(request or sample_request())
    assert isinstance(prepared, PreparedPipelineBoundary)
    state = run_ap_acf_precheck(prepared.materialize())
    state = _mark_stage(state, "ap_acf_precheck")
    state = run_root_of_trust(state)
    state = _mark_stage(state, "root_of_trust")
    state = run_procedural_truth_pipeline(state)
    state = _mark_stage(state, "procedural_truth")
    state = run_classification(state)
    state = _mark_stage(state, "classification")
    state = run_licensing(state)
    state = _mark_stage(state, "licensing")
    state = run_governance_pipeline(state)
    state = _mark_stage(state, "governance")
    return _mark_stage(state, "grc")


def _domain_state(request: dict[str, Any] | None = None) -> dict[str, Any]:
    state = domain_runner.run_domain_wrap(_governed_state(request))
    assert state["domain_result"] == "pass"
    assert "domain" in state["tokens"]
    return _mark_stage(state, "domain_wrap")


def _aurion_handoff_state(
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = run_aurion_runtime(_domain_state(request))
    assert state["aurion15_result"] == "pass"
    assert "aurion" in state["tokens"]
    state = _mark_stage(state, "aurion_runtime")
    state["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(state)
    )
    state["state_hash"] = rebuild_state_hash(state)
    return state


def _candidate_failures(state: dict[str, Any]) -> set[str]:
    feedback = state.get("governance_feedback", {}).get("aurion", {})
    failures = set(str(item) for item in feedback.get("failures", []))
    for field in ("candidate_validations", "ranked_candidate_validations"):
        for validation in feedback.get(field, []):
            failures.update(
                str(item) for item in validation.get("failures", [])
            )
    for candidate in feedback.get("rejected_candidates", []):
        failures.update(str(item) for item in candidate.get("rejection_reasons", []))
    return failures


def _install_candidate_generator(
    monkeypatch: pytest.MonkeyPatch,
    generator: Callable[[dict[str, Any]], list[object]],
) -> None:
    monkeypatch.setattr(aurion_runner, "generate_candidates", generator)
    monkeypatch.setattr(
        aurion_runner, "CANONICAL_CANDIDATE_GENERATOR", generator
    )


def _controlled_denial_proof(denied: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "controlled_denial_proof",
        "content": canonical_dumps(denied["controlled_outcome"]),
        "verified": True,
        "attested": True,
        "freshness_valid": True,
        "consistency_valid": True,
    }


def _install_domain_rules(
    monkeypatch: pytest.MonkeyPatch,
    rules: list[object],
    required_order: tuple[str, ...] | None = None,
) -> None:
    monkeypatch.setattr(domain_runner, "DOMAIN_ENGINES", rules)
    monkeypatch.setattr(
        domain_runner,
        "REQUIRED_DOMAIN_ENGINE_ORDER",
        required_order
        if required_order is not None
        else tuple(str(getattr(rule, "name", "")) for rule in rules),
    )
    monkeypatch.setattr(
        domain_runner,
        "REQUIRED_DOMAIN_ENGINE_TYPES",
        tuple(type(rule) for rule in rules),
    )


class _RawDomainRule:
    def __init__(
        self,
        name: str,
        raw_result: object = None,
        *,
        raises: bool = False,
    ) -> None:
        self.name = name
        self.raw_result = raw_result
        self.raises = raises

    def evaluate(self, state: dict[str, Any]) -> object:
        del state
        if self.raises:
            raise RuntimeError("synthetic_domain_failure")
        return deepcopy(self.raw_result)


class _PassOnSecondCandidate:
    name = "effective_scope_domain"

    def evaluate(self, state: dict[str, Any]) -> dict[str, Any]:
        attempt = state["current_candidate"]["attempt"]
        result = DOMAIN_PASS if attempt == 2 else DOMAIN_REQUIRE_NEXT_CANDIDATE
        return make_domain_result(
            domain=self.name,
            result=result,
            reason=f"attempt_{attempt}",
            evidence={
                "effective_scope": state["classification"]["operational_scope"]
            },
        )


class _ExplodingNameDomain:
    @property
    def name(self) -> str:
        raise RuntimeError("synthetic_domain_name_failure")


class _ForgedPassDomain:
    def __init__(self, name: str) -> None:
        self.name = name

    def evaluate(self, state: dict[str, Any]) -> dict[str, Any]:
        del state
        return make_domain_result(
            domain=self.name,
            result=DOMAIN_PASS,
            reason="forged_same_name_domain_pass",
            evidence={"forged": True},
        )


def test_valid_domain_aurion_evidence_tokens_and_handoff_are_exactly_bound() -> None:
    domain = _domain_state()
    domain_valid, domain_failures = validate_stage_evidence(domain, "domain")
    assert domain_valid, domain_failures
    upstream_valid, upstream_failures = validate_canonical_upstream(
        domain,
        required_tokens=(
            "authority",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
            "domain",
        ),
    )
    assert upstream_valid, upstream_failures
    handoff_valid, handoff_failures = validate_domain_handoff_to_aurion(domain)
    assert handoff_valid, handoff_failures

    aurion = _aurion_handoff_state()
    aurion_valid, aurion_failures = validate_stage_evidence(aurion, "aurion")
    assert aurion_valid, aurion_failures
    record_valid, record_failures = validate_handoff_evidence(aurion)
    assert record_valid, record_failures
    convergence_valid, convergence_failures = (
        validate_execution_convergence_handoff(aurion)
    )
    assert convergence_valid, convergence_failures
    feedback = aurion["governance_feedback"]["aurion"]
    assert feedback["admissible_candidate_set_digest"] == generate_digest(
        feedback["admissible_candidates"]
    )
    assert feedback["ordered_candidate_set_digest"] == generate_digest(
        feedback["ranked_candidates"]
    )
    assert feedback["admissible_candidates"] != feedback["ranked_candidates"]
    assert len(feedback["candidate_validations"]) == len(
        feedback["generated_candidates"]
    )
    assert len(feedback["ranked_candidate_validations"]) == len(
        feedback["ranked_candidates"]
    )


@pytest.mark.parametrize(
    ("field", "container"),
    [
        ("grc_evidence", None),
        ("grc", "tokens"),
    ],
)
def test_domain_rejects_missing_grc_evidence_or_token(
    field: str,
    container: str | None,
) -> None:
    state = _governed_state()
    if container is None:
        state.pop(field)
    else:
        state[container].pop(field)
    state["state_hash"] = rebuild_state_hash(state)

    result = domain_runner.run_domain_wrap(state)

    assert result["domain_result"] != "pass"
    assert result["execution_result"] == "HALT"
    assert result["governance_feedback"]["domain_wrap"]["attempts"] == []
    assert "domain" not in result["tokens"]


@pytest.mark.parametrize(
    ("field", "container"),
    [
        ("domain_evidence", None),
        ("domain", "tokens"),
    ],
)
def test_aurion_rejects_missing_domain_evidence_or_token(
    field: str,
    container: str | None,
) -> None:
    state = _domain_state()
    if container is None:
        state.pop(field)
    else:
        state[container].pop(field)
    state["state_hash"] = rebuild_state_hash(state)

    result = run_aurion_runtime(state)

    assert result["aurion15_result"] == "fail"
    assert result["execution_result"] == "HALT"
    assert "aurion" not in result["tokens"]


def test_empty_domain_rule_set_never_produces_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_domain_rules(monkeypatch, [])

    result = domain_runner.run_domain_wrap(_governed_state())

    assert result["domain_result"] != "pass"
    assert result["execution_result"] == "HALT"
    assert "domain" not in result["tokens"]


def test_missing_or_duplicate_domain_rules_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = make_domain_result(
        domain="only_rule",
        result=DOMAIN_PASS,
        reason="synthetic_pass",
    )
    _install_domain_rules(
        monkeypatch,
        [_RawDomainRule("only_rule", valid)],
        required_order=("only_rule", "missing_rule"),
    )
    missing = domain_runner.run_domain_wrap(_governed_state())
    assert missing["domain_result"] != "pass"
    assert "domain_rule_set_missing_or_reordered" in missing[
        "governance_feedback"
    ]["domain_wrap"]["failures"]

    duplicate_result = make_domain_result(
        domain="duplicate_rule",
        result=DOMAIN_PASS,
        reason="synthetic_pass",
    )
    duplicate_rules = [
        _RawDomainRule("duplicate_rule", duplicate_result),
        _RawDomainRule("duplicate_rule", duplicate_result),
    ]
    _install_domain_rules(monkeypatch, duplicate_rules)
    duplicate = domain_runner.run_domain_wrap(_governed_state())
    assert duplicate["domain_result"] != "pass"
    assert "duplicate_domain_rule" in duplicate["governance_feedback"][
        "domain_wrap"
    ]["failures"]
    assert "domain" not in duplicate["tokens"]


@pytest.mark.parametrize(
    ("rule", "expected_failure"),
    [
        (_RawDomainRule("not_mapping", "PASS"), "domain_rule_result_invalid:not_mapping"),
        (
            _RawDomainRule("malformed", {"domain": "malformed", "result": "pass"}),
            "domain_rule_result_schema_invalid:malformed",
        ),
        (
            _RawDomainRule("exception", raises=True),
            "domain_rule_exception:exception",
        ),
    ],
)
def test_malformed_or_exceptional_domain_rules_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    rule: _RawDomainRule,
    expected_failure: str,
) -> None:
    _install_domain_rules(monkeypatch, [rule])

    result = domain_runner.run_domain_wrap(_governed_state())

    assert result["domain_result"] != "pass"
    assert result["execution_result"] == "HALT"
    assert expected_failure in result["governance_feedback"]["domain_wrap"][
        "failures"
    ]
    assert "domain" not in result["tokens"]


def test_domain_fallback_preserves_original_and_binds_effective_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule = _PassOnSecondCandidate()
    _install_domain_rules(monkeypatch, [rule])

    result = domain_runner.run_domain_wrap(_governed_state())

    assert result["domain_result"] == "pass"
    assert result["classification"]["operational_scope"] == "controlled_test"
    assert result["context"]["operational_scope"] == "controlled_test"
    assert domain_effective_scope(result) == "controlled_test:bounded:1"
    assert constraint_snapshot(result)["domain_operational_scope"] == (
        "controlled_test:bounded:1"
    )
    assert result["domain_candidate"]["context_adjustments"][
        "operational_scope"
    ] == "controlled_test:bounded:1"
    token_snapshot = result["tokens"]["domain"]["payload"][
        "constraint_snapshot"
    ]
    assert token_snapshot["classification_operational_scope"] == "controlled_test"
    assert token_snapshot["domain_operational_scope"] == (
        "controlled_test:bounded:1"
    )


@pytest.mark.parametrize(
    ("case", "expected_failure"),
    [
        ("empty", "aurion_candidate_set_missing"),
        ("non_mapping", "aurion_candidate_not_mapping:1"),
        ("malformed", "candidate_schema_invalid"),
        ("duplicate", "aurion_candidate_id_duplicate"),
    ],
)
def test_empty_malformed_or_duplicate_candidate_sets_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_failure: str,
) -> None:
    state = _domain_state()
    valid_candidate = generate_candidates(state)[0]
    candidate_sets: dict[str, list[object]] = {
        "empty": [],
        "non_mapping": ["candidate"],
        "malformed": [{"candidate_id": "partial"}],
        "duplicate": [deepcopy(valid_candidate), deepcopy(valid_candidate)],
    }
    _install_candidate_generator(
        monkeypatch,
        lambda _: deepcopy(candidate_sets[case]),
    )

    result = run_aurion_runtime(state)

    assert result["aurion15_result"] == "fail"
    assert result["execution_result"] == "HALT"
    assert expected_failure in _candidate_failures(result)
    assert "aurion" not in result["tokens"]


def test_schema_valid_forged_candidate_set_cannot_replace_canonical_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _domain_state()
    forged_set = generate_candidates(state)
    forged_set[0]["candidate_id"] = "forged_but_well_formed"
    monkeypatch.setattr(
        aurion_runner,
        "generate_candidates",
        lambda _: deepcopy(forged_set),
    )

    result = run_aurion_runtime(state)

    assert result["aurion15_result"] == "fail"
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert "aurion_generated_candidate_set_mismatch" in _candidate_failures(
        result
    )
    assert "aurion" not in result["tokens"]


def test_ranker_cannot_mutate_validated_candidate_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mutating_ranker(
        state: dict[str, Any], candidates: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        del state
        ranked = deepcopy(candidates)
        ranked[0]["pathway"]["resolved_authority"] = (
            "attacker_expanded_authority"
        )
        return ranked

    monkeypatch.setattr(aurion_runner, "rank_candidates", mutating_ranker)

    result = run_aurion_runtime(_domain_state())

    assert result["aurion15_result"] == "fail"
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert "aurion_ranked_candidate_output_mismatch" in _candidate_failures(
        result
    )
    assert "candidate_resolved_authority_mismatch" in _candidate_failures(
        result
    )
    assert "aurion" not in result["tokens"]


def test_malformed_candidate_validator_record_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        aurion_runner,
        "validate_candidate_constraints",
        lambda state, candidate: None,
    )

    result = run_aurion_runtime(_domain_state())

    assert result["aurion15_result"] == "fail"
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert "generated_candidate_validation_record_invalid" in (
        _candidate_failures(result)
    )
    assert "aurion" not in result["tokens"]


@pytest.mark.parametrize(
    ("case", "expected_fragment"),
    [
        ("nan_autonomy", "autonomy"),
        ("infinite_autonomy", "autonomy"),
        ("infinite_rank", "rank_score"),
        ("boolean_autonomy", "autonomy"),
    ],
)
def test_nonfinite_and_boolean_candidate_values_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_fragment: str,
) -> None:
    state = _domain_state()
    candidate = deepcopy(generate_candidates(state)[0])
    if case == "nan_autonomy":
        candidate["pathway"]["autonomy_required"] = float("nan")
    elif case == "infinite_autonomy":
        candidate["pathway"]["autonomy_required"] = float("inf")
    elif case == "infinite_rank":
        candidate["rank_score"] = float("inf")
    else:
        candidate["pathway"]["autonomy_required"] = True
    _install_candidate_generator(
        monkeypatch,
        lambda _: [deepcopy(candidate)],
    )

    result = run_aurion_runtime(state)

    assert result["aurion15_result"] == "fail"
    assert result["execution_result"] == "HALT"
    failures = _candidate_failures(result)
    assert any(
        expected_fragment in failure
        or "nonfinite" in failure
        or "not_canonical" in failure
        for failure in failures
    ), failures
    assert "aurion" not in result["tokens"]


def test_cross_request_candidate_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _domain_state()
    other_request = sample_request()
    other_request["action"] = "cross_request_action"
    cross_request_candidate = generate_candidates(_domain_state(other_request))[0]
    _install_candidate_generator(
        monkeypatch,
        lambda _: [deepcopy(cross_request_candidate)],
    )

    result = run_aurion_runtime(state)

    failures = _candidate_failures(result)
    assert result["aurion15_result"] == "fail"
    assert "candidate_action_mismatch" in failures
    assert "candidate_state_binding_mismatch" in failures
    assert "aurion" not in result["tokens"]


CandidateMutation = Callable[[dict[str, Any]], None]


def _mutate_binding(candidate: dict[str, Any]) -> None:
    candidate["bindings"]["state_hash_entering_aurion"] = "0" * 64


def _mutate_scope(candidate: dict[str, Any]) -> None:
    candidate["pathway"]["operational_scope"] = "attacker_broadened_scope"


def _mutate_tier(candidate: dict[str, Any]) -> None:
    candidate["pathway"]["consequence_tier"] = "LOW"


def _mutate_autonomy(candidate: dict[str, Any]) -> None:
    candidate["pathway"]["autonomy_required"] = 100


def _mutate_authority(candidate: dict[str, Any]) -> None:
    candidate["pathway"]["resolved_authority"] = "attacker_authority"


@pytest.mark.parametrize(
    ("mutation", "expected_failure"),
    [
        (_mutate_binding, "candidate_state_binding_mismatch"),
        (_mutate_scope, "candidate_operational_scope_mismatch"),
        (_mutate_tier, "candidate_consequence_tier_mismatch"),
        (_mutate_autonomy, "candidate_autonomy_exceeds_ceiling"),
        (_mutate_authority, "candidate_resolved_authority_mismatch"),
    ],
)
def test_candidate_binding_scope_tier_autonomy_and_authority_mutations_reject(
    monkeypatch: pytest.MonkeyPatch,
    mutation: CandidateMutation,
    expected_failure: str,
) -> None:
    state = _domain_state()
    candidate = deepcopy(generate_candidates(state)[0])
    mutation(candidate)
    direct_validation = validate_candidate_constraints(state, candidate)
    assert direct_validation["valid"] is False
    assert expected_failure in direct_validation["failures"]
    _install_candidate_generator(
        monkeypatch,
        lambda _: [deepcopy(candidate)],
    )

    result = run_aurion_runtime(state)

    assert result["aurion15_result"] == "fail"
    assert expected_failure in _candidate_failures(result)
    assert "aurion" not in result["tokens"]


def test_repeated_domain_and_aurion_entry_cannot_reuse_prior_permission() -> None:
    domain = _domain_state()
    repeated_domain = domain_runner.run_domain_wrap(domain)
    assert repeated_domain["domain_result"] != "pass"
    assert repeated_domain["domain_reason"] == "domain_reentry_rejected"
    assert repeated_domain["execution_result"] == "HALT"
    assert "domain" not in repeated_domain["tokens"]
    assert "aurion" not in repeated_domain["tokens"]

    aurion = run_aurion_runtime(_domain_state())
    aurion = _mark_stage(aurion, "aurion_runtime")
    repeated_aurion = run_aurion_runtime(aurion)
    assert repeated_aurion["aurion15_result"] == "fail"
    assert repeated_aurion["aurion_reason"] == "aurion_reentry_rejected"
    assert repeated_aurion["execution_result"] == "HALT"
    assert "aurion" not in repeated_aurion["tokens"]


def test_controlled_reentry_requires_signed_prior_denial_lineage() -> None:
    denied_request = sample_request()
    denied_request["payload"]["classification"]["autonomy_level"] = 100
    denied = run_pipeline(denied_request)

    no_proof_request = sample_request()
    no_proof_request["context"].update(
        {
            "prior_denied_fingerprint": denied["request_fingerprint"],
            "material_change_declared": True,
            "material_change_reason": "autonomy returned within ceiling",
        }
    )
    no_proof = run_pipeline(no_proof_request)

    assert no_proof["domain_result"] != "pass"
    assert "controlled_reentry_prior_denial_proof_missing" in no_proof[
        "governance_feedback"
    ]["domain_wrap"]["failures"]
    assert no_proof["decision"] == "DENY"

    valid_request = sample_request()
    valid_request["context"].update(
        {
            "prior_denied_fingerprint": denied["request_fingerprint"],
            "material_change_declared": True,
            "material_change_reason": "autonomy returned within ceiling",
        }
    )
    valid_request["context"]["evidence"].append(
        _controlled_denial_proof(denied)
    )
    for public_entry in (
        prepare_pipeline_boundary,
        run_pipeline,
        run_dual_pipeline,
    ):
        assert "controlled_reentry_registry" not in inspect.signature(
            public_entry
        ).parameters
    with pytest.raises(TypeError):
        run_pipeline(
            valid_request,
            **{"controlled_reentry_registry": object()},
        )
    valid = run_pipeline(valid_request)

    assert valid["domain_result"] == "pass"
    assert valid["aurion15_result"] == "pass"
    assert valid["governed_reentry"]["reentry_permitted"] is True
    assert valid["governed_reentry"]["reentry_completed"] is True
    assert valid["execution_result"] == "EXECUTE"
    assert valid["controlled_reentry_proof_use"]["status"] == "ACCEPTED"

    replayed_request = sample_request()
    replayed_request["action"] = "distinct_corrected_action"
    replayed_request["context"].update(
        {
            "prior_denied_fingerprint": denied["request_fingerprint"],
            "material_change_declared": True,
            "material_change_reason": "distinct corrected action",
        }
    )
    replayed_request["context"]["evidence"].append(
        _controlled_denial_proof(denied)
    )
    replayed = run_pipeline(replayed_request)

    assert replayed["domain_result"] != "pass"
    assert replayed["controlled_reentry_proof_use"]["status"] == "REPLAYED"
    assert "controlled_reentry_prior_denial_proof_replayed" in replayed[
        "governance_feedback"
    ]["domain_wrap"]["failures"]
    assert replayed["decision"] == "DENY"
    assert replayed["execution_result"] == "HALT"

    mismatched_request = sample_request()
    mismatched_request["context"].update(
        {
            "prior_denied_fingerprint": "f" * 64,
            "material_change_declared": True,
            "material_change_reason": "claimed unrelated correction",
        }
    )
    mismatched_request["context"]["evidence"].append(
        _controlled_denial_proof(denied)
    )
    mismatched = run_pipeline(mismatched_request)

    assert mismatched["domain_result"] != "pass"
    assert "controlled_reentry_prior_denial_proof_invalid" in mismatched[
        "governance_feedback"
    ]["domain_wrap"]["failures"]
    assert mismatched["decision"] == "DENY"


def test_fresh_reentry_replay_clones_one_consumed_prepared_boundary() -> None:
    denied_request = sample_request()
    denied_request["action"] = "replay_origin_action"
    denied_request["payload"]["classification"]["autonomy_level"] = 100
    denied = run_pipeline(denied_request)

    corrected = sample_request()
    corrected["action"] = "replay_corrected_action"
    corrected["context"].update(
        {
            "prior_denied_fingerprint": denied["request_fingerprint"],
            "material_change_declared": True,
            "material_change_reason": "bounded replay correction",
        }
    )
    corrected["context"]["evidence"].append(
        _controlled_denial_proof(denied)
    )

    replay = run_replay_check(request=corrected, replay_count=2)

    assert replay["matched"] is True
    assert replay["mismatches"] == []
    assert replay["reference"]["domain_result"] == "pass"
    assert replay["reference"]["aurion15_result"] == "pass"
    assert replay["reference"]["execution_result"] == "EXECUTE"

    distinct_live_use = deepcopy(corrected)
    distinct_live_use["action"] = "second_live_correction"
    rejected = run_pipeline(distinct_live_use)

    assert rejected["controlled_reentry_proof_use"]["status"] == "REPLAYED"
    assert rejected["domain_result"] != "pass"
    assert rejected["decision"] == "DENY"
    assert rejected["execution_result"] == "HALT"
    assert "controlled_reentry_prior_denial_proof_replayed" in rejected[
        "governance_feedback"
    ]["domain_wrap"]["failures"]


def test_noncanonical_domain_results_and_rule_metadata_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    noncanonical = _RawDomainRule(
        "legal_domain",
        {
            "domain": "legal_domain",
            "result": DOMAIN_PASS,
            "reason": "synthetic_noncanonical_evidence",
            "failures": [],
            "evidence": {"unsupported": object()},
        },
    )
    _install_domain_rules(
        monkeypatch, [noncanonical], required_order=("legal_domain",)
    )

    invalid_result = domain_runner.run_domain_wrap(_governed_state())

    assert invalid_result["domain_result"] != "pass"
    assert invalid_result["decision"] == "DENY"
    assert invalid_result["execution_result"] == "HALT"
    assert "domain_rule_result_not_canonical:legal_domain" in (
        invalid_result["governance_feedback"]["domain_wrap"]["failures"]
    )
    assert "domain" not in invalid_result["tokens"]

    _install_domain_rules(
        monkeypatch, [_ExplodingNameDomain()], required_order=()
    )
    unreadable_name_result = domain_runner.run_domain_wrap(_governed_state())

    assert unreadable_name_result["domain_result"] != "pass"
    assert unreadable_name_result["decision"] == "DENY"
    assert unreadable_name_result["execution_result"] == "HALT"
    assert any(
        failure.startswith("domain_rule_name_unreadable:")
        for failure in unreadable_name_result["governance_feedback"][
            "domain_wrap"
        ]["failures"]
    )
    assert "domain" not in unreadable_name_result["tokens"]


def test_same_name_domain_implementation_substitution_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        domain_runner,
        "DOMAIN_ENGINES",
        [
            _ForgedPassDomain(name)
            for name in domain_runner.REQUIRED_DOMAIN_ENGINE_ORDER
        ],
    )

    result = domain_runner.run_domain_wrap(_governed_state())

    assert result["domain_result"] != "pass"
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert "domain_rule_implementation_mismatch" in result[
        "governance_feedback"
    ]["domain_wrap"]["failures"]
    assert "domain" not in result["tokens"]


@pytest.mark.parametrize(
    "invalid_state",
    [
        {"unsupported": object()},
        {"nonfinite": float("nan")},
    ],
)
def test_public_domain_and_aurion_boundaries_deny_noncanonical_state(
    invalid_state: dict[str, Any],
) -> None:
    domain = domain_runner.run_domain_wrap(invalid_state)
    assert domain["domain_result"] != "pass"
    assert domain["decision"] == "DENY"
    assert domain["execution_result"] == "HALT"
    assert domain["governance_feedback"]["domain_wrap"]["failures"] == [
        "domain_input_not_canonical"
    ]
    assert domain["tokens"] == {}

    aurion = run_aurion_runtime(invalid_state)
    assert aurion["aurion15_result"] == "fail"
    assert aurion["decision"] == "DENY"
    assert aurion["execution_result"] == "HALT"
    assert aurion["governance_feedback"]["aurion"]["failures"] == [
        "aurion_input_not_canonical"
    ]
    assert aurion["tokens"] == {}


def test_canonical_wrong_container_types_fail_closed_at_all_pass6_boundaries() -> None:
    governed_base = _governed_state()
    domain_base = _domain_state()
    handoff_base = _aurion_handoff_state()

    for field in ("safety_profile", "collective_signals", "hard_entry_gate"):
        governed = deepcopy(governed_base)
        governed[field] = []
        governed["state_hash"] = rebuild_state_hash(governed)
        upstream_valid, upstream_failures = validate_canonical_upstream(
            governed,
            required_tokens=(
                "authority",
                "procedural_truth",
                "classification",
                "licensing",
                "governance",
                "grc",
            ),
        )
        assert upstream_valid is False
        assert upstream_failures

        domain = domain_runner.run_domain_wrap(governed)
        assert domain["domain_result"] != "pass"
        assert domain["decision"] == "DENY"
        assert domain["execution_result"] == "HALT"
        assert domain["operational_state"] == "UNSET"
        assert domain["token_stack_valid"] is False
        assert domain["execution_reason"] == ""

        domain_input = deepcopy(domain_base)
        domain_input[field] = []
        domain_input["state_hash"] = rebuild_state_hash(domain_input)
        aurion = run_aurion_runtime(domain_input)
        assert aurion["aurion15_result"] == "fail"
        assert aurion["decision"] == "DENY"
        assert aurion["execution_result"] == "HALT"
        assert aurion["operational_state"] == "UNSET"
        assert aurion["token_stack_valid"] is False
        assert aurion["execution_reason"] == ""

        handoff = deepcopy(handoff_base)
        handoff[field] = []
        handoff["state_hash"] = rebuild_state_hash(handoff)
        handoff["execution_convergence_handoff"] = (
            build_execution_convergence_handoff(handoff)
        )
        handoff["state_hash"] = rebuild_state_hash(handoff)
        handoff_valid, handoff_failures = (
            validate_execution_convergence_handoff(handoff)
        )
        assert handoff_valid is False
        assert handoff_failures


@pytest.mark.parametrize("malformed_trace", [{}, "malformed", None])
def test_malformed_audit_trace_is_a_controlled_pass6_denial(
    malformed_trace: object,
) -> None:
    governed = _governed_state()
    governed["audit_trace"] = malformed_trace
    governed["state_hash"] = rebuild_state_hash(governed)

    domain = domain_runner.run_domain_wrap(governed)

    assert domain["domain_result"] != "pass"
    assert domain["decision"] == "DENY"
    assert domain["execution_result"] == "HALT"
    assert isinstance(domain["audit_trace"], list)
    assert "domain_audit_trace_invalid" in domain["governance_feedback"][
        "domain_wrap"
    ]["failures"]

    domain_input = _domain_state()
    domain_input["audit_trace"] = malformed_trace
    domain_input["state_hash"] = rebuild_state_hash(domain_input)

    aurion = run_aurion_runtime(domain_input)

    assert aurion["aurion15_result"] == "fail"
    assert aurion["decision"] == "DENY"
    assert aurion["execution_result"] == "HALT"
    assert isinstance(aurion["audit_trace"], list)
    assert "aurion_audit_trace_invalid" in aurion["governance_feedback"][
        "aurion"
    ]["failures"]


def test_pre_gate_execution_authority_substitution_is_rejected() -> None:
    governed = _governed_state()
    governed["decision"] = "ALLOW"
    governed["execution_result"] = "EXECUTE"
    governed["operational_state"] = "OPERABLE"
    governed["governed_reentry"]["reentry_completed"] = True
    governed["state_hash"] = rebuild_state_hash(governed)

    domain = domain_runner.run_domain_wrap(governed)
    domain_failures = domain["governance_feedback"]["domain_wrap"]["failures"]
    assert domain["domain_result"] != "pass"
    assert domain["decision"] == "DENY"
    assert domain["execution_result"] == "HALT"
    assert "domain_handoff_pre_execution_decision_invalid" in domain_failures
    assert "domain_handoff_pre_execution_result_invalid" in domain_failures
    assert (
        "domain_handoff_pre_execution_operational_state_invalid"
        in domain_failures
    )
    assert "domain_handoff_pre_execution_reentry_completed" in domain_failures

    domain_state = _domain_state()
    domain_state["decision"] = "ALLOW"
    domain_state["execution_result"] = "EXECUTE"
    domain_state["operational_state"] = "OPERABLE"
    domain_state["governed_reentry"]["reentry_completed"] = True
    domain_state["state_hash"] = rebuild_state_hash(domain_state)

    aurion = run_aurion_runtime(domain_state)
    aurion_failures = aurion["governance_feedback"]["aurion"]["failures"]
    assert aurion["aurion15_result"] == "fail"
    assert aurion["decision"] == "DENY"
    assert aurion["execution_result"] == "HALT"
    assert "aurion_entry_pre_execution_decision_invalid" in aurion_failures
    assert "aurion_entry_pre_execution_result_invalid" in aurion_failures
    assert (
        "aurion_entry_pre_execution_operational_state_invalid"
        in aurion_failures
    )
    assert "aurion_entry_pre_execution_reentry_completed" in aurion_failures

    handoff = run_aurion_runtime(_domain_state())
    handoff = _mark_stage(handoff, "aurion_runtime")
    handoff["decision"] = "ALLOW"
    handoff["execution_result"] = "EXECUTE"
    handoff["operational_state"] = "OPERABLE"
    handoff["governed_reentry"]["reentry_completed"] = True
    handoff["state_hash"] = rebuild_state_hash(handoff)
    handoff["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(handoff)
    )
    handoff["state_hash"] = rebuild_state_hash(handoff)

    handoff_valid, handoff_failures = validate_execution_convergence_handoff(
        handoff
    )
    assert handoff_valid is False
    assert (
        "execution_convergence_handoff_pre_execution_decision_invalid"
        in handoff_failures
    )
    assert (
        "execution_convergence_handoff_pre_execution_result_invalid"
        in handoff_failures
    )
    assert (
        "execution_convergence_handoff_pre_execution_operational_state_invalid"
        in handoff_failures
    )
    assert (
        "execution_convergence_handoff_pre_execution_reentry_completed"
        in handoff_failures
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("token_stack_valid", True),
        ("execution_timestamp", "EXECUTION_EVENT_FORGED"),
        ("execution_reason", "forged_execute"),
        ("token_verification_failures", ["forged_clean_stack"]),
    ],
)
def test_handoff_rejects_premature_terminal_control_fields(
    field: str, value: object
) -> None:
    state = run_aurion_runtime(_domain_state())
    state = _mark_stage(state, "aurion_runtime")
    state[field] = value
    state["state_hash"] = rebuild_state_hash(state)
    state["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(state)
    )
    state["state_hash"] = rebuild_state_hash(state)

    valid, failures = validate_execution_convergence_handoff(state)

    assert valid is False
    assert any(field in failure for failure in failures), failures


def test_pass6_handoff_requires_exact_stage_order_and_hash_chain_tail() -> None:
    extra_stage = _aurion_handoff_state()
    extra_stage["integration_stage_order"].append("execution_gate")
    extra_stage["state_hash"] = rebuild_state_hash(extra_stage)
    extra_stage["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(extra_stage)
    )
    extra_stage["state_hash"] = rebuild_state_hash(extra_stage)

    stage_valid, stage_failures = validate_execution_convergence_handoff(
        extra_stage
    )

    assert stage_valid is False
    assert (
        "execution_convergence_handoff_pre_execution_stage_order_invalid"
        in stage_failures
    )

    extra_hash = append_hash_entry(
        _aurion_handoff_state(),
        stage="execution_gate",
        payload={"forged_post_aurion_event": True},
    )
    extra_hash["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(extra_hash)
    )
    extra_hash["state_hash"] = rebuild_state_hash(extra_hash)

    hash_valid, hash_failures = validate_execution_convergence_handoff(
        extra_hash
    )

    assert hash_valid is False
    assert (
        "execution_convergence_handoff_pre_execution_chain_tail_invalid"
        in hash_failures
    )


def test_handoff_rejects_unknown_signed_token_and_permission_fields() -> None:
    unknown_token = issue_token(
        _aurion_handoff_state(),
        name="execution_permission",
        issued_at_stage="aurion_runtime",
        payload={"permission": "ALLOW"},
    )
    unknown_token["state_hash"] = rebuild_state_hash(unknown_token)
    unknown_token["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(unknown_token)
    )
    unknown_token["state_hash"] = rebuild_state_hash(unknown_token)

    token_valid, token_failures = validate_execution_convergence_handoff(
        unknown_token
    )

    assert token_valid is False
    assert (
        "execution_convergence_handoff_pre_execution_token_unexpected:execution_permission"
        in token_failures
    )
    assert (
        "execution_convergence_handoff_pre_execution_token_trace_unexpected"
        in token_failures
    )

    for field, value in (
        ("execution_permission", "ALLOW"),
        ("allow_execution", True),
    ):
        state = _aurion_handoff_state()
        state[field] = value
        state["state_hash"] = rebuild_state_hash(state)
        state["execution_convergence_handoff"] = (
            build_execution_convergence_handoff(state)
        )
        state["state_hash"] = rebuild_state_hash(state)

        valid, failures = validate_execution_convergence_handoff(state)

        assert valid is False
        assert (
            f"execution_convergence_handoff_pre_execution_field_present:{field}"
            in failures
        )

    nested = _aurion_handoff_state()
    nested["ui_projection"] = {
        "status": "ready",
        "execution_permission": "ALLOW",
    }
    nested["state_hash"] = rebuild_state_hash(nested)
    nested["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(nested)
    )
    nested["state_hash"] = rebuild_state_hash(nested)

    nested_valid, nested_failures = validate_execution_convergence_handoff(
        nested
    )

    assert nested_valid is False
    assert (
        "execution_convergence_handoff_pre_execution_nested_permission_field:"
        "ui_projection.execution_permission"
        in nested_failures
    )


def test_failed_domain_and_aurion_outputs_neutralize_forged_authority() -> None:
    permission_fields = {
        "execution_permission": "ALLOW",
        "allow_execution": True,
        "runtime_authority": "forged",
        "external_allow": True,
    }

    for runner, base_state, result_field, passing_result in (
        (
            domain_runner.run_domain_wrap,
            _governed_state(),
            "domain_result",
            "pass",
        ),
        (run_aurion_runtime, _domain_state(), "aurion15_result", "pass"),
    ):
        forged = deepcopy(base_state)
        forged.update(permission_fields)
        forged["operational_state"] = "OPERABLE"
        forged["token_stack_valid"] = True
        forged["execution_reason"] = "forged_execute"
        forged["token_verification_failures"] = ["forged_clean_stack"]
        forged["ui_projection"] = {
            "status": "ready",
            "execution_permission": "ALLOW",
        }
        forged["governed_reentry"]["reentry_completed"] = True
        forged = issue_token(
            forged,
            name="execution_permission",
            issued_at_stage="execution_gate",
            payload={"permission": "ALLOW"},
        )
        forged["state_hash"] = rebuild_state_hash(forged)

        result = runner(forged)

        assert result[result_field] != passing_result
        assert result["decision"] == "DENY"
        assert result["execution_result"] == "HALT"
        assert result["operational_state"] == "UNSET"
        assert result["token_stack_valid"] is False
        assert result["execution_reason"] == ""
        assert result["token_verification_failures"] == []
        assert "reentry_completed" not in result["governed_reentry"]
        assert "execution_permission" not in result["tokens"]
        assert all(
            entry.get("name") != "execution_permission"
            for entry in result["token_trace"]
            if isinstance(entry, dict)
        )
        for field in permission_fields:
            assert field not in result
        assert result["ui_projection"] == {"status": "ready"}


def test_direct_gate_rejects_forged_pre_execution_control_state() -> None:
    state = run_aurion_runtime(_domain_state())
    state = _mark_stage(state, "aurion_runtime")
    state["operational_state"] = "OPERABLE"
    state["token_stack_valid"] = True
    state["governed_reentry"]["reentry_completed"] = True
    state["state_hash"] = rebuild_state_hash(state)
    state["execution_convergence_handoff"] = (
        build_execution_convergence_handoff(state)
    )
    state["state_hash"] = rebuild_state_hash(state)

    result = run_execution_gate(state)

    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result["execution_verified"] is False
    assert any(
        "canonical_aurion_handoff_pre_execution" in failure
        for failure in result["token_verification_failures"]
    )


def test_same_id_pathway_mutation_is_rejected_by_direct_execution_gate() -> None:
    state = _aurion_handoff_state()
    original_id = state["current_candidate"]["candidate_id"]
    state["current_candidate"]["pathway"]["mode"] = "safe_state_or_hold"
    assert state["current_candidate"]["candidate_id"] == original_id
    state["state_hash"] = rebuild_state_hash(state)

    result = run_execution_gate(state)

    assert result["execution_result"] == "HALT"
    assert result["execution_verified"] is False
    assert any(
        "aurion" in failure
        or "execution_convergence_handoff" in failure
        for failure in result["token_verification_failures"]
    )


def test_deleted_domain_feedback_cannot_enter_aurion() -> None:
    state = _domain_state()
    state["governance_feedback"].pop("domain_wrap")
    state["state_hash"] = rebuild_state_hash(state)

    result = run_aurion_runtime(state)

    assert result["aurion15_result"] == "fail"
    assert result["execution_result"] == "HALT"
    assert "aurion" not in result["tokens"]
    assert any(
        "domain_evidence" in failure or "validation_state_mismatch:domain" in failure
        for failure in result["governance_feedback"]["aurion"]["failures"]
    )


def test_prior_audit_lineage_deletion_cannot_cross_pass6_boundaries() -> None:
    governed = _governed_state()
    assert len(governed["audit_trace"]) > 1
    governed["audit_trace"] = []
    governed["state_hash"] = rebuild_state_hash(governed)

    domain = domain_runner.run_domain_wrap(governed)

    assert domain["domain_result"] != "pass"
    assert domain["decision"] == "DENY"
    assert domain["execution_result"] == "HALT"
    assert any(
        "audit_lineage" in failure or "grc_evidence_mismatch" in failure
        for failure in domain["governance_feedback"]["domain_wrap"][
            "failures"
        ]
    )

    domain_input = _domain_state()
    assert len(domain_input["audit_trace"]) > 1
    domain_input["audit_trace"] = []
    domain_input["state_hash"] = rebuild_state_hash(domain_input)

    aurion = run_aurion_runtime(domain_input)

    assert aurion["aurion15_result"] == "fail"
    assert aurion["decision"] == "DENY"
    assert aurion["execution_result"] == "HALT"
    assert any(
        "audit_lineage" in failure or "domain_evidence_mismatch" in failure
        for failure in aurion["governance_feedback"]["aurion"]["failures"]
    )


def test_convergence_detects_same_result_domain_aurion_pathway_mutation() -> None:
    reset_measured_startup_for_tests()
    state = main(sample_request())
    mutated = deepcopy(state)
    mutated["current_candidate"]["pathway"]["mode"] = "safe_state_or_hold"
    mutated["state_hash"] = rebuild_state_hash(mutated)

    proof = build_pipeline_convergence_proof(
        pipeline_a=state,
        pipeline_b=mutated,
        mode="MODE_1_FULL_MIRRORED",
    )

    assert proof["matched"] is False
    assert any(
        any(fragment in field for fragment in ("domain", "aurion", "candidate", "pathway"))
        for field in proof["mismatches"]
    )


def test_replay_projection_detects_same_result_aurion_pathway_mutation() -> None:
    reset_measured_startup_for_tests()
    state = main(sample_request())
    mutated = deepcopy(state)
    mutated["current_candidate"]["pathway"]["mode"] = "safe_state_or_hold"
    mutated["state_hash"] = rebuild_state_hash(mutated)
    reference = build_replay_summary(state)
    replayed = build_replay_summary(mutated)
    changed_fields = [
        field
        for field in REPLAY_COMPARISON_FIELDS
        if reference.get(field) != replayed.get(field)
    ]

    assert any(
        any(fragment in field for fragment in ("domain", "aurion", "candidate", "pathway"))
        for field in changed_fields
    )


def test_standalone_legacy_domain_helper_is_integrity_only() -> None:
    record = build_domain_admissibility(
        {
            "legal_domain": "PASS",
            "operational_domain": "PASS",
            "risk_domain": "PASS",
            "environment_state": "CONTROLLED",
            "domain_state": "VALID",
        }
    )
    assert record["valid"] is False
    assert record["execution_convergence_eligible"] is False
    assert verify_domain(record) is True
    evaluated = evaluate_domain(record)
    assert evaluated["allowed"] is False
    assert evaluated["execution_convergence_eligible"] is False


def test_standalone_legacy_aurion_helpers_are_integrity_only() -> None:
    resolution = candidate_resolution.resolve_candidates(
        [
            {
                "candidate_id": "legacy_candidate",
                "score": 0.99,
                "constraints": {"claimed": "valid"},
                "path": "legacy_path",
            }
        ]
    )
    assert resolution["valid"] is False
    assert resolution["execution_convergence_eligible"] is False
    assert candidate_resolution.verify_candidate_resolution(resolution) is True
    evaluated_candidate = candidate_resolution.evaluate_candidate(resolution)
    assert evaluated_candidate["allowed"] is False
    assert evaluated_candidate["execution_convergence_eligible"] is False

    runtime = runtime_constraint_engine.build_runtime_constraint(
        {
            "candidate_hash": resolution["candidate_hash"],
            "constraint_state": "VALID",
            "threshold_state": "VALID",
            "governance_state": "ALLOW",
            "execution_state": "READY",
        }
    )
    assert runtime["valid"] is False
    assert runtime["execution_convergence_eligible"] is False
    assert runtime_constraint_engine.verify_runtime_constraint(runtime) is True
    evaluated_runtime = runtime_constraint_engine.evaluate_runtime_constraint(runtime)
    assert evaluated_runtime["allowed"] is False
    assert evaluated_runtime["execution_convergence_eligible"] is False
