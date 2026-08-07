from __future__ import annotations

from copy import deepcopy

from main import main, sample_request
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.config.security_config import (
    CONDITIONAL_THRESHOLD_TOKENS,
    build_audit_security,
    build_collective_signal_security,
    build_execution_gate_security,
    build_pqc_config,
    build_security_config,
    build_token_requirements,
)
from sbp_lex.config.thresholds import (
    LOW,
    MEDIUM,
    TOP,
    apply_thresholds,
    calculate_consequentiality_tier,
    calculate_financial_factor,
    calculate_financial_tier,
    required_corroboration_for_tier,
)
from sbp_lex.domains import runner as domain_runner
from sbp_lex.domains.base_domain import (
    DOMAIN_ESCALATE,
    DOMAIN_PASS,
    DOMAIN_REQUIRE_NEXT_CANDIDATE,
    DOMAIN_RESULTS,
    make_domain_result,
)
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.governance.corroboration_engine import run_corroboration_validation
from sbp_lex.governance.evidence_engine import run_evidence_validation
from sbp_lex.governance.threshold_conditioning_engine import run_threshold_conditioning
from sbp_lex.security.threshold_tokens import verify_threshold_bundle
from sbp_lex.security.token_stack import issue_token
from sbp_lex.pipeline.runner import (
    PreparedPipelineBoundary,
    prepare_pipeline_boundary,
)


def _qualified_evidence(count: int) -> list[dict[str, object]]:
    return [
        {
            "source": f"source_{index}",
            "content": f"content_{index}",
            "verified": True,
            "attested": True,
            "freshness_valid": True,
            "consistency_valid": True,
        }
        for index in range(count)
    ]


def _corroboration_state(tier_factor: int, evidence: list[dict[str, object]]) -> dict:
    request = sample_request()
    request["safety_profile"] = {
        "human_safety": tier_factor,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 0,
    }
    request["context"]["financial_amount"] = 0
    request["context"]["evidence"] = evidence
    prepared = prepare_pipeline_boundary(request)
    assert isinstance(prepared, PreparedPipelineBoundary)
    state = prepared.materialize()
    state = run_ap_acf_precheck(state)
    state = run_root_of_trust(state)
    state = run_evidence_validation(state)
    state = run_threshold_conditioning(state)
    return run_corroboration_validation(state)


def test_locked_threshold_mapping_and_unknown_tier() -> None:
    assert calculate_consequentiality_tier(
        human_safety=3,
        irreversibility=0,
        cascading_impact=0,
        financial_operational=0,
    ) == TOP
    assert calculate_consequentiality_tier(
        human_safety=2,
        irreversibility=0,
        cascading_impact=0,
        financial_operational=0,
    ) == MEDIUM
    for factor in (0, 1, None, "invalid"):
        assert calculate_consequentiality_tier(
            human_safety=factor,
            irreversibility=0,
            cascading_impact=0,
            financial_operational=0,
        ) == LOW
    assert required_corroboration_for_tier("UNKNOWN") == 5


def test_locked_financial_banding() -> None:
    cases = [
        (499.99, 1, LOW),
        (500.00, 2, MEDIUM),
        (49_999.99, 2, MEDIUM),
        (50_000.00, 3, TOP),
    ]
    for amount, factor, tier in cases:
        assert calculate_financial_factor(amount) == factor
        assert calculate_financial_tier(amount) == tier
    state = apply_thresholds(
        {
            "safety_profile": {
                "human_safety": 0,
                "irreversibility": 0,
                "cascading_impact": 0,
                "financial_operational": 0,
            },
            "context": {"financial_amount": 50_000.00},
        }
    )
    assert state["safety_profile"]["financial_operational"] == 3
    assert state["safety_profile"]["computed_tier"] == TOP


def test_existing_top_tier_cannot_silently_downgrade() -> None:
    state = {
        "safety_profile": {
            "human_safety": 1,
            "irreversibility": 1,
            "cascading_impact": 1,
            "financial_operational": 1,
            "computed_tier": TOP,
        },
        "context": {"financial_amount": 0},
    }
    assert apply_thresholds(state)["safety_profile"]["computed_tier"] == TOP


def test_security_builders_and_canonical_threshold_tokens() -> None:
    assert build_pqc_config()["digest_algorithm"] == "sha256"
    assert build_token_requirements()["conditional_thresholds"] == CONDITIONAL_THRESHOLD_TOKENS
    assert build_collective_signal_security()["allow_unsigned_collective_signals"] is False
    assert build_execution_gate_security()["require_hash_chain"] is True
    assert build_audit_security()["require_audit_hash"] is True
    assert build_security_config()["tokens"]["conditional_thresholds"] == CONDITIONAL_THRESHOLD_TOKENS

    state = main(sample_request())
    assert all(name in state["tokens"] for name in CONDITIONAL_THRESHOLD_TOKENS)
    assert verify_threshold_bundle(state) == (True, [])


def test_domain_result_contract_maps_legacy_and_unknown_values() -> None:
    legacy = make_domain_result(domain="test", result="fail", reason="legacy")
    unknown = make_domain_result(domain="test", result="uncontrolled", reason="unknown")
    assert legacy["result"] == DOMAIN_REQUIRE_NEXT_CANDIDATE
    assert unknown["result"] == DOMAIN_ESCALATE
    assert legacy["result"] in DOMAIN_RESULTS
    assert unknown["result"] in DOMAIN_RESULTS


class _PassOnThirdCandidate:
    name = "test_domain"

    def evaluate(self, state: dict) -> dict:
        attempt = state["current_candidate"]["attempt"]
        result = DOMAIN_PASS if attempt == 3 else DOMAIN_REQUIRE_NEXT_CANDIDATE
        return make_domain_result(domain=self.name, result=result, reason=f"attempt_{attempt}")


class _NeverPasses:
    name = "test_domain"

    def evaluate(self, state: dict) -> dict:
        attempt = state["current_candidate"]["attempt"]
        return make_domain_result(
            domain=self.name,
            result=DOMAIN_REQUIRE_NEXT_CANDIDATE,
            reason=f"attempt_{attempt}",
        )


def _domain_state(profile: str | None = None) -> dict:
    request = sample_request()
    request["action"] = "governed_test"
    request["context"]["operational_scope"] = "test_scope"
    if profile:
        request["context"]["deployment_profile"] = profile
    return main(request)


def test_domain_fallback_is_bounded_unique_and_audited(monkeypatch) -> None:
    monkeypatch.setattr(domain_runner, "DOMAIN_ENGINES", [_PassOnThirdCandidate()])
    result = domain_runner.run_domain_wrap(_domain_state())
    lineage = result["governance_feedback"]["domain_wrap"]["attempts"]
    assert result["domain_result"] == DOMAIN_PASS
    assert len(lineage) == 3
    assert len({item["candidate_hash"] for item in lineage}) == 3
    assert [item["candidate"]["search_space_remaining"] for item in lineage] == [4, 3, 2]
    attempt_audit = [
        item for item in result["audit_trace"] if item["stage"] == "domain_wrap_attempt"
    ]
    assert [item["candidate_hash"] for item in attempt_audit[-3:]] == [
        item["candidate_hash"] for item in lineage
    ]


def test_domain_fallback_escalates_at_profile_limit(monkeypatch) -> None:
    monkeypatch.setattr(domain_runner, "DOMAIN_ENGINES", [_NeverPasses()])
    result = domain_runner.run_domain_wrap(_domain_state("physical-critical"))
    feedback = result["governance_feedback"]["domain_wrap"]
    assert result["domain_result"] == DOMAIN_ESCALATE
    assert result["execution_result"] == "HALT"
    assert feedback["attempt_count"] == 3
    assert feedback["max_attempts"] == 3


def test_raw_evidence_does_not_count_toward_corroboration() -> None:
    result = _corroboration_state(1, [{"source": "raw", "content": "raw"}])
    feedback = result["governance_feedback"]
    assert feedback["evidence_validation"]["result"] == "FAIL"
    assert feedback["corroboration"]["evidence_count"] == 0
    assert result["corroboration_met"] is False


def test_corroboration_requires_locked_count_for_each_tier() -> None:
    for factor, required in ((3, 5), (2, 3), (1, 2)):
        insufficient = _corroboration_state(factor, _qualified_evidence(required - 1))
        assert insufficient["corroboration_met"] is False
        assert insufficient["governance_feedback"]["corroboration"]["failure_outcome"] == (
            "ESCALATE" if factor == 3 else "REFINE"
        )
        sufficient = _corroboration_state(factor, _qualified_evidence(required))
        assert sufficient["corroboration_met"] is True
        assert sufficient["governance_feedback"]["corroboration"]["evidence_count"] == required


def test_execution_gate_halts_without_corroboration() -> None:
    state = main(sample_request())
    state["corroboration_met"] = False
    result = run_execution_gate(state)
    assert result["execution_result"] == "HALT"
    assert "corroboration_threshold_not_met" in result["token_verification_failures"]


def test_execution_gate_halts_when_threshold_bundle_is_invalid() -> None:
    state = main(sample_request())
    state["tokens"]["threshold_bundle"]["digest"] = "tampered"
    result = run_execution_gate(state)
    assert result["execution_result"] == "HALT"
    assert "invalid_threshold_bundle" in result["token_verification_failures"]


def test_execution_proceeds_only_with_complete_valid_controls() -> None:
    state = main(sample_request())
    assert state["procedural_truth_result"] == "PASS"
    assert state["corroboration_met"] is True
    assert state["domain_result"] == DOMAIN_PASS
    assert state["aurion15_result"] == "pass"
    assert state["token_stack_valid"] is True
    assert state["execution_verified"] is True
    assert state["execution_result"] == "EXECUTE"
