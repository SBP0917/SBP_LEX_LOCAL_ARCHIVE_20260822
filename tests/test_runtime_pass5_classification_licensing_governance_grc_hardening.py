from __future__ import annotations

from copy import deepcopy

import pytest

from main import sample_request
from sbp_lex.api.schema_validation import validate_runtime_request_schema
from sbp_lex.authority_first.root_of_trust_runner import run_root_of_trust
from sbp_lex.classification.ap_acf import run_ap_acf_precheck
from sbp_lex.classification.engine import run_classification
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.governance.engine import run_governance
from sbp_lex.governance.governance_runner import run_governance_pipeline
from sbp_lex.governance.grc import run_grc
from sbp_lex.governance.procedural_truth_runner import (
    run_procedural_truth_pipeline,
)
from sbp_lex.licensing.engine import run_licensing
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.pipeline.replay_runner import (
    REPLAY_COMPARISON_FIELDS,
    run_replay_check,
    verify_replay_result,
)
from sbp_lex.pipeline.runner import (
    PreparedPipelineBoundary,
    _mark_stage,
    _finalize_pipeline,
    prepare_pipeline_boundary,
    run_pipeline,
)
from sbp_lex.security.authority_boundary import (
    validate_canonical_upstream,
    validate_governed_domain_handoff,
)
from sbp_lex.security.governed_stage_evidence import (
    GOVERNED_STAGES,
    live_state_hash_valid,
    validate_stage_evidence,
)
from sbp_lex.security.pqc import generate_digest, sign_payload
from sbp_lex.shared.convergence import (
    GOVERNED_STAGE_PARITY_FIELDS,
    build_pipeline_convergence_proof,
    verify_convergence_proof,
)
from sbp_lex.shared.hash_chain import rebuild_state_hash, verify_hash_chain


def _pt_state(request: dict | None = None) -> dict:
    prepared = prepare_pipeline_boundary(request or sample_request())
    assert isinstance(prepared, PreparedPipelineBoundary)
    state = run_ap_acf_precheck(prepared.materialize())
    state = _mark_stage(state, "ap_acf_precheck")
    state = run_root_of_trust(state)
    state = _mark_stage(state, "root_of_trust")
    state = run_procedural_truth_pipeline(state)
    return _mark_stage(state, "procedural_truth")


def _classified_state(request: dict | None = None) -> dict:
    state = run_classification(_pt_state(request))
    return _mark_stage(state, "classification")


def _licensed_state(request: dict | None = None) -> dict:
    state = run_licensing(_classified_state(request))
    return _mark_stage(state, "licensing")


def _governed_state(request: dict | None = None) -> dict:
    state = run_governance_pipeline(_licensed_state(request))
    state = _mark_stage(state, "governance")
    return _mark_stage(state, "grc")


def _missing_licence_request() -> dict:
    request = sample_request()
    for container in (request["payload"], request["context"]):
        for field in ("licence_state", "license_state", "licence", "license"):
            container.pop(field, None)
    return request


def test_valid_governed_handoff_has_exact_signed_stage_lineage() -> None:
    state = _governed_state()
    assert state["classification_result"] == "ALLOW"
    assert state["licensing_result"] == "ALLOW"
    assert state["governance_result"] == "ALLOW"
    assert state["grc_result"] == "PASS"
    assert live_state_hash_valid(state) is True
    assert verify_hash_chain(state) is True
    for stage in GOVERNED_STAGES:
        valid, failures = validate_stage_evidence(state, stage)
        assert valid, failures
        assert state[f"{stage}_evidence"]["verified"] is True
        assert stage in state["tokens"]
    valid, failures = validate_governed_domain_handoff(state)
    assert valid, failures


def test_missing_licence_never_defaults_to_valid() -> None:
    state = _licensed_state(_missing_licence_request())
    assert state["licensing_result"] == "DENY"
    assert "licence_state_missing" in state["licensing_reason"]
    assert "licensing" not in state["tokens"]


def test_american_licence_alias_is_enforced_and_valid_when_explicit() -> None:
    request = sample_request()
    request["payload"].pop("licence_state")
    request["context"].pop("licence_state")
    request["payload"]["license_state"] = "VALID"
    request["context"]["license_state"] = "VALID"
    state = run_pipeline(request)
    assert state["licensing_result"] == "ALLOW"
    assert state["execution_result"] == "EXECUTE"


@pytest.mark.parametrize(
    "declaration",
    [
        {"state": "DENIED"},
        {"status": "EXPIRED"},
        {"state": "VALID", "issuer": "unverified"},
    ],
)
def test_structured_licence_cannot_be_ignored(declaration: dict) -> None:
    request = _missing_licence_request()
    request["payload"]["license"] = declaration
    state = run_pipeline(request)
    assert state.get("execution_result") != "EXECUTE"
    assert state.get("licensing_result") in (None, "DENY")
    assert "licensing" not in state.get("tokens", {})

    direct = _classified_state()
    direct["payload"].pop("licence_state", None)
    direct["context"].pop("licence_state", None)
    direct["payload"]["license"] = declaration
    direct["state_hash"] = rebuild_state_hash(direct)
    licensed = run_licensing(direct)
    assert licensed["licensing_result"] == "DENY"
    assert (
        "licence_state_invalid" in licensed["licensing_reason"]
        or "structured_licence_fields_unsupported" in licensed["licensing_reason"]
    )


def test_conflicting_licence_sources_fail_closed() -> None:
    request = sample_request()
    request["context"]["license_state"] = "DENIED"
    state = _licensed_state(request)
    assert state["licensing_result"] == "DENY"
    assert "licence_state_conflict" in state["licensing_reason"]


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("autonomy_level", True, "classification_autonomy_level_must_be_int"),
        ("autonomy_ceiling", -1, "classification_autonomy_ceiling_out_of_range"),
        ("autonomy_level", 101, "classification_autonomy_level_out_of_range"),
        ("autonomy_ceiling", 10**500, "classification_autonomy_ceiling_out_of_range"),
    ],
)
def test_autonomy_schema_is_bounded_and_non_boolean(
    field: str, value: object, failure: str
) -> None:
    request = sample_request()
    request["payload"]["classification"][field] = value
    valid, failures = validate_runtime_request_schema(request)
    assert valid is False
    assert failure in failures


def test_class_profile_ceiling_cannot_be_self_escalated() -> None:
    request = sample_request()
    request["payload"]["classification"].update(
        {"ap_acf_class": "CLASS_1", "autonomy_level": 20, "autonomy_ceiling": 100}
    )
    state = _classified_state(request)
    assert state["classification_result"] == "DENY"
    assert "autonomy_ceiling_exceeds_class_profile" in state[
        "classification_reason"
    ]
    assert "classification" not in state["tokens"]


def test_nested_environment_modifiers_are_closed_and_consumed() -> None:
    malformed = sample_request()
    malformed["payload"]["classification"]["environment_modifiers"] = {
        "unknown_override": "allow"
    }
    valid, failures = validate_runtime_request_schema(malformed)
    assert valid is False
    assert (
        "unknown_field:payload.classification.environment_modifiers.unknown_override"
        in failures
    )

    request = sample_request()
    request["context"]["environment"] = "medical"
    request["payload"]["classification"]["environment_modifiers"] = {
        "environment": "medical"
    }
    state = run_pipeline(request)
    assert (
        state["classification"]["environment_modifiers"]["environment"]
        == "medical"
    )
    assert state["governance_result"] == "ESCALATE"
    assert state["execution_result"] == "HALT"


def test_classification_scope_substitution_cannot_enter_licensing() -> None:
    state = _classified_state()
    state["classification"]["operational_scope"] = "attacker_broadened_scope"
    result = run_licensing(state)
    assert result["licensing_result"] == "DENY"
    assert "validation_state_mismatch:classification" in result[
        "licensing_reason"
    ]
    assert "licensing" not in result["tokens"]


def test_cross_request_classification_evidence_and_token_are_rejected() -> None:
    first = _classified_state()
    second_request = sample_request()
    second_request["action"] = "different_request"
    second = _classified_state(second_request)
    second["classification_evidence"] = deepcopy(first["classification_evidence"])
    second["tokens"]["classification"] = deepcopy(first["tokens"]["classification"])
    second["state_hash"] = rebuild_state_hash(second)
    result = run_licensing(second)
    assert result["licensing_result"] == "DENY"
    assert "licensing" not in result["tokens"]


def test_classification_denial_reentry_purges_all_descendant_authority() -> None:
    state = run_pipeline(sample_request())
    result = run_classification(state)
    assert result["classification_result"] == "DENY"
    assert "classification_reentry_requires_full_retraversal" in result[
        "classification_reason"
    ]
    for token in (
        "classification",
        "licensing",
        "governance",
        "grc",
        "domain",
        "aurion",
        "execution_boundary",
        "execution_attestation",
    ):
        assert token not in result["tokens"]


def test_explicit_scope_contract_is_reachable_but_never_broadens() -> None:
    request = sample_request()
    request["context"]["requested_scope"] = "controlled_test"
    request["context"]["permitted_scopes"] = ["controlled_test"]
    request["context"]["permitted_environments"] = ["controlled_test"]
    valid, failures = validate_runtime_request_schema(request)
    assert valid, failures
    allowed = run_pipeline(request)
    assert allowed["licensing_result"] == "ALLOW"

    broadened = deepcopy(request)
    broadened["context"]["requested_scope"] = "production"
    broadened["context"]["permitted_scopes"].append("production")
    denied = _licensed_state(broadened)
    assert denied["licensing_result"] == "DENY"
    assert "requested_scope_broadens_classification_scope" in denied[
        "licensing_reason"
    ]


def test_licensing_scope_substitution_cannot_enter_governance() -> None:
    state = _licensed_state()
    state["licensing_scope"] = "attacker_broadened_scope"
    result = run_governance_pipeline(state)
    assert result["governance_result"] == "DENY"
    assert result["grc_result"] == "DENY"
    assert "governance" not in result["tokens"]


def test_licensing_denial_reentry_purges_stale_allow_token() -> None:
    state = _licensed_state()
    state["classification_result"] = "DENY"
    state["state_hash"] = rebuild_state_hash(state)
    result = run_licensing(state)
    assert result["licensing_result"] == "DENY"
    assert "licensing_reentry_requires_full_retraversal" in result[
        "licensing_reason"
    ]
    assert "licensing" not in result["tokens"]


def test_grc_cannot_pass_without_the_complete_governance_chain() -> None:
    forged = _pt_state()
    forged["governance_result"] = "ALLOW"
    forged["governance_reason"] = "forged_allow"
    forged["state_hash"] = rebuild_state_hash(forged)
    result = run_grc(forged)
    assert result["grc_result"] == "DENY"
    assert result["governance_result"] == "DENY"
    assert result["decision"] == "DENY"


def test_grc_cannot_pass_when_governance_token_is_deleted() -> None:
    state = _licensed_state()
    from sbp_lex.governance.engine import run_governance

    state = run_governance(state)
    state["tokens"].pop("governance")
    state["state_hash"] = rebuild_state_hash(state)
    result = run_grc(state)
    assert result["grc_result"] == "DENY"
    assert result["governance_result"] == "DENY"


def test_deleting_governance_denial_history_cannot_invert_to_allow() -> None:
    state = _licensed_state()
    state["last_denied_fingerprint"] = state["request_fingerprint"]
    state["state_hash"] = rebuild_state_hash(state)
    denied = run_governance_pipeline(state)
    assert denied["governance_result"] == "DENY"
    assert denied["grc_result"] == "DENY"

    attack = deepcopy(denied)
    attack["governance_result"] = "ALLOW"
    attack["governance_reason"] = "forged_allow"
    attack["governance_feedback"].pop("history", None)
    attack["last_denied_fingerprint"] = None
    attack["state_hash"] = rebuild_state_hash(attack)
    result = run_grc(attack)
    assert result["grc_result"] == "DENY"
    assert result["decision"] == "DENY"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("current_candidate", {"result": "ALLOW"}),
        ("ui_result", "ALLOW"),
        ("urgency", "EMERGENCY_ALLOW"),
        ("severity", "OVERRIDE"),
        ("adaptive_mode", "SELF_AUTHORIZE"),
        ("synthetic_skg", {"authority": "ALLOW"}),
        ("synthetic_dtn", {"authority": "ALLOW"}),
        ("stale_previous_allow", True),
    ],
)
def test_governance_denial_supremacy_survives_downstream_authority_inversion(
    field: str, value: object
) -> None:
    state = _licensed_state()
    state["last_denied_fingerprint"] = state["request_fingerprint"]
    state["state_hash"] = rebuild_state_hash(state)
    denied = run_governance_pipeline(state)
    denied = _mark_stage(denied, "governance")
    denied = _mark_stage(denied, "grc")
    denied[field] = value
    denied["governance_result"] = "ALLOW"
    denied["grc_result"] = "PASS"
    denied["state_hash"] = rebuild_state_hash(denied)
    domain = run_domain_wrap(denied)
    assert domain["domain_result"] == "escalate"
    assert domain["decision"] == "DENY"
    assert domain["governance_feedback"]["domain_wrap"]["attempts"] == []
    assert "domain" not in domain["tokens"]


def test_escalate_cannot_become_domain_or_execution_permission() -> None:
    request = sample_request()
    request["payload"]["classification"].update(
        {"ap_acf_class": "CLASS_5", "autonomy_ceiling": 50}
    )
    state = run_pipeline(request)
    assert state["governance_result"] == "ESCALATE"
    assert state["grc_result"] == "ESCALATE"
    assert state["execution_result"] == "HALT"
    assert "governance" not in state["tokens"]
    assert "domain" not in state["tokens"]


@pytest.mark.parametrize("attack", ["missing", "deny", "state_hash", "cross_request"])
def test_domain_requires_exact_pass_grc_evidence_and_token(attack: str) -> None:
    state = _governed_state()
    if attack == "missing":
        state["tokens"].pop("grc")
    elif attack == "deny":
        state["grc_result"] = "DENY"
    elif attack == "state_hash":
        state["state_hash"] = "0" * 64
    else:
        other_request = sample_request()
        other_request["action"] = "cross_request"
        other = _governed_state(other_request)
        state["grc_evidence"] = deepcopy(other["grc_evidence"])
        state["tokens"]["grc"] = deepcopy(other["tokens"]["grc"])
    if attack not in {"state_hash"}:
        state["state_hash"] = rebuild_state_hash(state)
    result = run_domain_wrap(state)
    assert result["domain_result"] == "escalate"
    assert result["governance_feedback"]["domain_wrap"]["attempts"] == []
    assert "domain" not in result["tokens"]


def test_tier_and_autonomy_constraints_cannot_be_weakened_late() -> None:
    state = _governed_state()
    state["classification"]["autonomy_ceiling"] = 100
    state["safety_profile"]["computed_tier"] = "LOW"
    state["state_hash"] = rebuild_state_hash(state)
    result = run_domain_wrap(state)
    assert result["domain_result"] == "escalate"
    failures = result["governance_feedback"]["domain_wrap"]["failures"]
    assert any("autonomy" in failure or "tier" in failure for failure in failures)


def test_pass5_replay_compares_exact_governed_fields() -> None:
    replay = run_replay_check(request=sample_request(), replay_count=2)
    assert replay["matched"] is True
    assert verify_replay_result(replay) == (True, [])
    for field in GOVERNED_STAGE_PARITY_FIELDS:
        assert field in REPLAY_COMPARISON_FIELDS
        assert replay["reference"][field] == replay["runs"][1][field]


def test_pass5_ab_parity_detects_grc_and_reentry_divergence() -> None:
    state = run_dual_pipeline(sample_request())
    pipeline_b = deepcopy(state)
    pipeline_b["grc_result"] = "DENY"
    pipeline_b["governed_reentry"]["reason"] = "injected_divergence"
    proof = build_pipeline_convergence_proof(
        pipeline_a=state,
        pipeline_b=pipeline_b,
        mode="MODE_1_FULL_MIRRORED",
    )
    assert proof["matched"] is False
    assert "grc_result" in proof["mismatches"]
    assert "governed_reentry_digest" in proof["mismatches"]
    assert proof["near_match_reconciliation_used"] is False


def test_audit_preserves_complete_pass5_evidence_and_domain_boundary() -> None:
    state = run_pipeline(sample_request())
    lineage = state["audit_record"]["payload"]["integration_evidence"][
        "classification_licensing_governance_grc_lineage"
    ]
    assert lineage["domain_handoff_valid"] is True
    assert lineage["constraint_continuity_valid"] is True
    assert lineage["governance_history_valid"] is True
    assert lineage["governance_history_digest"] == generate_digest(
        lineage["governance_history"]
    )
    for stage in GOVERNED_STAGES:
        record = lineage["stages"][stage]
        assert record["evidence_valid"] is True
        assert record["evidence_digest"]
        assert record["stage_state_digest"]
        assert record["hash_chain_logical_index"]


def test_stage_tokens_bind_rebuilt_decision_state_not_prior_stage_hash() -> None:
    pt = _pt_state()
    classified = run_classification(pt)
    evidence_payload = classified["classification_evidence"]["payload"]
    token = classified["tokens"]["classification"]
    assert token["state_hash"] == evidence_payload["state_hash_before_token"]
    assert token["state_hash"] != evidence_payload["state_hash_entering_stage"]
    assert token["payload"]["decision_state_digest"] == evidence_payload[
        "decision_state_digest"
    ]


@pytest.mark.parametrize("malformed_chain", [None, ["not-a-hash-entry"]])
def test_malformed_hash_chain_is_a_controlled_classification_denial(
    malformed_chain: object,
) -> None:
    state = _pt_state()
    state["hash_chain"] = malformed_chain
    state["state_hash"] = rebuild_state_hash(state)
    result = run_classification(state)
    assert result["classification_result"] == "DENY"
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert "classification" not in result["tokens"]


def test_historical_classification_allow_is_superseded_by_later_denial() -> None:
    allowed = run_pipeline(sample_request())
    denied = run_classification(allowed)
    assert denied["classification_result"] == "DENY"

    attack = deepcopy(denied)
    for field in (
        "classification",
        "classification_result",
        "classification_reason",
        "classification_evidence",
        "pipeline_mode",
    ):
        attack[field] = deepcopy(allowed[field])
    attack["tokens"]["classification"] = deepcopy(
        allowed["tokens"]["classification"]
    )
    attack["state_hash"] = rebuild_state_hash(attack)
    valid, failures = validate_canonical_upstream(
        attack, required_tokens=("classification",)
    )
    assert valid is False
    assert "validation_state_mismatch:classification" in failures
    evidence_valid, evidence_failures = validate_stage_evidence(
        attack, "classification"
    )
    assert evidence_valid is False
    assert "classification_evidence_superseded" in evidence_failures


def test_historical_governed_allow_cannot_supersede_later_denial() -> None:
    allowed = _governed_state()
    denied = run_governance_pipeline(allowed)
    denied = _mark_stage(denied, "governance")
    denied = _mark_stage(denied, "grc")
    assert denied["governance_result"] == "DENY"

    attack = deepcopy(denied)
    for field in (
        "governance_state",
        "governance_result",
        "governance_reason",
        "governance_evidence",
        "grc_state",
        "grc_result",
        "grc_reason",
        "grc_evidence",
        "governed_reentry",
    ):
        attack[field] = deepcopy(allowed[field])
    for token in ("governance", "grc"):
        attack["tokens"][token] = deepcopy(allowed["tokens"][token])
    for field in ("history", "governance", "grc"):
        attack["governance_feedback"][field] = deepcopy(
            allowed["governance_feedback"][field]
        )
    attack.pop("last_denied_fingerprint", None)
    attack["state_hash"] = rebuild_state_hash(attack)
    result = run_domain_wrap(attack)
    assert result["domain_result"] == "escalate"
    failures = result["governance_feedback"]["domain_wrap"]["failures"]
    assert any("evidence_superseded" in failure for failure in failures)
    assert result["governance_feedback"]["domain_wrap"]["attempts"] == []


def test_grc_evidence_binds_the_denial_and_reentry_inputs_it_consumes() -> None:
    state = _governed_state()
    state["last_denied_fingerprint"] = "a" * 64
    state["state_hash"] = rebuild_state_hash(state)
    result = run_domain_wrap(state)
    assert result["domain_result"] == "escalate"
    failures = result["governance_feedback"]["domain_wrap"]["failures"]
    assert "grc_evidence_mismatch:stage_state" in failures


def test_direct_domain_rejects_every_incomplete_pass5_prefix() -> None:
    licensed = _licensed_state()
    governance_only = run_governance(licensed)
    governance_only = _mark_stage(governance_only, "governance")
    prefixes = (_pt_state(), _classified_state(), licensed, governance_only)
    for state in prefixes:
        result = run_domain_wrap(state)
        assert result["domain_result"] == "escalate"
        assert result["governance_feedback"]["domain_wrap"]["attempts"] == []
        assert "domain" not in result.get("tokens", {})


def test_grc_rejects_fingerprint_retry_fallback_and_feedback_substitution() -> None:
    governance = run_governance(_licensed_state())
    attacks = []

    fingerprint = deepcopy(governance)
    fingerprint["request_fingerprint"] = "f" * 64
    fingerprint["state_hash"] = rebuild_state_hash(fingerprint)
    attacks.append(fingerprint)

    retry = deepcopy(governance)
    retry["last_denied_fingerprint"] = retry["request_fingerprint"]
    retry["state_hash"] = rebuild_state_hash(retry)
    attacks.append(retry)

    fallback = deepcopy(governance)
    fallback["context"]["domain_fallback_safe"] = True
    fallback["state_hash"] = rebuild_state_hash(fallback)
    attacks.append(fallback)

    feedback = deepcopy(governance)
    feedback["governance_feedback"]["history"] = "deleted"
    feedback["state_hash"] = rebuild_state_hash(feedback)
    attacks.append(feedback)

    for attack in attacks:
        result = run_grc(attack)
        assert result["grc_result"] == "DENY"
        assert result["governance_result"] == "DENY"
        assert result["decision"] == "DENY"


def test_escalate_to_allow_mutation_cannot_pass_grc() -> None:
    request = sample_request()
    request["payload"]["classification"].update(
        {"ap_acf_class": "CLASS_5", "autonomy_ceiling": 50}
    )
    governance = run_governance(_licensed_state(request))
    assert governance["governance_result"] == "ESCALATE"
    governance["governance_result"] = "ALLOW"
    governance["governance_reason"] = "forged_allow"
    governance["state_hash"] = rebuild_state_hash(governance)
    result = run_grc(governance)
    assert result["grc_result"] == "DENY"
    assert result["decision"] == "DENY"


def test_replay_preserves_classification_licensing_and_escalate_outcomes() -> None:
    classification_denied = sample_request()
    classification_denied["payload"]["classification"].update(
        {"ap_acf_class": "CLASS_1", "autonomy_ceiling": 100}
    )
    licensing_denied = _missing_licence_request()
    escalated = sample_request()
    escalated["payload"]["classification"].update(
        {"ap_acf_class": "CLASS_5", "autonomy_ceiling": 50}
    )
    cases = (
        (classification_denied, "DENY", None, None, None),
        (licensing_denied, "ALLOW", "DENY", None, None),
        (escalated, "ALLOW", "ALLOW", "ESCALATE", "ESCALATE"),
    )
    for request, classification, licensing, governance, grc in cases:
        replay = run_replay_check(request=request, replay_count=2)
        assert replay["matched"] is True
        assert verify_replay_result(replay) == (True, [])
        reference = replay["reference"]
        assert reference["classification_result"] == classification
        assert reference["licensing_result"] == licensing
        assert reference["governance_result"] == governance
        assert reference["grc_result"] == grc


def test_audit_token_expectations_cover_deny_and_escalate() -> None:
    classification_denied = sample_request()
    classification_denied["payload"]["classification"].update(
        {"ap_acf_class": "CLASS_1", "autonomy_ceiling": 100}
    )
    licensing_denied = _missing_licence_request()
    escalated = sample_request()
    escalated["payload"]["classification"].update(
        {"ap_acf_class": "CLASS_5", "autonomy_ceiling": 50}
    )
    states = (
        run_pipeline(classification_denied),
        run_pipeline(licensing_denied),
        run_pipeline(escalated),
    )
    for state in states:
        stages = state["audit_record"]["payload"]["integration_evidence"][
            "classification_licensing_governance_grc_lineage"
        ]["stages"]
        for record in stages.values():
            assert record["token_valid"] is True
            assert record["token_present"] is record["token_expected"]
    escalate_stages = states[-1]["audit_record"]["payload"][
        "integration_evidence"
    ]["classification_licensing_governance_grc_lineage"]["stages"]
    assert escalate_stages["governance"]["token_expected"] is False
    assert escalate_stages["grc"]["token_expected"] is True


def test_governance_denial_audit_preserves_valid_grc_denial_token() -> None:
    state = _licensed_state()
    state["last_denied_fingerprint"] = state["request_fingerprint"]
    state["state_hash"] = rebuild_state_hash(state)
    state = run_governance_pipeline(state)
    state = _mark_stage(state, "governance")
    state = _mark_stage(state, "grc")
    state.setdefault("convergence_hash", state["state_hash"])
    state.setdefault("execution_verified", False)
    state.setdefault("decision", "DENY")
    state = _finalize_pipeline(state)
    stages = state["audit_record"]["payload"]["integration_evidence"][
        "classification_licensing_governance_grc_lineage"
    ]["stages"]
    assert stages["governance"]["result"] == "DENY"
    assert stages["governance"]["token_present"] is False
    assert stages["governance"]["token_valid"] is True
    assert stages["grc"]["result"] == "DENY"
    assert stages["grc"]["token_present"] is True
    assert stages["grc"]["token_valid"] is True


def _resign_convergence_proof(proof: dict) -> dict:
    payload = {
        key: deepcopy(value)
        for key, value in proof.items()
        if key not in {"convergence_hash", "signature"}
    }
    proof["convergence_hash"] = generate_digest(payload)
    proof["signature"] = sign_payload(payload)
    return proof


def test_parity_recomputes_live_state_and_rejects_resigned_inconsistency() -> None:
    pipeline_a = _governed_state()
    pipeline_b = deepcopy(pipeline_a)
    pipeline_b["classification"]["deployment_restrictions"] = ["ATTACK"]
    pipeline_b["licensing"]["licence_state"] = "DENIED"
    pipeline_b["state_hash"] = rebuild_state_hash(pipeline_b)
    proof = build_pipeline_convergence_proof(
        pipeline_a=pipeline_a,
        pipeline_b=pipeline_b,
        mode="MODE_1_FULL_MIRRORED",
    )
    assert proof["matched"] is False
    assert "classification_live_state_digest" in proof["mismatches"]
    assert "classification_evidence_valid" in proof["mismatches"]
    assert "licensing_live_state_digest" in proof["mismatches"]
    assert verify_convergence_proof(proof) is True

    forged = deepcopy(proof)
    forged["matched"] = True
    forged["mismatches"] = []
    forged = _resign_convergence_proof(forged)
    assert verify_convergence_proof(forged) is False


def test_replay_verifier_requires_exact_comparison_metadata() -> None:
    replay = run_replay_check(request=sample_request(), replay_count=2)
    replay["comparison_fields"] = replay["comparison_fields"][:-1]
    payload = {
        key: deepcopy(value)
        for key, value in replay.items()
        if key not in {"replay_hash", "replay_signature"}
    }
    replay["replay_hash"] = generate_digest(payload)
    signature_payload = {**payload, "replay_hash": replay["replay_hash"]}
    replay["replay_signature"] = sign_payload(signature_payload)
    valid, failures = verify_replay_result(replay)
    assert valid is False
    assert failures == ["REPLAY_MISMATCH"]


def test_actual_dual_runner_reports_exact_pass5_parity_and_halts_divergence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = run_dual_pipeline(sample_request())
    parity = valid["pipeline_governed_stage_parity"]
    assert parity["applicable"] is True
    assert parity["exact_parity_result"] is True
    assert all(parity["field_matches"].values())

    import sbp_lex.pipeline.dual_runner as dual_module

    base = run_pipeline(sample_request())
    calls = 0

    def divergent_pipeline(_: PreparedPipelineBoundary) -> dict:
        nonlocal calls
        calls += 1
        result = deepcopy(base)
        if calls == 2:
            result["grc_result"] = "DENY"
            result["state_hash"] = rebuild_state_hash(result)
        return result

    monkeypatch.setattr(dual_module, "_run_admitted_pipeline", divergent_pipeline)
    result = dual_module.run_dual_pipeline(sample_request())
    assert result["pipeline_governed_stage_parity"]["exact_parity_result"] is False
    assert result["pipeline_convergence"]["matched"] is False
    assert result["decision"] == "ESCALATE"
    assert result["execution_result"] == "HALT"
    assert "divergence_record" in result
