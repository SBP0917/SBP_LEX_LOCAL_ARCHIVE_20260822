from __future__ import annotations

import random
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from main import sample_request
from sbp_lex.formal.model import (
    ARCHITECTURAL_STATES,
    CANONICAL_CONTROL_STATES,
    EXTERNAL_NON_AUTHORITY_COMPONENTS,
    PIPELINE_MODES,
    REQUIRED_TOKEN_NAMES,
    SAFE_TERMINAL_STATES,
    TRANSITION_INDEX,
    TRANSITION_RECORDS,
    FormalState,
    LineageNode,
)
from sbp_lex.formal.assurance import (
    FormalAssuranceError,
    build_artifact,
    load_artifact,
    validate_artifact,
    write_artifact,
)
from sbp_lex.formal.verifier import (
    CANONICAL_RUNTIME_ORDER,
    LINEAGE_ORDER,
    SAFE_CONVERGENCE,
    FormalArchitectureVerifier,
    formalize_runtime_state,
    replay_formal_verification,
    safe_state_for,
    verify_lineage,
    verify_transition,
)
from sbp_lex.pipeline.runner import run_pipeline
from sbp_lex.pipeline.dual_runner import run_dual_pipeline
from sbp_lex.security.pqc import generate_digest

DIGESTS = {name: generate_digest({"phq": name}) for name in (
    "request", "state", "eie", "runtime", "measurement", "evidence",
)}


def pipeline_summary() -> dict[str, Any]:
    return {
        "request_fingerprint": DIGESTS["request"],
        "eie_digest": DIGESTS["eie"],
        "canonical_state_hash": DIGESTS["state"],
        "decision": "ALLOW",
        "governance_result": "ALLOW",
        "domain_result": "pass",
        "aurion15_result": "pass",
        "execution_result": "EXECUTE",
    }


def valid_state(mode: str = "MODE_3_SINGLE_CONSTRAINED", **updates: Any) -> FormalState:
    summary = pipeline_summary()
    pipeline_b = None
    active = 1
    if mode == "MODE_1_FULL_MIRRORED":
        pipeline_b = {**summary, "role": "MIRROR", "independently_authorized": False}
        active = 2
    elif mode == "MODE_2_SPLIT_VALIDATOR":
        pipeline_b = {
            **summary, "role": "VALIDATOR", "independently_authorized": False,
            "weakens_pipeline_a": False, "overrides_governance": False,
        }
        active = 2
    payload: dict[str, Any] = {
        "architectural_state": "EXECUTION_GATE_RESOLVED",
        "decision_state": "ALLOW",
        "pipeline_mode": mode,
        "convergence_state": "MATCHED",
        "required_evidence": tuple(sorted({
            "authority_first_result", "procedural_truth_result", "classification_result",
            "licensing_result", "governance_result", "grc_result", "domain_result",
            "aurion15_result",
        })),
        "causal_predecessor": "AURION_RESOLVED",
        "request_fingerprint": DIGESTS["request"],
        "canonical_state_hash": DIGESTS["state"],
        "eie_digest": DIGESTS["eie"],
        "runtime_identity": DIGESTS["runtime"],
        "measured_baseline_identity": "DESKTOP_V1_PHQ_TEST_BASELINE",
        "measurement_digest": DIGESTS["measurement"],
        "stage_history": CANONICAL_RUNTIME_ORDER,
        "tokens": {name: {"name": name} for name in REQUIRED_TOKEN_NAMES},
        "authority_scope": ("READ", "WRITE_BOUNDED"),
        "permission_scope": ("inspect", "execute_bounded"),
        "constraints": {
            "max_items": 10, "min_items": 1, "allowed_modes": ["bounded"],
            "requires_confirmation": True,
        },
        "licensing_scope": ("inspect", "execute_bounded"),
        "identities": {"source": "source-1", "adapter": "adapter-1", "target": "target-1"},
        "evidence": {
            "authority_first_result": "PASS", "procedural_truth_result": "PASS",
            "classification_result": "ALLOW", "licensing_result": "ALLOW",
            "governance_result": "ALLOW", "grc_result": "PASS",
            "domain_result": "pass", "aurion15_result": "pass",
            "source": "source-1", "provenance": "signed-package", "schema": "v1",
            "signature": "verified", "package_identity": "package-1",
            "dependency_lineage": "dependency-1",
        },
        "pipeline_a": summary,
        "pipeline_b": pipeline_b,
        "measured_startup_status": "MEASURED_STARTUP_APPROVED",
        "component_authorities": {component: () for component in EXTERNAL_NON_AUTHORITY_COMPONENTS},
        "collective_attachment_count": 1,
        "active_pipeline_count": active,
        "classification_rank": 2,
        "consequence_tier": 2,
        "corroboration_required": 2,
        "audit_complete": True,
        "audit_lineage": (DIGESTS["evidence"],),
    }
    payload.update(updates)
    return FormalState(**payload)


def state_at(name: str, **updates: Any) -> FormalState:
    payload = valid_state().as_payload()
    payload.update({
        "architectural_state": name,
        "decision_state": "UNRESOLVED",
        "audit_complete": False,
        "audit_lineage": (),
    })
    payload.update(updates)
    return FormalState(**payload)


def complete_lineage() -> tuple[LineageNode, ...]:
    nodes: list[LineageNode] = []
    for index, node_type in enumerate(LINEAGE_ORDER):
        identifier = f"node-{index:02d}-{node_type.lower()}"
        predecessor = () if index == 0 else (nodes[-1].node_identifier,)
        capability_id = "capability-1" if index >= LINEAGE_ORDER.index("H7_CAPABILITY") else None
        attested = capability_id if node_type == "EXECUTION_ATTESTATION" else None
        nodes.append(LineageNode(
            node_identifier=identifier,
            node_type=node_type,
            predecessor_identifiers=predecessor,
            request_fingerprint=DIGESTS["request"],
            canonical_state_hash=DIGESTS["state"],
            eie_digest=DIGESTS["eie"],
            runtime_identity=DIGESTS["runtime"],
            measured_baseline_identity="DESKTOP_V1_PHQ_TEST_BASELINE",
            evidence_digest=generate_digest({"node": node_type}),
            capability_id=capability_id,
            attested_capability_id=attested,
        ).with_digest())
    return tuple(nodes)


@pytest.mark.parametrize("mode", PIPELINE_MODES)
def test_complete_valid_traversal_for_each_pipeline_mode(mode: str) -> None:
    result = FormalArchitectureVerifier().verify(valid_state(mode))
    assert result.valid
    assert result.decision == "FORMAL_PASS"
    assert result.authority_granted is False
    assert result.assurance_owner == "SBP_LEX_DESKTOP_V1_DETACHED_FORMAL_ASSURANCE"
    assert result.verify_integrity()


def test_formal_schemas_are_strict_and_cover_exact_contracts() -> None:
    root = Path(__file__).resolve().parents[1] / "sbp_lex" / "formal" / "schemas"
    state = json.loads((root / "formal_state.schema.json").read_text("utf-8"))
    transition = json.loads((root / "transition_record.schema.json").read_text("utf-8"))
    lineage = json.loads((root / "lineage_node.schema.json").read_text("utf-8"))
    assert state["additionalProperties"] is False
    assert transition["additionalProperties"] is False
    assert lineage["additionalProperties"] is False
    assert set(transition["required"]) == set(TRANSITION_RECORDS[0].as_payload())
    assert set(lineage["required"]) == set(complete_lineage()[0].payload_without_digest()) | {"node_digest"}


def test_formal_assurance_artifact_is_signed_reproducible_and_non_authoritative(tmp_path: Path) -> None:
    first = build_artifact()
    second = build_artifact()
    assert first["payload_digest"] == second["payload_digest"]
    assert validate_artifact(first)["authority_granted"] is False
    path = tmp_path / "formal-assurance.json"
    write_artifact(path)
    assert validate_artifact(load_artifact(path))["formal_specification_digest"] == first["payload"]["formal_specification_digest"]


def test_formal_assurance_artifact_rejects_tamper() -> None:
    artifact = build_artifact()
    artifact["payload"]["authority_granted"] = True
    with pytest.raises(FormalAssuranceError):
        validate_artifact(artifact)


@pytest.mark.parametrize("record", TRANSITION_RECORDS, ids=lambda item: item.transition_identifier)
def test_every_declared_transition_is_machine_checkable(record: Any) -> None:
    source = state_at(record.source_state)
    destination = state_at(record.destination_state)
    valid, violation = verify_transition(source, destination)
    assert valid, violation
    assert set(record.as_payload()) == {
        "transition_identifier", "source_state", "destination_state",
        "required_preconditions", "required_evidence", "required_tokens",
        "required_bindings", "permitted_pipeline_modes", "failure_destination",
        "terminal_status", "authority_owner", "audit_requirement",
    }


@pytest.mark.parametrize(
    "source,destination",
    list(zip(CANONICAL_CONTROL_STATES[1:], CANONICAL_CONTROL_STATES[:-1])),
)
def test_every_reversed_canonical_transition_is_rejected(source: str, destination: str) -> None:
    valid, violation = verify_transition(state_at(source), state_at(destination))
    assert not valid
    assert violation and violation.code == "undeclared_transition"


@pytest.mark.parametrize("missing", CANONICAL_RUNTIME_ORDER[:-2])
def test_each_mandatory_runtime_stage_cannot_be_skipped(missing: str) -> None:
    history = tuple(stage for stage in CANONICAL_RUNTIME_ORDER if stage != missing)
    result = FormalArchitectureVerifier().verify(valid_state(stage_history=history))
    assert not result.valid
    assert any(item.code in {"canonical_stage_order_invalid", "pipeline_mode_missing_mandatory_layer"} for item in result.violations)


@pytest.mark.parametrize(
    "architectural_state,terminal,attestation",
    [
        ("EXECUTION_COMPLETED", "COMPLETED", {"status": "COMPLETED"}),
        ("EXECUTION_FAILED", "FAILED", {"status": "FAILED"}),
        ("EXECUTION_CANCELLED", "CANCELLED", {"status": "CANCELLED"}),
        ("EXECUTION_AMBIGUOUS", "AMBIGUOUS", {"status": "AMBIGUOUS"}),
    ],
)
def test_all_execution_terminal_outcomes_are_explicit(
    architectural_state: str, terminal: str, attestation: dict[str, str],
) -> None:
    result = FormalArchitectureVerifier().verify(valid_state(
        architectural_state=architectural_state,
        terminal_outcome=terminal,
        capability_state=terminal,
        capability_consumed=terminal == "COMPLETED",
        execution_attestation=attestation,
    ))
    assert result.valid


@pytest.mark.parametrize("component", sorted(EXTERNAL_NON_AUTHORITY_COMPONENTS))
def test_external_components_cannot_hold_runtime_authority(component: str) -> None:
    authorities = {item: () for item in EXTERNAL_NON_AUTHORITY_COMPONENTS}
    authorities[component] = ("EXECUTION",)
    result = FormalArchitectureVerifier().verify(valid_state(component_authorities=authorities))
    assert any(item.code == "external_component_has_authority" for item in result.violations)


@pytest.mark.parametrize(
    "updates,expected",
    [
        ({"state_constructor": "ADAPTER"}, "alternative_state_constructor"),
        ({"collective_attachment_count": 2}, "collective_attachment_cardinality_invalid"),
        ({"topology": "DISTRIBUTED"}, "desktop_v1_no_node_boundary_violated"),
        ({"node_count": 1}, "desktop_v1_no_node_boundary_violated"),
        ({"audit_lineage": ()}, "audit_continuity_missing"),
    ],
)
def test_core_architectural_invariants(updates: dict[str, Any], expected: str) -> None:
    result = FormalArchitectureVerifier().verify(valid_state(**updates))
    assert any(item.code == expected for item in result.violations)


@pytest.mark.parametrize(
    "field,bad_value,expected",
    [
        ("authority_first_result", "FAIL", "execution_without:authority_first_result"),
        ("procedural_truth_result", "FAIL", "execution_without:procedural_truth_result"),
        ("classification_result", "UNSET", "execution_without:classification_result"),
        ("licensing_result", "DENY", "execution_without:licensing_result"),
        ("governance_result", "DENY", "execution_without:governance_result"),
        ("grc_result", "FAIL", "execution_without:grc_result"),
        ("domain_result", "fail", "execution_without:domain_result"),
        ("aurion15_result", "fail", "execution_without:aurion15_result"),
    ],
)
def test_impossible_execution_without_upstream_clearance(field: str, bad_value: str, expected: str) -> None:
    evidence = dict(valid_state().evidence or {})
    evidence[field] = bad_value
    result = FormalArchitectureVerifier().verify(valid_state(evidence=evidence))
    assert any(item.code == expected for item in result.violations)


def test_impossible_execution_bindings_fail_closed() -> None:
    verifier = FormalArchitectureVerifier()
    cases = (
        valid_state(convergence_state="FAILED"),
        valid_state(measured_startup_status="REJECTED"),
        valid_state(tokens={}),
        valid_state(architectural_state="EXECUTION_COMPLETED", terminal_outcome="COMPLETED", execution_attestation={"x": 1}),
        valid_state(architectural_state="EXECUTION_COMPLETED", terminal_outcome="COMPLETED", capability_consumed=True, capability_cancelled=True, execution_attestation={"x": 1}),
        valid_state(architectural_state="EXECUTION_ACTIVE", capability_expired=True),
    )
    assert all(not verifier.verify(item).valid for item in cases)


def test_complete_causal_lineage_is_valid_and_deterministic() -> None:
    nodes = complete_lineage()
    assert verify_lineage(nodes) == ()
    first = FormalArchitectureVerifier().verify(valid_state(), lineage=nodes)
    second = FormalArchitectureVerifier().verify(valid_state(), lineage=nodes)
    assert first.valid and second.valid
    assert first.evidence_digest == second.evidence_digest
    assert first.lineage_digest == second.lineage_digest


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("missing", "missing_lineage_predecessor"),
        ("unknown", "unknown_lineage_predecessor"),
        ("cycle", "lineage_cycle"),
        ("fork", "lineage_fork_or_reentry"),
        ("request", "lineage_binding_mismatch:request_fingerprint"),
        ("state", "lineage_binding_mismatch:canonical_state_hash"),
        ("eie", "lineage_binding_mismatch:eie_digest"),
        ("runtime", "lineage_binding_mismatch:runtime_identity"),
        ("baseline", "lineage_binding_mismatch:measured_baseline_identity"),
        ("stale", "stale_lineage_evidence"),
        ("token", "token_transplantation"),
        ("attestation", "execution_attestation_transplantation"),
    ],
)
def test_causal_lineage_mutations_are_rejected(mutation: str, expected: str) -> None:
    nodes = list(complete_lineage())
    index = 10
    node = nodes[index]
    changes: dict[str, Any] = {}
    if mutation == "missing":
        changes["predecessor_identifiers"] = ()
    elif mutation == "unknown":
        changes["predecessor_identifiers"] = ("unknown-node",)
    elif mutation == "cycle":
        changes["predecessor_identifiers"] = (node.node_identifier,)
    elif mutation == "fork":
        changes["predecessor_identifiers"] = (nodes[index - 1].node_identifier, nodes[index - 2].node_identifier)
    elif mutation == "request":
        changes["request_fingerprint"] = generate_digest({"other": "request"})
    elif mutation == "state":
        changes["canonical_state_hash"] = generate_digest({"other": "state"})
    elif mutation == "eie":
        changes["eie_digest"] = generate_digest({"other": "eie"})
    elif mutation == "runtime":
        changes["runtime_identity"] = generate_digest({"other": "runtime"})
    elif mutation == "baseline":
        changes["measured_baseline_identity"] = "OTHER_BASELINE"
    elif mutation == "stale":
        changes["fresh"] = False
    elif mutation == "token":
        changes["token_stage"] = "WRONG_STAGE"
    elif mutation == "attestation":
        index = LINEAGE_ORDER.index("EXECUTION_ATTESTATION")
        node = nodes[index]
        changes["attested_capability_id"] = "other-capability"
    nodes[index] = replace(node, **changes, node_digest="").with_digest()
    violations = verify_lineage(nodes)
    assert any(item.code == expected for item in violations)


@pytest.mark.parametrize("failure,expected", sorted(SAFE_CONVERGENCE.items()))
def test_every_binding_failure_has_a_deterministic_safe_state(failure: str, expected: str) -> None:
    assert safe_state_for(failure) == expected
    assert safe_state_for(failure) == safe_state_for(failure)


def test_unknown_failure_converges_to_persistent_inoperability() -> None:
    assert safe_state_for("not_declared") == "PERSISTENTLY_INOPERABLE"


def test_mode1_exact_parity_and_approximate_parity_rejection() -> None:
    exact = valid_state("MODE_1_FULL_MIRRORED")
    assert FormalArchitectureVerifier().verify(exact).valid
    approximate = replace(exact, formal_flags={"approximate_convergence": True})
    assert any(item.code == "mode1_approximate_parity_rejected" for item in FormalArchitectureVerifier().verify(approximate).violations)
    mismatched = dict(exact.pipeline_b or {})
    mismatched["request_fingerprint"] = generate_digest({"mismatch": True})
    assert any(item.code == "mode1_exact_parity_required" for item in FormalArchitectureVerifier().verify(replace(exact, pipeline_b=mismatched)).violations)


def test_mode2_validator_cannot_self_authorize_or_weaken_primary() -> None:
    state = valid_state("MODE_2_SPLIT_VALIDATOR")
    assert FormalArchitectureVerifier().verify(state).valid
    for field in ("independently_authorized", "weakens_pipeline_a", "overrides_governance"):
        validator = dict(state.pipeline_b or {})
        validator[field] = True
        result = FormalArchitectureVerifier().verify(replace(state, pipeline_b=validator))
        assert not result.valid


def test_mode3_preserves_mandatory_layers_and_stronger_mode_requirement() -> None:
    assert FormalArchitectureVerifier().verify(valid_state()).valid
    assert not FormalArchitectureVerifier().verify(valid_state(stronger_mode_required=True)).valid
    assert not FormalArchitectureVerifier().verify(valid_state(formal_flags={"omitted_doctrine": ["GRC"]})).valid


def test_conservation_laws_allow_only_narrowing() -> None:
    first = valid_state()
    second = replace(
        first,
        authority_scope=("READ",), permission_scope=("inspect",), licensing_scope=("inspect",),
        constraints={"max_items": 5, "min_items": 2, "allowed_modes": ["bounded"], "requires_confirmation": True},
        classification_rank=3, consequence_tier=3, corroboration_required=3,
        audit_lineage=first.audit_lineage + (generate_digest({"audit": 2}),),
    )
    assert FormalArchitectureVerifier().verify_conservation((first, second)) == ()


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("authority", "authority_broadened"),
        ("permission", "permission_broadened"),
        ("license", "licensing_scope_broadened"),
        ("constraint", "constraints_removed_or_weakened"),
        ("denial", "denial_not_conserved"),
        ("request", "identity_or_state_not_conserved:request_fingerprint"),
        ("state", "identity_or_state_not_conserved:canonical_state_hash"),
        ("classification", "classification_silently_decreased"),
        ("tier", "consequence_tier_downgraded"),
        ("corroboration", "corroboration_requirement_reduced"),
        ("audit", "audit_lineage_rewritten"),
        ("evidence", "evidence_not_conserved:provenance"),
    ],
)
def test_conservation_law_mutations_fail(mutation: str, expected: str) -> None:
    first = valid_state()
    changes: dict[str, Any] = {}
    if mutation == "authority": changes["authority_scope"] = first.authority_scope + ("ADMIN",)
    elif mutation == "permission": changes["permission_scope"] = first.permission_scope + ("delete",)
    elif mutation == "license": changes["licensing_scope"] = first.licensing_scope + ("delete",)
    elif mutation == "constraint": changes["constraints"] = {"max_items": 20}
    elif mutation == "denial":
        first = replace(first, decision_state="DENY")
        changes["decision_state"] = "ALLOW"
    elif mutation == "request": changes["request_fingerprint"] = generate_digest({"other": 1})
    elif mutation == "state": changes["canonical_state_hash"] = generate_digest({"other": 2})
    elif mutation == "classification": changes["classification_rank"] = 1
    elif mutation == "tier": changes["consequence_tier"] = 1
    elif mutation == "corroboration": changes["corroboration_required"] = 1
    elif mutation == "audit": changes["audit_lineage"] = ()
    elif mutation == "evidence": changes["evidence"] = {**dict(first.evidence or {}), "provenance": "other"}
    violations = FormalArchitectureVerifier().verify_conservation((first, replace(first, **changes)))
    assert any(item.code == expected for item in violations)


def test_property_sequences_are_deterministic_and_fail_closed() -> None:
    rng = random.Random(917)
    verifier = FormalArchitectureVerifier()
    for _ in range(256):
        length = rng.randint(2, len(CANONICAL_CONTROL_STATES))
        legal = [state_at(name) for name in CANONICAL_CONTROL_STATES[:length]]
        assert not verifier.verify(valid_state(), transitions=legal).violations
        source = rng.choice(CANONICAL_CONTROL_STATES)
        destination = rng.choice(tuple(ARCHITECTURAL_STATES))
        if (source, destination) not in TRANSITION_INDEX:
            valid, violation = verify_transition(state_at(source), state_at(destination))
            assert not valid and violation is not None


def test_formal_digest_map_order_and_replay_are_stable() -> None:
    one = valid_state(evidence={"a": 1, "b": 2, **dict(valid_state().evidence or {})})
    two = valid_state(evidence={**dict(valid_state().evidence or {}), "b": 2, "a": 1})
    assert one.digest == two.digest
    first = replay_formal_verification(one, replay_count=3, lineage=complete_lineage())
    second = replay_formal_verification(two, replay_count=3, lineage=complete_lineage())
    assert first["matched"] and second["matched"]
    assert first["replay_digest"] == second["replay_digest"]


def test_mutation_protection_for_critical_architectural_laws() -> None:
    verifier = FormalArchitectureVerifier()
    mutations = {
        "classification_before_licensing": valid_state(stage_history=tuple(
            "licensing" if item == "classification" else "classification" if item == "licensing" else item
            for item in CANONICAL_RUNTIME_ORDER
        )),
        "governance_before_grc": valid_state(stage_history=tuple(
            "grc" if item == "governance" else "governance" if item == "grc" else item
            for item in CANONICAL_RUNTIME_ORDER
        )),
        "aurion_self_authorize": valid_state(evidence={**dict(valid_state().evidence or {}), "domain_result": "fail"}),
        "approximate_mode1": valid_state("MODE_1_FULL_MIRRORED", formal_flags={"approximate_convergence": True}),
        "h7_single_use": valid_state(architectural_state="EXECUTION_COMPLETED", terminal_outcome="COMPLETED", execution_attestation={"x": 1}),
        "cancellation": valid_state(architectural_state="EXECUTION_COMPLETED", terminal_outcome="COMPLETED", capability_consumed=True, capability_cancelled=True, execution_attestation={"x": 1}),
        "audit_omission": valid_state(audit_lineage=()),
        "external_state_construction": valid_state(state_constructor="ADAPTER"),
        "collective_before_state": valid_state(stage_history=("hard_ingress", "collective_attach", "state_construction")),
        "pt_before_root": valid_state(stage_history=("hard_ingress", "state_construction", "collective_attach", "ap_acf_precheck", "procedural_truth", "root_of_trust")),
    }
    for name, mutation in mutations.items():
        assert not verifier.verify(mutation).valid, name
    removed = dict(TRANSITION_INDEX)
    removed.pop(("CLASSIFIED", "LICENSED"))
    result = FormalArchitectureVerifier(transition_index=removed).verify(
        valid_state(), transitions=(state_at("CLASSIFIED"), state_at("LICENSED")),
    )
    assert not result.valid
    assert any(item.code == "undeclared_transition" for item in result.violations)


def test_runtime_snapshot_is_verified_without_granting_authority() -> None:
    state = run_dual_pipeline(sample_request())
    status = {
        "measured_runtime_identity": DIGESTS["runtime"],
        "approved_runtime_baseline": "DESKTOP_V1_PHQ_TEST_BASELINE",
        "runtime_measurement_digest": DIGESTS["measurement"],
        "measured_startup_status": "MEASURED_STARTUP_APPROVED",
    }
    formal = formalize_runtime_state(state, status)
    result = FormalArchitectureVerifier().verify(formal)
    assert result.valid
    assert result.authority_granted is False
    assert formal.stage_history == CANONICAL_RUNTIME_ORDER


def test_denied_runtime_snapshot_cannot_reenter_downstream() -> None:
    request = sample_request()
    request.pop("resolved_authority")
    denied = run_pipeline(request)
    assert denied["governed_state_formed"] is False
    assert denied["downstream_stage_reached"] is False
    assert denied["decision"] == "DENY"
    assert denied["execution_result"] == "HALT"
    assert denied["execution_verified"] is False
    source = state_at("DENIED", decision_state="DENY")
    destination = state_at("EXECUTION_GATE_RESOLVED", decision_state="ALLOW")
    valid, violation = verify_transition(source, destination)
    assert not valid
    assert violation and violation.safe_state == "HALTED"
