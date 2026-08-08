from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.audit.audit_finalisation import verify_audit_record
from sbp_lex.execution.controlled_outcome import verify_controlled_outcome
from sbp_lex.execution.terminal_assurance import verify_terminal_state_seal
from sbp_lex.runtime.measured_startup import ensure_measured_startup
from sbp_lex.runtime.traversal_receipt import (
    TRAVERSAL_RECEIPT_PURPOSES,
    verify_traversal_receipt,
)
from sbp_lex.security.execution_attestation import (
    MEASURED_RUNTIME_FIELDS,
    build_execution_attestation,
    build_execution_boundary_payload,
    verify_execution_attestation,
    verify_execution_boundary_token,
)
from sbp_lex.security.master_convergence_token import issue_master_convergence_token, verify_master_token
from sbp_lex.security.threshold_tokens import (
    required_threshold_token_names,
    verify_threshold_bundle,
)
from sbp_lex.security.token_stack import (
    issue_token,
    issue_token_bundle,
    verify_exact_token_bundle,
    verify_required_tokens,
    verify_token,
    verify_token_trace,
)
from sbp_lex.shared.convergence_digest import build_convergence_digest, verify_convergence_digest
from sbp_lex.shared.hash_chain import (
    append_hash_entry,
    rebuild_state_hash,
    verify_hash_chain,
    verify_success_terminal_hash_chain,
)
from sbp_lex.security.authority_boundary import (
    TOKEN_STAGE,
    validate_canonical_upstream,
    verify_canonical_stage_lineage,
)
from sbp_lex.security.domain_aurion_evidence import validate_handoff_evidence
from sbp_lex.security.pqc import generate_digest, verify_signature
from sbp_lex.shared.control_chain_validation import validate_control_chain_bindings, validate_root_anchor_binding
from sbp_lex.shared.convergence import verify_convergence_proof
from sbp_lex.shared.state_builder import validate_boundary_protection

STRICT_REQUIRED_TOKENS = [
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain",
    "aurion",
    "execution_boundary",
    "threshold_bundle",
    "token_bundle",
    "master_convergence",
    "execution_attestation",
]

UPSTREAM_GATE_TOKENS = (
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain",
    "aurion",
)
TERMINAL_SUCCESS_TOKENS = frozenset(
    {
        *UPSTREAM_GATE_TOKENS,
        *required_threshold_token_names(),
        "threshold_bundle",
        "execution_boundary",
        "token_bundle",
        "master_convergence",
        "execution_attestation",
    }
)
PRE_BUNDLE_TOKENS = frozenset(
    TERMINAL_SUCCESS_TOKENS
    - {"token_bundle", "master_convergence", "execution_attestation"}
)
SUCCESS_ONLY_TOKENS = frozenset(
    {
        "execution_boundary",
        "token_bundle",
        "master_convergence",
        "execution_attestation",
    }
)
PRE_GATE_STAGE_ORDER = [
    "hard_ingress",
    "state_construction",
    "collective_attach",
    "ap_acf_precheck",
    "root_of_trust",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain_wrap",
    "aurion_runtime",
]
AUDIT_READINESS_VERSION = "PASS7_AUDIT_READINESS_V1"
RUNTIME_BINDING_VERSION = "PASS7_EXECUTION_RUNTIME_BINDING_V1"


def _deduplicate_failures(failures: list[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in failures if str(item)))[:256]


def _strip_success_material(state: Dict[str, Any]) -> Dict[str, Any]:
    tokens = state.get("tokens")
    if isinstance(tokens, Mapping):
        state["tokens"] = {
            name: deepcopy(token)
            for name, token in tokens.items()
            if name not in SUCCESS_ONLY_TOKENS
        }
    trace = state.get("token_trace")
    if isinstance(trace, list):
        state["token_trace"] = [
            deepcopy(entry)
            for entry in trace
            if not isinstance(entry, Mapping)
            or entry.get("name") not in SUCCESS_ONLY_TOKENS
        ]
    state.pop("master_token", None)
    state.pop("execution_attestation", None)
    state.pop("execution_timestamp", None)
    state.pop("execution_convergence", None)
    state.pop("convergence_hash", None)
    return state


def _runtime_binding(
    state: Mapping[str, Any],
) -> tuple[Dict[str, Any] | None, list[str]]:
    receipt = state.get("runtime_traversal_receipt")
    if not isinstance(receipt, Mapping):
        return None, ["runtime_traversal_receipt_missing"]
    payload = receipt.get("payload")
    purpose = payload.get("purpose") if isinstance(payload, Mapping) else None
    if purpose not in TRAVERSAL_RECEIPT_PURPOSES:
        return None, ["runtime_traversal_receipt_purpose_invalid"]
    try:
        measurement = ensure_measured_startup()
    except Exception as exc:
        return None, [f"measured_startup_invalid:{type(exc).__name__}"]
    receipt_valid, receipt_failures = verify_traversal_receipt(
        receipt,
        expected_purpose=str(purpose),
        expected_request_fingerprint=str(
            state.get("request_fingerprint", "")
        ),
        current_measurement=measurement,
    )
    if not receipt_valid:
        return None, receipt_failures
    assert isinstance(payload, Mapping)
    binding: Dict[str, Any] = {
        "binding_version": RUNTIME_BINDING_VERSION,
        "receipt_digest": receipt.get("receipt_digest"),
        "receipt_purpose": purpose,
        "request_fingerprint": payload.get("request_fingerprint"),
        "runtime_id": payload.get("runtime_id"),
        "operational": purpose == "OPERATIONAL_TRAVERSAL",
        **{field: measurement.get(field) for field in MEASURED_RUNTIME_FIELDS},
    }
    if purpose == "OPERATIONAL_TRAVERSAL":
        binding.update(
            {
                "request_id": payload.get("request_id"),
                "traversal_started_event_hash": payload.get(
                    "traversal_started_event_hash"
                ),
                "traversal_started_sequence": payload.get(
                    "traversal_started_sequence"
                ),
            }
        )
    return binding, []


def _build_audit_readiness(state: Mapping[str, Any]) -> Dict[str, Any]:
    chain = state.get("hash_chain", [])
    trace = state.get("audit_trace", [])
    payload = {
        "readiness_version": AUDIT_READINESS_VERSION,
        "ready": True,
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "gate_input_state_hash": state.get("state_hash"),
        "pre_gate_chain_tail": (
            chain[-1].get("hash")
            if isinstance(chain, list)
            and chain
            and isinstance(chain[-1], Mapping)
            else None
        ),
        "audit_trace_digest": generate_digest(trace),
        "expected_terminal_stage": "audit",
        "authority_role": "evidence_only_non_authoritative",
    }
    return {**payload, "readiness_digest": generate_digest(payload)}


def _verify_audit_readiness(
    state: Mapping[str, Any],
    *,
    expected_gate_input_state_hash: str | None = None,
) -> bool:
    readiness = state.get("audit_readiness")
    if not isinstance(readiness, Mapping):
        return False
    payload = {
        key: deepcopy(value)
        for key, value in readiness.items()
        if key != "readiness_digest"
    }
    if set(payload) != {
        "readiness_version",
        "ready",
        "request_fingerprint",
        "eie_digest",
        "gate_input_state_hash",
        "pre_gate_chain_tail",
        "audit_trace_digest",
        "expected_terminal_stage",
        "authority_role",
    }:
        return False
    boundary = state.get("tokens", {}).get("execution_boundary", {})
    boundary_payload = (
        boundary.get("payload", {}) if isinstance(boundary, Mapping) else {}
    )
    return (
        readiness.get("readiness_digest") == generate_digest(payload)
        and payload.get("readiness_version") == AUDIT_READINESS_VERSION
        and payload.get("ready") is True
        and payload.get("request_fingerprint")
        == state.get("request_fingerprint")
        and payload.get("eie_digest") == state.get("eie_hash")
        and (
            expected_gate_input_state_hash is None
            or payload.get("gate_input_state_hash")
            == expected_gate_input_state_hash
        )
        and payload.get("expected_terminal_stage") == "audit"
        and payload.get("authority_role")
        == "evidence_only_non_authoritative"
        and payload.get("pre_gate_chain_tail")
        == boundary_payload.get("pre_gate_chain_tail")
        and generate_digest(dict(readiness))
        == boundary_payload.get("audit_readiness_digest")
    )


def _provider_failures(state: Mapping[str, Any]) -> list[str]:
    references = state.get("verified_substrate_references")
    if not isinstance(references, Mapping):
        return ["desktop_provider_evidence_missing"]
    failures: list[str] = []
    expected = {
        "provider_mode": "synthetic_local",
        "authority_role": "context_only_non_authoritative",
        "raw_packages_crossed_hard_entry": False,
        "direct_state_write": False,
        "skg_validation_status": "VALID",
        "dtn_validation_status": "VALID",
        "bridge_validation_status": "PASS",
    }
    for field, value in expected.items():
        if references.get(field) != value:
            failures.append(f"desktop_provider_binding_invalid:{field}")
    if references.get("runtime") not in {
        "DESKTOP_V1_SYNTHETIC_EXTERNAL_SUBSTRATES",
        "DESKTOP_V1_SIGNED_LOCAL_CONTEXT",
    }:
        failures.append("desktop_provider_runtime_invalid")
    return failures


def _gate_entry_failures(state: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for field, expected_type in (
        ("tokens", Mapping),
        ("token_trace", list),
        ("hash_chain", list),
        ("audit_trace", list),
        ("safety_profile", Mapping),
        ("collective_attachment", Mapping),
        ("verified_substrate_references", Mapping),
    ):
        if not isinstance(state.get(field), expected_type):
            failures.append(f"gate_input_container_invalid:{field}")
    if failures:
        return failures
    if state.get("integration_stage_order") != PRE_GATE_STAGE_ORDER:
        failures.append("execution_gate_entry_stage_order_invalid")
    if any(
        entry.get("stage") in {"execution_gate", "audit", "controlled_return"}
        for entry in state.get("hash_chain", [])
        if isinstance(entry, Mapping)
    ):
        failures.append("execution_gate_reentry_detected")
    if any(name in state.get("tokens", {}) for name in SUCCESS_ONLY_TOKENS):
        failures.append("execution_gate_terminal_token_preexists")
    for field in (
        "execution_attestation",
        "master_token",
        "controlled_outcome",
        "final_outcome",
        "terminal_state_seal",
    ):
        if state.get(field) not in (None, {}, ""):
            failures.append(f"execution_gate_terminal_field_preexists:{field}")
    if state.get("audit_record") not in (None, {}):
        failures.append("execution_gate_audit_preexists")
    if state.get("audit_hash") not in (None, ""):
        failures.append("execution_gate_audit_hash_preexists")
    if state.get("decision") not in {None, "UNSET"}:
        failures.append("execution_gate_decision_preexists")
    if state.get("execution_result") not in {None, "UNSET"}:
        failures.append("execution_gate_result_preexists")
    expected_pre_gate_tokens = set(PRE_BUNDLE_TOKENS) - {
        "execution_boundary"
    }
    if set(state.get("tokens", {})) != expected_pre_gate_tokens:
        failures.append("execution_gate_pre_token_set_invalid")
    trace_ok, trace_failures = verify_token_trace(
        state, expected_names=expected_pre_gate_tokens, exact=True
    )
    if not trace_ok:
        failures.extend(trace_failures)
    return failures


def _deterministic_execution_timestamp(state: Mapping[str, Any]) -> str:
    return f"EXECUTION_EVENT_{len(state.get('hash_chain', [])) + len(state.get('token_trace', [])) + 1:012d}"


def _apply_fail_closed(state: Dict[str, Any], failures: list[str]) -> Dict[str, Any]:
    state["execution_result"] = "HALT"
    state["decision"] = "DENY"
    state["execution_verified"] = False
    state["execution_reason"] = ",".join(str(f) for f in failures) if failures else "fail_closed"
    state["token_stack_valid"] = False
    state["token_verification_failures"] = failures
    state.setdefault("convergence_hash", state.get("state_hash"))
    state["effect_phase"] = "NOT_AUTHORISED"
    state["effect_confirmed_success"] = False
    return state


def _run_execution_gate(state: Mapping[str, Any]) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    failures: list[str] = _gate_entry_failures(working_state)
    failures.extend(_provider_failures(working_state))
    upstream_valid, upstream_failures = validate_canonical_upstream(
        working_state,
        required_tokens=(
            "authority",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
            "domain",
            "aurion",
        ),
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    control_chain_valid, control_chain_failures = validate_control_chain_bindings(working_state)
    if not control_chain_valid:
        failures.extend(control_chain_failures)
    root_valid, root_failures = validate_root_anchor_binding(working_state)
    if not root_valid:
        failures.extend(root_failures)
    boundary_valid, boundary_failures = validate_boundary_protection(
        working_state
    )
    if not boundary_valid:
        failures.extend(boundary_failures)
    handoff_valid, handoff_failures = validate_handoff_evidence(
        working_state
    )
    if not handoff_valid:
        failures.extend(handoff_failures)

    if not verify_hash_chain(working_state):
        failures.append("hash_chain_invalid")
    if working_state.get("state_hash") != rebuild_state_hash(working_state):
        failures.append("state_hash_mismatch")
    request_fingerprint = working_state.get("request_fingerprint")
    if not request_fingerprint or any(
        entry.get("request_fingerprint") != request_fingerprint
        for entry in working_state.get("hash_chain", [])
    ):
        failures.append("request_fingerprint_mismatch")
    if working_state.get("authority_first_result") != "PASS":
        failures.append("authority_not_pass")
    if working_state.get("procedural_truth_result") != "PASS":
        failures.append("procedural_truth_not_pass")
    if working_state.get("procedural_truth_outcome") != "PT_PASS":
        failures.append("procedural_truth_outcome_mismatch")
    certification = working_state.get("procedural_truth_certification", {})
    if not isinstance(certification, Mapping):
        failures.append("procedural_truth_certification_missing")
        certification = {}
    if certification.get("procedural_truth_status") != "PASS":
        failures.append("procedural_truth_status_not_pass")
    if certification.get("certification_status") != "CERTIFIED":
        failures.append("procedural_truth_not_certified")
    if certification.get("root_of_trust_anchorage_status") != "VALID":
        failures.append("root_of_trust_anchorage_invalid")
    if certification.get("skg_verification_status") != "VALID":
        failures.append("skg_verification_invalid")
    if certification.get("dtn_contextualisation_status") != "VALID":
        failures.append("dtn_contextualisation_invalid")
    if certification.get("eie_hash") != working_state.get("eie_hash"):
        failures.append("procedural_truth_eie_hash_mismatch")
    pt_token_for_state = working_state.get("tokens", {}).get("procedural_truth", {})
    if certification.get("state_hash") != pt_token_for_state.get("state_hash"):
        failures.append("procedural_truth_state_hash_mismatch")
    if certification.get("request_fingerprint") != working_state.get("request_fingerprint"):
        failures.append("procedural_truth_request_fingerprint_mismatch")
    if certification.get("traversal_id") != working_state.get("traversal_id"):
        failures.append("procedural_truth_traversal_id_mismatch")
    if certification.get("pt_token_required") is True:
        pt_token = working_state.get("tokens", {}).get("procedural_truth", {})
        if not isinstance(pt_token, Mapping) or not pt_token.get("digest"):
            failures.append("procedural_truth_token_missing")
        elif certification.get("pt_token_hash") != pt_token.get("digest"):
            failures.append("procedural_truth_token_hash_mismatch")
    required_sufficiency = [
        "source_floor_met",
        "independence_met",
        "provenance_met",
        "integrity_met",
        "attestation_met",
        "authority_met",
        "jurisdiction_met",
        "freshness_met",
        "consistency_met",
        "runtime_validity_met",
        "consequence_burden_met",
    ]
    for field in required_sufficiency:
        if certification.get(field) is not True:
            failures.append(f"procedural_truth_{field}_false")
    if certification.get("unresolved_contradictions") is True:
        failures.append("procedural_truth_unresolved_contradiction")
    if working_state.get("corroboration_met") is not True:
        failures.append("corroboration_threshold_not_met")
    if working_state.get("classification_result") != "ALLOW":
        failures.append("classification_not_allow")
    if working_state.get("licensing_result") != "ALLOW":
        failures.append("licensing_not_allow")
    if working_state.get("governance_result") != "ALLOW":
        failures.append("governance_not_allow")
    if working_state.get("grc_result") != "PASS":
        failures.append("grc_not_pass")
    if working_state.get("domain_result") != "pass":
        failures.append("domain_not_pass")
    if working_state.get("aurion15_result") != "pass":
        failures.append("aurion_not_pass")

    threshold_ok, threshold_failures = verify_threshold_bundle(working_state)
    if not threshold_ok:
        failures.extend(threshold_failures)
    runtime_binding, runtime_failures = _runtime_binding(working_state)
    if runtime_binding is None:
        failures.extend(runtime_failures)

    failures = _deduplicate_failures(failures)
    if failures:
        working_state = _strip_success_material(working_state)
        working_state["effect_phase"] = "NOT_AUTHORISED"
        working_state = _apply_fail_closed(working_state, failures)
        return append_hash_entry(
            working_state,
            stage="execution_gate",
            payload={
                "execution_result": "HALT",
                "decision": "DENY",
                "failures": failures,
            },
        )

    assert runtime_binding is not None
    gate_input_state_hash = str(working_state.get("state_hash", ""))
    working_state["execution_runtime_binding"] = runtime_binding
    working_state["audit_readiness"] = _build_audit_readiness(working_state)
    working_state["effect_phase"] = "AUTHORISED_TO_ATTEMPT"
    working_state["effect_confirmed_success"] = False
    working_state["state_hash"] = rebuild_state_hash(working_state)

    boundary_payload, boundary_payload_failures = (
        build_execution_boundary_payload(working_state)
    )
    if boundary_payload is None:
        failures.extend(boundary_payload_failures)
    else:
        working_state = issue_token(
            working_state,
            name="execution_boundary",
            issued_at_stage="execution_gate",
            payload=boundary_payload,
        )
        boundary_ok, boundary_failures = verify_execution_boundary_token(
            working_state, require_live_state_hash=True
        )
        if not boundary_ok:
            failures.extend(boundary_failures)
        if not _verify_audit_readiness(
            working_state,
            expected_gate_input_state_hash=gate_input_state_hash,
        ):
            failures.append("audit_readiness_invalid")

    if not failures:
        working_state = issue_token_bundle(
            working_state, issued_at_stage="execution_gate"
        )
        bundle_ok, bundle_failures = verify_exact_token_bundle(
            working_state,
            expected_names=PRE_BUNDLE_TOKENS,
            expected_stage="execution_gate",
        )
        if not bundle_ok:
            failures.extend(bundle_failures)

    pre_master_required = sorted(
        PRE_BUNDLE_TOKENS | {"token_bundle"}
    )
    token_ok, token_failures = verify_required_tokens(
        working_state, required=pre_master_required
    )
    if not token_ok:
        failures.extend(token_failures)

    if not failures:
        working_state["execution_result"] = "EXECUTE"
        working_state["decision"] = "ALLOW"
        working_state["execution_verified"] = True
        working_state["execution_reason"] = "execution_converged"
        working_state["token_stack_valid"] = True
        working_state["token_verification_failures"] = []

        convergence_digest = build_convergence_digest(working_state)
        working_state["convergence_hash"] = convergence_digest.get(
            "convergence_hash"
        )
        working_state["execution_convergence"] = convergence_digest
        if not verify_convergence_digest(working_state, convergence_digest):
            failures.append("convergence_digest_invalid")

    if not failures:
        working_state = issue_master_convergence_token(
            working_state, issued_at_stage="execution_gate"
        )
        if not verify_master_token(working_state):
            failures.append("master_convergence_invalid")

    if not failures:
        working_state["execution_timestamp"] = (
            _deterministic_execution_timestamp(working_state)
        )
        attestation = build_execution_attestation(working_state)
        working_state["execution_attestation"] = attestation
        if not attestation.get("valid") or not verify_execution_attestation(
            working_state, attestation
        ):
            failures.append("execution_attestation_invalid")
        else:
            working_state = issue_token(
                working_state,
                name="execution_attestation",
                issued_at_stage="execution_gate",
                payload=attestation,
            )

    if not failures:
        final_ok, final_failures = verify_required_tokens(
            working_state, required=sorted(TERMINAL_SUCCESS_TOKENS)
        )
        if not final_ok:
            failures.extend(final_failures)
        trace_ok, trace_failures = verify_token_trace(
            working_state,
            expected_names=TERMINAL_SUCCESS_TOKENS,
            exact=True,
        )
        if not trace_ok:
            failures.extend(trace_failures)

    failures = _deduplicate_failures(failures)
    if failures:
        working_state = _strip_success_material(working_state)
        working_state["effect_phase"] = "NOT_AUTHORISED"
        working_state = _apply_fail_closed(working_state, failures)
    else:
        working_state["token_stack_valid"] = True
        working_state["token_verification_failures"] = []

    return append_hash_entry(
        working_state,
        stage="execution_gate",
        payload={
            "execution_result": working_state["execution_result"],
            "decision": working_state["decision"],
            "failures": failures,
        },
    )


def run_execution_gate(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Public fail-closed Gate boundary; malformed input never escapes as success."""

    try:
        if not isinstance(state, Mapping):
            raise TypeError("execution_gate_state_mapping_required")
        return _run_execution_gate(state)
    except Exception as exc:
        working_state = (
            deepcopy(dict(state)) if isinstance(state, Mapping) else {}
        )
        failure = f"execution_gate_terminal_exception:{type(exc).__name__}"
        working_state = _strip_success_material(working_state)
        working_state = _apply_fail_closed(working_state, [failure])
        try:
            if verify_hash_chain(working_state):
                return append_hash_entry(
                    working_state,
                    stage="execution_gate",
                    payload={
                        "execution_result": "HALT",
                        "decision": "DENY",
                        "failures": [failure],
                    },
                )
        except Exception:
            pass
        return working_state


def _evaluate_strict_execution_security(state: Mapping[str, Any]) -> Dict[str, Any]:
    failures: list[str] = []
    if not isinstance(state, Mapping):
        return {
            "valid": False,
            "allowed": False,
            "failures": ["terminal_state_mapping_required"],
        }
    failures.extend(_provider_failures(state))
    protected_valid, protected_failures = validate_boundary_protection(state)
    if not protected_valid:
        failures.extend(protected_failures)
    if not verify_hash_chain(state):
        failures.append("hash_chain_invalid")
    terminal_chain_ok, terminal_chain_failures = (
        verify_success_terminal_hash_chain(state)
    )
    if not terminal_chain_ok:
        failures.extend(terminal_chain_failures)
    upstream_valid, upstream_failures = validate_canonical_upstream(
        state,
        required_tokens=(
            "authority",
            "procedural_truth",
            "classification",
            "licensing",
            "governance",
            "grc",
            "domain",
            "aurion",
        ),
    )
    if not upstream_valid:
        failures.extend(upstream_failures)
    control_chain_valid, control_chain_failures = validate_control_chain_bindings(state)
    if not control_chain_valid:
        failures.extend(control_chain_failures)
    handoff_valid, handoff_failures = validate_handoff_evidence(state)
    if not handoff_valid:
        failures.extend(handoff_failures)
    stage_valid, stage_failures = verify_canonical_stage_lineage(
        state, required_tokens=("execution_attestation",)
    )
    if not stage_valid:
        failures.extend(stage_failures)

    if state.get("procedural_truth_result") != "PASS":
        failures.append("procedural_truth_not_pass")
    if state.get("procedural_truth_outcome") != "PT_PASS":
        failures.append("procedural_truth_outcome_mismatch")
    certification = state.get("procedural_truth_certification", {})
    if not isinstance(certification, Mapping):
        failures.append("procedural_truth_certification_missing")
        certification = {}
    if certification.get("procedural_truth_status") != "PASS":
        failures.append("procedural_truth_status_not_pass")
    if certification.get("certification_status") != "CERTIFIED":
        failures.append("procedural_truth_not_certified")
    if certification.get("pt_token_required") is True:
        pt_token = state.get("tokens", {}).get("procedural_truth", {})
        if not isinstance(pt_token, Mapping) or certification.get("pt_token_hash") != pt_token.get("digest"):
            failures.append("procedural_truth_token_hash_mismatch")
    if certification.get("unresolved_contradictions") is True:
        failures.append("procedural_truth_unresolved_contradiction")
    for field in (
        "source_floor_met",
        "independence_met",
        "provenance_met",
        "integrity_met",
        "attestation_met",
        "authority_met",
        "jurisdiction_met",
        "freshness_met",
        "consistency_met",
        "runtime_validity_met",
        "consequence_burden_met",
    ):
        if certification.get(field) is not True:
            failures.append(f"procedural_truth_{field}_false")
    if state.get("corroboration_met") is not True:
        failures.append("corroboration_threshold_not_met")
    for field, expected, failure in (
        ("authority_first_result", "PASS", "authority_not_pass"),
        ("classification_result", "ALLOW", "classification_not_allow"),
        ("licensing_result", "ALLOW", "licensing_not_allow"),
        ("governance_result", "ALLOW", "governance_not_allow"),
        ("grc_result", "PASS", "grc_not_pass"),
        ("domain_result", "pass", "domain_not_pass"),
        ("aurion15_result", "pass", "aurion_not_pass"),
    ):
        if state.get(field) != expected:
            failures.append(failure)
    if state.get("decision") == "ALLOW" and state.get("execution_result") != "EXECUTE":
        failures.append("allow_without_execute")
    if state.get("execution_result") == "EXECUTE" and state.get("execution_verified") is not True:
        failures.append("execute_without_verified")
    if state.get("execution_result") == "EXECUTE" and state.get("token_stack_valid") is not True:
        failures.append("execute_without_valid_token_stack")
    if state.get("token_verification_failures"):
        failures.append("token_failures_present")

    token_ok, token_failures = verify_required_tokens(
        state, required=sorted(TERMINAL_SUCCESS_TOKENS)
    )
    if not token_ok:
        failures.extend(token_failures)
    tokens = state.get("tokens", {})
    if not isinstance(tokens, Mapping) or set(tokens) != set(
        TERMINAL_SUCCESS_TOKENS
    ):
        failures.append("terminal_token_set_invalid")
        tokens = {}
    trace_ok, trace_failures = verify_token_trace(
        state, expected_names=TERMINAL_SUCCESS_TOKENS, exact=True
    )
    if not trace_ok:
        failures.extend(trace_failures)

    tier = (
        state.get("safety_profile", {}).get("computed_tier")
        if isinstance(state.get("safety_profile"), Mapping)
        else None
    )
    historical_gate_hash = (
        tokens.get("execution_boundary", {}).get("state_hash")
        if isinstance(tokens.get("execution_boundary"), Mapping)
        else None
    )
    for name in TERMINAL_SUCCESS_TOKENS:
        token = tokens.get(name)
        expected_stage = (
            "procedural_truth"
            if name in set(required_threshold_token_names())
            or name == "threshold_bundle"
            else (
                "execution_gate"
                if name in {"token_bundle", "master_convergence"}
                else TOKEN_STAGE.get(name)
            )
        )
        token_expectations = {
            "expected_request_fingerprint": state.get(
                "request_fingerprint"
            ),
            "expected_name": name,
            "expected_stage": expected_stage,
        }
        # Authority is issued before Procedural Truth computes the terminal
        # consequence tier.  Its signed historical tier is validated by the
        # Root-of-Trust lineage; all later tokens bind the terminal tier.
        if name != "authority":
            token_expectations["expected_tier"] = tier
        if not verify_token(token, **token_expectations):
            failures.append(f"terminal_token_binding_invalid:{name}")

    boundary_ok, boundary_failures = verify_execution_boundary_token(state)
    if not boundary_ok:
        failures.extend(boundary_failures)
    bundle_ok, bundle_failures = verify_exact_token_bundle(
        state,
        expected_names=PRE_BUNDLE_TOKENS,
        expected_stage="execution_gate",
    )
    if not bundle_ok:
        failures.extend(bundle_failures)

    threshold_ok, threshold_failures = verify_threshold_bundle(state)
    if not threshold_ok:
        failures.extend(threshold_failures)

    if not verify_master_token(state):
        failures.append("master_convergence_invalid")

    if not verify_execution_attestation(state, state.get("execution_attestation", {})):
        failures.append("execution_attestation_invalid")
    attestation_token = tokens.get("execution_attestation", {})
    if (
        not isinstance(attestation_token, Mapping)
        or attestation_token.get("payload")
        != state.get("execution_attestation")
    ):
        failures.append("execution_attestation_token_payload_mismatch")
    for name in (
        "execution_boundary",
        "token_bundle",
        "master_convergence",
        "execution_attestation",
    ):
        token = tokens.get(name, {})
        if (
            not isinstance(token, Mapping)
            or token.get("state_hash") != historical_gate_hash
        ):
            failures.append(f"terminal_token_state_hash_mismatch:{name}")

    convergence_record = state.get("execution_convergence", {})
    convergence_payload = convergence_record.get("payload", {}) if isinstance(convergence_record, Mapping) else {}
    if not isinstance(convergence_payload, Mapping):
        failures.append("convergence_digest_invalid")
    else:
        boundary_payload = (
            tokens.get("execution_boundary", {}).get("payload", {})
            if isinstance(tokens.get("execution_boundary"), Mapping)
            else {}
        )
        expected_convergence = {
            "request_fingerprint": state.get("request_fingerprint"),
            "state_hash": historical_gate_hash,
            "classification_result": state.get("classification_result"),
            "licensing_result": state.get("licensing_result"),
            "governance_result": state.get("governance_result"),
            "domain_result": state.get("domain_result"),
            "aurion15_result": state.get("aurion15_result"),
            "execution_result": state.get("execution_result"),
            "decision": state.get("decision"),
            "threshold_bundle_hash": tokens.get(
                "threshold_bundle", {}
            ).get("digest"),
            "token_bundle_hash": tokens.get("token_bundle", {}).get(
                "digest"
            ),
            "hash_chain_tail": boundary_payload.get(
                "pre_gate_chain_tail"
            ),
        }
        if dict(convergence_payload) != expected_convergence:
            failures.append("convergence_digest_invalid")
        elif convergence_record.get("convergence_hash") != generate_digest(
            convergence_payload
        ):
            failures.append("convergence_digest_invalid")
        elif not verify_signature(
            convergence_payload, convergence_record.get("signature", {})
        ):
            failures.append("convergence_digest_invalid")

    audit_record = state.get("audit_record")
    if not verify_audit_record(audit_record):
        failures.append("audit_record_invalid")
        audit_payload: Mapping[str, Any] = {}
    else:
        assert isinstance(audit_record, Mapping)
        audit_payload = audit_record.get("payload", {})
        if state.get("audit_hash") != audit_record.get("audit_hash"):
            failures.append("audit_hash_mismatch")
        expected_audit_values = {
            "request_fingerprint": state.get("request_fingerprint"),
            "decision": state.get("decision"),
            "execution_verified": state.get("execution_verified"),
            "convergence_hash": state.get("convergence_hash"),
            "pipeline_mode": state.get("pipeline_mode"),
        }
        for field, value in expected_audit_values.items():
            if audit_payload.get(field) != value:
                failures.append(f"audit_binding_mismatch:{field}")
        integration = audit_payload.get("integration_evidence", {})
        if not isinstance(integration, Mapping):
            failures.append("audit_integration_evidence_invalid")
        else:
            if integration.get("governance_result") != "ALLOW":
                failures.append("audit_governance_binding_invalid")
            if integration.get("token_stack_valid") is not True:
                failures.append("audit_token_stack_binding_invalid")
            if integration.get("hash_chain_valid_at_audit") is not True:
                failures.append("audit_hash_chain_binding_invalid")
            if integration.get("token_verification_failures") != []:
                failures.append("audit_token_failure_binding_invalid")
            if integration.get("execution_runtime_binding") != state.get(
                "execution_runtime_binding"
            ):
                failures.append("audit_runtime_binding_invalid")
            if integration.get("audit_readiness") != state.get(
                "audit_readiness"
            ):
                failures.append("audit_readiness_binding_invalid")
            eie_identity = integration.get("eie_identity", {})
            if (
                not isinstance(eie_identity, Mapping)
                or eie_identity.get("traversal_id")
                != state.get("traversal_id")
                or eie_identity.get("eie_digest") != state.get("eie_hash")
            ):
                failures.append("audit_eie_binding_invalid")
            if integration.get("execution_boundary_digest") != tokens.get(
                "execution_boundary", {}
            ).get("digest"):
                failures.append("audit_execution_boundary_binding_invalid")

    if state.get("audit_finalisation") != {
        "audit_complete": True,
        "audit_locked": True,
        "audit_verified": True,
    }:
        failures.append("audit_finalisation_invalid")

    controlled_outcome = state.get("controlled_outcome")
    if not verify_controlled_outcome(controlled_outcome):
        failures.append("controlled_outcome_invalid")
    else:
        assert isinstance(controlled_outcome, Mapping)
        outcome_payload = controlled_outcome.get("payload", {})
        expected_outcome_values = {
            "request_fingerprint": state.get("request_fingerprint"),
            "audit_hash": state.get("audit_hash"),
            "convergence_hash": state.get("convergence_hash"),
            "decision": state.get("decision"),
            "execution_verified": state.get("execution_verified"),
            "pipeline_mode": state.get("pipeline_mode"),
            "operational_state": state.get("operational_state"),
            "persistent_inoperability": state.get(
                "persistent_inoperability"
            ),
            "governed_reentry": state.get("governed_reentry", {}),
        }
        for field, value in expected_outcome_values.items():
            if outcome_payload.get(field) != value:
                failures.append(f"controlled_outcome_binding_mismatch:{field}")

    if state.get("final_outcome") != {
        "allowed": True,
        "decision": "ALLOW",
        "outcome_locked": True,
    }:
        failures.append("final_outcome_invalid")

    if not _verify_audit_readiness(state):
        failures.append("audit_readiness_invalid")

    receipt = state.get("runtime_traversal_receipt")
    receipt_payload = (
        receipt.get("payload", {}) if isinstance(receipt, Mapping) else {}
    )
    receipt_purpose = (
        receipt_payload.get("purpose")
        if isinstance(receipt_payload, Mapping)
        else None
    )
    if receipt_purpose not in TRAVERSAL_RECEIPT_PURPOSES:
        failures.append("runtime_traversal_receipt_purpose_invalid")
    else:
        receipt_ok, receipt_failures = verify_traversal_receipt(
            receipt,
            expected_purpose=str(receipt_purpose),
            expected_request_fingerprint=str(
                state.get("request_fingerprint", "")
            ),
        )
        if not receipt_ok:
            failures.extend(receipt_failures)
    expected_runtime_binding, runtime_failures = _runtime_binding(state)
    if expected_runtime_binding is None:
        failures.extend(runtime_failures)
    elif state.get("execution_runtime_binding") != expected_runtime_binding:
        failures.append("execution_runtime_binding_invalid")

    convergence = state.get("pipeline_convergence")
    if (
        not isinstance(convergence, Mapping)
        or not verify_convergence_proof(convergence)
        or convergence.get("matched") is not True
        or convergence.get("verified") is not True
        or convergence.get("mode") != state.get("pipeline_mode")
    ):
        failures.append("pipeline_convergence_invalid")

    seal_ok, seal_failures = verify_terminal_state_seal(
        state,
        state.get("terminal_state_seal"),
        expected_receipt_purpose=(
            str(receipt_purpose)
            if receipt_purpose in TRAVERSAL_RECEIPT_PURPOSES
            else None
        ),
    )
    if not seal_ok:
        failures.extend(seal_failures)

    expected_effect_phase = (
        "AUTHORISED_TO_ATTEMPT"
        if receipt_purpose == "OPERATIONAL_TRAVERSAL"
        else "NOT_AUTHORISED"
    )
    if state.get("effect_phase") != expected_effect_phase:
        failures.append("effect_phase_invalid")
    if state.get("effect_confirmed_success") is not False:
        failures.append("effect_success_reported_before_effect")
    operationally_eligible = (
        receipt_purpose == "OPERATIONAL_TRAVERSAL"
        and state.get("effect_authority_eligible") is True
    )
    if receipt_purpose == "OPERATIONAL_TRAVERSAL" and not operationally_eligible:
        failures.append("effect_authority_eligibility_invalid")
    if receipt_purpose != "OPERATIONAL_TRAVERSAL" and state.get(
        "effect_authority_eligible"
    ) is not False:
        failures.append("non_operational_state_effect_authority_present")

    final_failures = _deduplicate_failures(failures)
    return {
        "valid": len(final_failures) == 0,
        "allowed": (
            len(final_failures) == 0
            and state.get("decision") == "ALLOW"
            and operationally_eligible
        ),
        "failures": final_failures,
    }


def evaluate_strict_execution_security(
    state: Mapping[str, Any],
) -> Dict[str, Any]:
    """Non-raising terminal validator used before any effect authority."""

    try:
        return _evaluate_strict_execution_security(state)
    except Exception as exc:
        return {
            "valid": False,
            "allowed": False,
            "failures": [
                f"terminal_security_exception:{type(exc).__name__}"
            ],
        }


def evaluate_execution_gate(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    state = run_execution_gate(execution_state)
    return {
        "allowed": state.get("execution_result") == "EXECUTE",
        "decision": state.get("decision"),
        "failures": state.get("token_verification_failures", []),
    }


def validate_execution_integrity(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    security = evaluate_strict_execution_security(execution_state)
    return {
        "valid": security["valid"],
        "failures": security["failures"],
    }


def enforce_execution_boundary(execution_state: Mapping[str, Any]) -> Dict[str, Any]:
    security = evaluate_strict_execution_security(execution_state)
    if not security["allowed"]:
        return {
            "allowed": False,
            "decision": "DENY",
            "boundary_locked": True,
            "failures": security["failures"],
        }
    return {
        "allowed": True,
        "decision": "ALLOW",
        "boundary_locked": False,
        "failures": [],
    }
