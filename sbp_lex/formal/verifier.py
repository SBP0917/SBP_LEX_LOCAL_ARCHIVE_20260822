from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from sbp_lex.execution.capability import (
    STATES as H7_CAPABILITY_STATES,
    TERMINAL_STATES as H7_TERMINAL_STATES,
    TRANSITIONS as H7_TRANSITIONS,
    constraints_preserved,
    verify_capability,
    verify_post_execution_attestation,
)
from sbp_lex.execution.terminal_assurance import verify_terminal_state_seal
from sbp_lex.formal.model import (
    ARCHITECTURAL_STATES,
    AUTHORITY_CAPABILITIES,
    CANONICAL_CONTROL_STATES,
    CONVERGENCE_STATES,
    DECISION_STATES,
    EXTERNAL_NON_AUTHORITY_COMPONENTS,
    FORMAL_EVIDENCE_VERSION,
    FORMAL_MODEL_VERSION,
    FORMAL_STATE_FIELDS,
    PIPELINE_MODES,
    REQUIRED_TOKEN_NAMES,
    SAFE_TERMINAL_STATES,
    TERMINAL_OUTCOMES,
    TRANSITION_INDEX,
    FormalState,
    LineageNode,
    TransitionRecord,
    formal_state_from_mapping,
)
from sbp_lex.runtime.measured_startup import MeasuredStartupError, ensure_measured_startup
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

ASSURANCE_OWNER = "SBP_LEX_DESKTOP_V1_DETACHED_FORMAL_ASSURANCE"
ASSURANCE_DOMAIN = "SBP_LEX_DESKTOP_V1_PHQ_FORMAL_ASSURANCE"

RUNTIME_STAGE_TO_FORMAL = {
    "hard_ingress": "HARD_ENTRY_ACCEPTED",
    "state_construction": "CANONICAL_STATE_CONSTRUCTED",
    "collective_attach": "COLLECTIVE_SIGNALS_ATTACHED",
    "root_of_trust": "ROOT_OF_TRUST_ESTABLISHED",
    "procedural_truth": "PROCEDURAL_TRUTH_CERTIFIED",
    "classification": "CLASSIFIED",
    "licensing": "LICENSED",
    "governance": "GOVERNANCE_RESOLVED",
    "grc": "GRC_RESOLVED",
    "domain_wrap": "DOMAIN_RESOLVED",
    "aurion_runtime": "AURION_RESOLVED",
    "execution_gate": "EXECUTION_GATE_RESOLVED",
}

CANONICAL_RUNTIME_ORDER = (
    "hard_ingress", "state_construction", "collective_attach", "ap_acf_precheck",
    "root_of_trust", "procedural_truth", "classification", "licensing",
    "governance", "grc", "domain_wrap", "aurion_runtime", "execution_gate",
    "audit", "controlled_return",
)

LINEAGE_ORDER = (
    "EXTERNAL_REQUEST", "NATIVE_PROTOCOL", "ADAPTER_TRANSLATION", "EIE", "SKG_PACKAGE",
    "DTN_PACKAGE", "HARD_ENTRY", "CANONICAL_STATE", "COLLECTIVE_ATTACHMENT",
    "ROOT_OF_TRUST", "PROCEDURAL_TRUTH", "CLASSIFICATION", "LICENSING",
    "GOVERNANCE", "GRC", "DOMAIN", "AURION", "EXECUTION_GATE", "H7_CAPABILITY",
    "EXECUTION_RESULT", "EXECUTION_ATTESTATION", "AUDIT",
)

SAFE_CONVERGENCE = {
    "invalid_native_protocol": "DENIED",
    "invalid_adapter_translation": "DENIED",
    "invalid_eie": "DENIED",
    "invalid_skg_package": "DENIED",
    "invalid_dtn_package": "DENIED",
    "hard_entry_failure": "DENIED",
    "state_construction_failure": "HALTED",
    "collective_attachment_failure": "HALTED",
    "root_of_trust_failure": "DENIED",
    "procedural_truth_failure": "DENIED",
    "classification_failure": "DENIED",
    "licensing_failure": "DENIED",
    "governance_denied": "DENIED",
    "grc_failure": "HALTED",
    "domain_failure": "DENIED",
    "aurion_failure": "HALTED",
    "convergence_failure": "PERSISTENTLY_INOPERABLE",
    "execution_gate_failure": "PERSISTENTLY_INOPERABLE",
    "invalid_h7_capability": "HALTED",
    "mid_execution_invalidation": "EXECUTION_FAILED",
    "ambiguous_completion": "EXECUTION_AMBIGUOUS",
    "audit_continuity_failure": "PERSISTENTLY_INOPERABLE",
    "unknown": "PERSISTENTLY_INOPERABLE",
}


@dataclass(frozen=True, order=True)
class FormalViolation:
    code: str
    component: str
    safe_state: str
    detail_digest: str

    @classmethod
    def build(cls, code: str, component: str, safe_state: str, detail: Any = None) -> "FormalViolation":
        return cls(code, component, safe_state, generate_digest({"code": code, "component": component, "detail": detail}))


@dataclass(frozen=True)
class FormalVerificationResult:
    valid: bool
    decision: str
    safe_state: str | None
    violations: tuple[FormalViolation, ...]
    formal_state_digest: str
    transition_digest: str
    lineage_digest: str
    evidence_digest: str
    assurance_owner: str = ASSURANCE_OWNER
    authority_granted: bool = False
    model_version: str = FORMAL_MODEL_VERSION
    evidence_version: str = FORMAL_EVIDENCE_VERSION
    integrity_signature: Mapping[str, Any] | None = None

    def payload_without_signature(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("integrity_signature", None)
        return payload

    def verify_integrity(self) -> bool:
        return bool(self.integrity_signature) and verify_signature(
            {"integrity_domain": ASSURANCE_DOMAIN, "payload": self.payload_without_signature()},
            self.integrity_signature,
        )


def _violation(code: str, component: str, safe_state: str = "PERSISTENTLY_INOPERABLE", detail: Any = None) -> FormalViolation:
    return FormalViolation.build(code, component, safe_state, detail)


def _history_positions(history: Sequence[str]) -> dict[str, int]:
    return {stage: index for index, stage in enumerate(history)}


def _is_prefix(sequence: Sequence[str], expected: Sequence[str]) -> bool:
    return tuple(sequence) == tuple(expected[:len(sequence)])


def _strict_constraints_preserved(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    try:
        return constraints_preserved(previous, current)
    except Exception:
        return False


def safe_state_for(failure: str) -> str:
    return SAFE_CONVERGENCE.get(failure, SAFE_CONVERGENCE["unknown"])


def verify_transition(
    source: FormalState, destination: FormalState, *,
    transition_index: Mapping[tuple[str, str], TransitionRecord] = TRANSITION_INDEX,
) -> tuple[bool, FormalViolation | None]:
    record = transition_index.get((source.architectural_state, destination.architectural_state))
    if record is None:
        return False, _violation(
            "undeclared_transition", "transition_system", "HALTED",
            {"source": source.architectural_state, "destination": destination.architectural_state},
        )
    if destination.pipeline_mode not in record.permitted_pipeline_modes or destination.pipeline_mode != source.pipeline_mode:
        return False, _violation("pipeline_doctrine_changed", "transition_system", "HALTED")
    bindings = (
        "request_fingerprint", "canonical_state_hash", "eie_digest",
        "runtime_identity", "measured_baseline_identity",
    )
    for field in bindings:
        prior = getattr(source, field)
        current = getattr(destination, field)
        if prior and current != prior:
            return False, _violation(f"transition_binding_mismatch:{field}", "transition_system", "HALTED")
    if source.decision_state in {"DENY", "HALT", "ESCALATE"} and destination.architectural_state not in SAFE_TERMINAL_STATES + ("AUDIT_FINALISED",):
        return False, _violation("downstream_restoration_of_failure", "transition_system", "HALTED")
    return True, None


def verify_transition_sequence(
    states: Sequence[FormalState], *,
    transition_index: Mapping[tuple[str, str], TransitionRecord] = TRANSITION_INDEX,
) -> tuple[FormalViolation, ...]:
    violations: list[FormalViolation] = []
    for source, destination in zip(states, states[1:]):
        valid, violation = verify_transition(source, destination, transition_index=transition_index)
        if not valid and violation is not None:
            violations.append(violation)
    return tuple(sorted(set(violations)))


def verify_lineage(nodes: Sequence[LineageNode]) -> tuple[FormalViolation, ...]:
    if not nodes:
        return ()
    violations: list[FormalViolation] = []
    by_id: dict[str, LineageNode] = {}
    children: dict[str, int] = {}
    for node in nodes:
        if node.node_identifier in by_id:
            violations.append(_violation("duplicate_lineage_node", "causal_lineage", "HALTED", node.node_identifier))
        by_id[node.node_identifier] = node
        if node.node_digest != generate_digest(node.payload_without_digest()):
            violations.append(_violation("lineage_node_digest_mismatch", "causal_lineage", "HALTED", node.node_identifier))
        if not node.fresh:
            violations.append(_violation("stale_lineage_evidence", "causal_lineage", "HALTED", node.node_identifier))
    if tuple(node.node_type for node in nodes) != LINEAGE_ORDER[:len(nodes)]:
        violations.append(_violation("lineage_reordered_or_truncated", "causal_lineage", "HALTED"))
    root = nodes[0]
    if root.predecessor_identifiers:
        violations.append(_violation("lineage_root_has_predecessor", "causal_lineage", "HALTED"))
    reference = {
        "request_fingerprint": root.request_fingerprint,
        "canonical_state_hash": root.canonical_state_hash,
        "eie_digest": root.eie_digest,
        "runtime_identity": root.runtime_identity,
        "measured_baseline_identity": root.measured_baseline_identity,
    }
    for index, node in enumerate(nodes[1:], start=1):
        expected = nodes[index - 1].node_identifier
        if node.predecessor_identifiers != (expected,):
            if not node.predecessor_identifiers:
                code = "missing_lineage_predecessor"
            elif any(item not in by_id for item in node.predecessor_identifiers):
                code = "unknown_lineage_predecessor"
            else:
                code = "lineage_fork_or_reentry"
            violations.append(_violation(code, "causal_lineage", "HALTED", node.node_identifier))
        for predecessor in node.predecessor_identifiers:
            children[predecessor] = children.get(predecessor, 0) + 1
        for field, expected_value in reference.items():
            if getattr(node, field) != expected_value:
                violations.append(_violation(f"lineage_binding_mismatch:{field}", "causal_lineage", "HALTED", node.node_identifier))
        if node.token_stage and node.token_stage != node.node_type:
            violations.append(_violation("token_transplantation", "causal_lineage", "HALTED", node.node_identifier))
        if node.node_type == "EXECUTION_ATTESTATION" and node.attested_capability_id != node.capability_id:
            violations.append(_violation("execution_attestation_transplantation", "causal_lineage", "HALTED"))
    if any(count > 1 for count in children.values()):
        violations.append(_violation("prohibited_lineage_fork", "causal_lineage", "HALTED"))
    # Bounded parent walk detects cycles even when input order is adversarial.
    for node in nodes:
        seen: set[str] = set()
        current = node
        while current.predecessor_identifiers:
            predecessor = current.predecessor_identifiers[0]
            if predecessor in seen or predecessor == node.node_identifier:
                violations.append(_violation("lineage_cycle", "causal_lineage", "HALTED", node.node_identifier))
                break
            seen.add(predecessor)
            if predecessor not in by_id:
                break
            current = by_id[predecessor]
    return tuple(sorted(set(violations)))


class FormalArchitectureVerifier:
    """Non-authoritative executable assurance for the existing Desktop V1 architecture."""

    def __init__(self, *, transition_index: Mapping[tuple[str, str], TransitionRecord] = TRANSITION_INDEX) -> None:
        self.transition_index = dict(transition_index)

    def _coerce(self, state: FormalState | Mapping[str, Any]) -> tuple[FormalState | None, list[FormalViolation]]:
        if isinstance(state, FormalState):
            return state, []
        if not isinstance(state, Mapping):
            return None, [_violation("formal_state_not_mapping", "state_model")]
        unknown = set(state) - FORMAL_STATE_FIELDS
        if unknown:
            return None, [_violation("unknown_formal_state_fields", "state_model", detail=sorted(unknown))]
        try:
            return formal_state_from_mapping(state), []
        except (TypeError, ValueError) as exc:
            return None, [_violation("formal_state_schema_invalid", "state_model", detail=str(exc))]

    def verify_state(self, state: FormalState | Mapping[str, Any]) -> tuple[FormalViolation, ...]:
        formal, violations = self._coerce(state)
        if formal is None:
            return tuple(violations)
        if formal.model_version != FORMAL_MODEL_VERSION:
            violations.append(_violation("formal_model_version_invalid", "state_model"))
        if formal.architectural_state not in ARCHITECTURAL_STATES:
            violations.append(_violation("unknown_architectural_state", "state_model"))
        if formal.decision_state not in DECISION_STATES:
            violations.append(_violation("unknown_decision_state", "state_model"))
        if formal.capability_state is not None and formal.capability_state not in H7_CAPABILITY_STATES:
            violations.append(_violation("unknown_h7_capability_state", "state_model"))
        if formal.terminal_outcome not in TERMINAL_OUTCOMES:
            violations.append(_violation("unknown_terminal_outcome", "state_model"))
        if formal.pipeline_mode not in PIPELINE_MODES:
            violations.append(_violation("unknown_pipeline_mode", "mode_laws"))
        if formal.convergence_state not in CONVERGENCE_STATES:
            violations.append(_violation("unknown_convergence_state", "mode_laws"))
        for field in (
            "request_fingerprint", "canonical_state_hash", "eie_digest",
            "runtime_identity", "measured_baseline_identity", "measurement_digest",
        ):
            if not getattr(formal, field):
                violations.append(_violation(f"required_binding_missing:{field}", "state_model", "HALTED"))
        violations.extend(self.verify_invariants(formal))
        violations.extend(self.verify_mode_laws(formal))
        violations.extend(self.verify_impossible_states(formal))
        return tuple(sorted(set(violations)))

    def verify_invariants(self, state: FormalState) -> tuple[FormalViolation, ...]:
        violations: list[FormalViolation] = []
        history = tuple(state.stage_history)
        if len(history) != len(set(history)):
            violations.append(_violation("duplicate_canonical_stage", "canonical_state_singularity", "HALTED"))
        canonical_history = tuple(item for item in history if item in CANONICAL_RUNTIME_ORDER)
        if not _is_prefix(canonical_history, CANONICAL_RUNTIME_ORDER):
            violations.append(_violation("canonical_stage_order_invalid", "architectural_invariants", "HALTED"))
        positions = _history_positions(history)
        precedence = (
            ("state_construction", "collective_attach"),
            ("collective_attach", "root_of_trust"),
            ("root_of_trust", "procedural_truth"),
            ("procedural_truth", "classification"),
            ("classification", "licensing"),
            ("licensing", "governance"),
            ("governance", "grc"),
            ("grc", "domain_wrap"),
            ("domain_wrap", "aurion_runtime"),
            ("aurion_runtime", "execution_gate"),
            ("execution_gate", "audit"),
        )
        for prior, later in precedence:
            if later in positions and (prior not in positions or positions[prior] >= positions[later]):
                violations.append(_violation(f"precedence_violation:{prior}_before_{later}", "architectural_invariants", "HALTED"))
        if state.state_constructor != "SBP_LEX_CANONICAL_STATE_CONSTRUCTION":
            violations.append(_violation("alternative_state_constructor", "canonical_state_singularity", "HALTED"))
        if state.collective_attachment_count not in {0, 1}:
            violations.append(_violation("collective_attachment_cardinality_invalid", "architectural_invariants", "HALTED"))
        if state.collective_attachment_count and "state_construction" not in positions:
            violations.append(_violation("collective_attachment_before_state", "architectural_invariants", "HALTED"))
        for component, capabilities in (state.component_authorities or {}).items():
            if component in EXTERNAL_NON_AUTHORITY_COMPONENTS and set(capabilities) & AUTHORITY_CAPABILITIES:
                violations.append(_violation("external_component_has_authority", "external_non_authority", "DENIED", component))
        if state.topology != "DESKTOP_V1_LOCAL_PRIVATE_SINGLE_HOST" or state.node_count != 0:
            violations.append(_violation("desktop_v1_no_node_boundary_violated", "desktop_v1_boundary", "PERSISTENTLY_INOPERABLE"))
        if state.audit_complete and not state.audit_lineage:
            violations.append(_violation("audit_continuity_missing", "audit_continuity", "PERSISTENTLY_INOPERABLE"))
        return tuple(violations)

    def verify_impossible_states(self, state: FormalState) -> tuple[FormalViolation, ...]:
        violations: list[FormalViolation] = []
        execution_approved = state.decision_state == "ALLOW" and state.architectural_state in {
            "EXECUTION_GATE_RESOLVED", "EXECUTION_CAPABILITY_ISSUED", "EXECUTION_RESERVED",
            "EXECUTION_ACTIVE", "EXECUTION_COMPLETED", "AUDIT_FINALISED",
        }
        evidence = state.evidence or {}
        if execution_approved:
            required_results = {
                "authority_first_result": "PASS", "procedural_truth_result": "PASS",
                "classification_result": "ALLOW", "licensing_result": "ALLOW",
                "governance_result": "ALLOW", "grc_result": "PASS",
                "domain_result": "pass", "aurion15_result": "pass",
            }
            for field, expected in required_results.items():
                if evidence.get(field) != expected:
                    violations.append(_violation(f"execution_without:{field}", "impossible_state", "DENIED"))
            if state.convergence_state != "MATCHED":
                violations.append(_violation("execution_without_exact_convergence", "impossible_state", "PERSISTENTLY_INOPERABLE"))
            if state.measured_startup_status != "MEASURED_STARTUP_APPROVED":
                violations.append(_violation("execution_without_measured_startup", "impossible_state", "PERSISTENTLY_INOPERABLE"))
            missing = [name for name in REQUIRED_TOKEN_NAMES if name not in (state.tokens or {})]
            if missing:
                violations.append(_violation("execution_without_complete_token_stack", "impossible_state", "DENIED", missing))
        execution_terminal = state.architectural_state in {
            "EXECUTION_COMPLETED", "EXECUTION_FAILED", "EXECUTION_CANCELLED", "EXECUTION_AMBIGUOUS",
        }
        if state.architectural_state == "EXECUTION_COMPLETED":
            if not state.capability_consumed:
                violations.append(_violation("completion_without_capability_consumption", "h7_integrity", "HALTED"))
            if state.capability_cancelled:
                violations.append(_violation("completion_after_cancellation", "h7_integrity", "EXECUTION_AMBIGUOUS"))
            if state.capability_revoked:
                violations.append(_violation("completion_after_revocation", "h7_integrity", "EXECUTION_AMBIGUOUS"))
            if state.capability_state == "AMBIGUOUS":
                violations.append(_violation("completion_from_ambiguous_capability", "h7_integrity", "EXECUTION_AMBIGUOUS"))
        if state.architectural_state == "EXECUTION_ACTIVE" and state.capability_expired:
            violations.append(_violation("active_expired_capability", "h7_integrity", "EXECUTION_FAILED"))
        if execution_terminal and not state.execution_attestation:
            violations.append(_violation("execution_terminal_without_attestation", "audit_continuity", "PERSISTENTLY_INOPERABLE"))
        if state.audit_complete and state.terminal_outcome == "COMPLETED" and not state.execution_attestation:
            violations.append(_violation("audit_success_without_execution_attestation", "audit_continuity", "PERSISTENTLY_INOPERABLE"))
        if state.execution_capability:
            if not verify_capability(state.execution_capability):
                violations.append(_violation("h7_capability_integrity_invalid", "h7_integrity", "HALTED"))
            else:
                capability = state.execution_capability
                bindings = {
                    "request_fingerprint": state.request_fingerprint,
                    "canonical_state_hash": state.canonical_state_hash,
                    "eie_digest": state.eie_digest,
                    "pipeline_mode": state.pipeline_mode,
                    "runtime_identity": state.runtime_identity,
                    "approved_baseline_identifier": state.measured_baseline_identity,
                    "measurement_digest": state.measurement_digest,
                }
                for field, expected in bindings.items():
                    if capability.get(field) != expected:
                        violations.append(_violation(f"h7_binding_mismatch:{field}", "h7_integrity", "HALTED"))
                if state.execution_attestation and not verify_post_execution_attestation(
                    state.execution_attestation, capability=capability,
                ):
                    violations.append(_violation("h7_attestation_integrity_invalid", "h7_integrity", "EXECUTION_AMBIGUOUS"))
        return tuple(violations)

    def verify_mode_laws(self, state: FormalState) -> tuple[FormalViolation, ...]:
        violations: list[FormalViolation] = []
        required = {
            "procedural_truth", "classification", "licensing", "governance", "grc",
            "domain_wrap", "aurion_runtime", "execution_gate", "audit",
        }
        history = set(state.stage_history)
        if state.architectural_state in {"EXECUTION_GATE_RESOLVED", "EXECUTION_CAPABILITY_ISSUED", "EXECUTION_RESERVED", "EXECUTION_ACTIVE", "EXECUTION_COMPLETED", "AUDIT_FINALISED"}:
            missing = sorted(required - history)
            if missing:
                violations.append(_violation("pipeline_mode_missing_mandatory_layer", "mode_laws", "HALTED", missing))
        a = state.pipeline_a or {}
        b = state.pipeline_b
        parity_fields = (
            "request_fingerprint", "eie_digest", "canonical_state_hash", "decision",
            "governance_result", "domain_result", "aurion15_result", "execution_result",
        )
        if state.pipeline_mode == "MODE_1_FULL_MIRRORED":
            if state.active_pipeline_count != 2 or not isinstance(b, Mapping):
                violations.append(_violation("mode1_requires_two_pipelines", "mode_laws", "HALTED"))
            else:
                mismatches = [field for field in parity_fields if a.get(field) != b.get(field)]
                if mismatches or state.convergence_state != "MATCHED":
                    violations.append(_violation("mode1_exact_parity_required", "mode_laws", "PERSISTENTLY_INOPERABLE", mismatches))
            if (state.formal_flags or {}).get("approximate_convergence"):
                violations.append(_violation("mode1_approximate_parity_rejected", "mode_laws", "PERSISTENTLY_INOPERABLE"))
        elif state.pipeline_mode == "MODE_2_SPLIT_VALIDATOR":
            if state.active_pipeline_count != 2 or not isinstance(b, Mapping):
                violations.append(_violation("mode2_validator_missing", "mode_laws", "HALTED"))
            else:
                if b.get("role") != "VALIDATOR" or b.get("independently_authorized") is True:
                    violations.append(_violation("mode2_validator_self_authorization", "mode_laws", "DENIED"))
                if b.get("weakens_pipeline_a") is True or b.get("overrides_governance") is True:
                    violations.append(_violation("mode2_validator_weakening", "mode_laws", "DENIED"))
                if state.convergence_state != "MATCHED":
                    violations.append(_violation("mode2_validator_convergence_failed", "mode_laws", "PERSISTENTLY_INOPERABLE"))
        elif state.pipeline_mode == "MODE_3_SINGLE_CONSTRAINED":
            if state.active_pipeline_count != 1 or b is not None:
                violations.append(_violation("mode3_single_pipeline_cardinality", "mode_laws", "HALTED"))
            if state.stronger_mode_required:
                violations.append(_violation("mode3_stronger_mode_required", "mode_laws", "HALTED"))
        doctrine = (state.formal_flags or {}).get("omitted_doctrine", ())
        if doctrine:
            violations.append(_violation("pipeline_mode_changed_authority_doctrine", "mode_laws", "HALTED", doctrine))
        return tuple(violations)

    def verify_conservation(self, states: Sequence[FormalState]) -> tuple[FormalViolation, ...]:
        violations: list[FormalViolation] = []
        for previous, current in zip(states, states[1:]):
            if not set(current.authority_scope).issubset(previous.authority_scope):
                violations.append(_violation("authority_broadened", "authority_conservation", "DENIED"))
            if not set(current.permission_scope).issubset(previous.permission_scope):
                violations.append(_violation("permission_broadened", "permission_conservation", "DENIED"))
            if not set(current.licensing_scope).issubset(previous.licensing_scope):
                violations.append(_violation("licensing_scope_broadened", "licensing_conservation", "DENIED"))
            if not _strict_constraints_preserved(previous.constraints or {}, current.constraints or {}):
                violations.append(_violation("constraints_removed_or_weakened", "constraint_conservation", "HALTED"))
            if previous.decision_state in {"DENY", "HALT", "ESCALATE"} and current.decision_state == "ALLOW":
                violations.append(_violation("denial_not_conserved", "denial_conservation", "DENIED"))
            for field in (
                "request_fingerprint", "canonical_state_hash", "eie_digest",
                "runtime_identity", "measured_baseline_identity",
            ):
                if getattr(previous, field) != getattr(current, field):
                    violations.append(_violation(f"identity_or_state_not_conserved:{field}", "identity_conservation", "HALTED"))
            if current.classification_rank < previous.classification_rank:
                violations.append(_violation("classification_silently_decreased", "classification_conservation", "DENIED"))
            if current.consequence_tier < previous.consequence_tier:
                violations.append(_violation("consequence_tier_downgraded", "consequentiality_conservation", "DENIED"))
            if current.corroboration_required < previous.corroboration_required:
                violations.append(_violation("corroboration_requirement_reduced", "corroboration_conservation", "DENIED"))
            if not set(previous.audit_lineage).issubset(current.audit_lineage):
                violations.append(_violation("audit_lineage_rewritten", "audit_conservation", "PERSISTENTLY_INOPERABLE"))
            previous_evidence = previous.evidence or {}
            current_evidence = current.evidence or {}
            for key in ("source", "provenance", "schema", "signature", "package_identity", "dependency_lineage"):
                if key in previous_evidence and current_evidence.get(key) != previous_evidence.get(key):
                    violations.append(_violation(f"evidence_not_conserved:{key}", "evidence_conservation", "HALTED"))
        return tuple(sorted(set(violations)))

    def verify(
        self, state: FormalState | Mapping[str, Any], *,
        transitions: Sequence[FormalState] = (), lineage: Sequence[LineageNode] = (),
    ) -> FormalVerificationResult:
        formal, coercion = self._coerce(state)
        violations = list(coercion)
        if formal is not None:
            violations.extend(self.verify_state(formal))
        if transitions:
            violations.extend(verify_transition_sequence(transitions, transition_index=self.transition_index))
            violations.extend(self.verify_conservation(transitions))
        if lineage:
            violations.extend(verify_lineage(lineage))
        unique = tuple(sorted(set(violations)))
        safe_state = unique[0].safe_state if unique else None
        formal_digest = formal.digest if formal is not None else generate_digest(dict(state) if isinstance(state, Mapping) else {"invalid": True})
        transition_digest = generate_digest([item.as_payload() for item in self.transition_index.values()])
        lineage_digest = generate_digest([node.payload_without_digest() | {"node_digest": node.node_digest} for node in lineage])
        core = {
            "valid": not unique,
            "decision": "FORMAL_PASS" if not unique else "FORMAL_REJECT",
            "safe_state": safe_state,
            "violations": [asdict(item) for item in unique],
            "formal_state_digest": formal_digest,
            "transition_digest": transition_digest,
            "lineage_digest": lineage_digest,
            "assurance_owner": ASSURANCE_OWNER,
            "authority_granted": False,
            "model_version": FORMAL_MODEL_VERSION,
            "evidence_version": FORMAL_EVIDENCE_VERSION,
        }
        evidence_digest = generate_digest(core)
        result = FormalVerificationResult(
            valid=not unique,
            decision=core["decision"],
            safe_state=safe_state,
            violations=unique,
            formal_state_digest=formal_digest,
            transition_digest=transition_digest,
            lineage_digest=lineage_digest,
            evidence_digest=evidence_digest,
        )
        signature = sign_payload({"integrity_domain": ASSURANCE_DOMAIN, "payload": result.payload_without_signature()})
        return replace(result, integrity_signature=signature)


def _formal_canonical_state_hash(state: Mapping[str, Any]) -> str:
    seal = state.get("terminal_state_seal")
    seal_valid, _ = verify_terminal_state_seal(state, seal)
    if seal_valid and isinstance(seal, Mapping):
        payload = seal.get("payload")
        if isinstance(payload, Mapping):
            terminal_digest = payload.get("pre_seal_state_digest")
            if isinstance(terminal_digest, str) and terminal_digest:
                return terminal_digest
    return str(state.get("state_hash", ""))


def formalize_runtime_state(state: Mapping[str, Any], runtime_status: Mapping[str, Any]) -> FormalState:
    order = tuple(state.get("integration_stage_order", ()))
    latest = "EXECUTION_GATE_RESOLVED" if "execution_gate" in order else (
        RUNTIME_STAGE_TO_FORMAL.get(next((item for item in reversed(order) if item in RUNTIME_STAGE_TO_FORMAL), ""), "HALTED")
    )
    convergence = state.get("pipeline_convergence", {})
    mode = str(state.get("pipeline_mode", "MODE_3_SINGLE_CONSTRAINED"))
    canonical_state_hash = _formal_canonical_state_hash(state)
    pipeline_a = {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "canonical_state_hash": canonical_state_hash,
        "decision": state.get("decision"),
        "governance_result": state.get("governance_result"),
        "domain_result": state.get("domain_result"),
        "aurion15_result": state.get("aurion15_result"),
        "execution_result": state.get("execution_result"),
    }
    raw_b = convergence.get("pipeline_b") if isinstance(convergence, Mapping) else None
    pipeline_b = None
    if mode == "MODE_1_FULL_MIRRORED" and isinstance(raw_b, Mapping):
        pipeline_b = {**pipeline_a, **dict(raw_b), "role": "MIRROR", "independently_authorized": False}
    elif mode == "MODE_2_SPLIT_VALIDATOR" and isinstance(raw_b, Mapping):
        pipeline_b = {
            **pipeline_a, **dict(raw_b), "role": "VALIDATOR", "independently_authorized": False,
            "weakens_pipeline_a": False, "overrides_governance": False,
        }
    evidence = {
        "authority_first_result": state.get("authority_first_result"),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "classification_result": state.get("classification_result"),
        "licensing_result": state.get("licensing_result"),
        "governance_result": state.get("governance_result"),
        "grc_result": state.get("grc_result"),
        "domain_result": state.get("domain_result"),
        "aurion15_result": state.get("aurion15_result"),
    }
    return FormalState(
        architectural_state=latest,
        decision_state=str(state.get("decision", "UNRESOLVED")),
        terminal_outcome="NONE",
        audit_complete=bool(state.get("audit_finalisation", {}).get("audit_complete")),
        pipeline_mode=mode,
        convergence_state="MATCHED" if convergence.get("matched", mode == "MODE_3_SINGLE_CONSTRAINED") else "FAILED",
        required_evidence=tuple(sorted(evidence)),
        causal_predecessor="AURION_RESOLVED" if latest == "EXECUTION_GATE_RESOLVED" else None,
        request_fingerprint=str(state.get("request_fingerprint", "")),
        canonical_state_hash=canonical_state_hash,
        eie_digest=str(state.get("eie_hash", "")),
        runtime_identity=str(runtime_status.get("measured_runtime_identity", "")),
        measured_baseline_identity=str(runtime_status.get("approved_runtime_baseline", "")),
        measurement_digest=str(runtime_status.get("runtime_measurement_digest", "")),
        stage_history=order,
        tokens=dict(state.get("tokens", {})),
        authority_scope=("CANONICAL_TRAVERSAL",),
        permission_scope=(str(state.get("action", "")),),
        constraints=dict(state.get("classification", {}).get("constraints", {})),
        identities={
            "source": str(state.get("eie", {}).get("source_system_identity", "")),
            "adapter": str(state.get("eie", {}).get("adapter_identity", "")),
        },
        evidence=evidence,
        pipeline_a=pipeline_a,
        pipeline_b=pipeline_b,
        measured_startup_status=str(runtime_status.get("measured_startup_status", "UNSET")),
        component_authorities={component: () for component in EXTERNAL_NON_AUTHORITY_COMPONENTS},
        collective_attachment_count=1 if state.get("collective_signal_status") == "ATTACHED" else 0,
        active_pipeline_count=1 if mode == "MODE_3_SINGLE_CONSTRAINED" else 2,
        audit_lineage=(str(state.get("audit_hash", "")),) if state.get("audit_hash") else (),
    )


def verify_current_runtime_state(state: Mapping[str, Any], runtime_status: Mapping[str, Any]) -> FormalVerificationResult:
    return FormalArchitectureVerifier().verify(formalize_runtime_state(state, runtime_status))


def replay_formal_verification(
    state: FormalState | Mapping[str, Any], *, replay_count: int = 2,
    transitions: Sequence[FormalState] = (), lineage: Sequence[LineageNode] = (),
) -> dict[str, Any]:
    if not isinstance(replay_count, int) or replay_count < 2 or replay_count > 16:
        raise ValueError("formal_replay_count_invalid")
    verifier = FormalArchitectureVerifier()
    results = tuple(verifier.verify(state, transitions=transitions, lineage=lineage) for _ in range(replay_count))
    digests = tuple(item.evidence_digest for item in results)
    payload = {
        "replay_version": "PHQ_DESKTOP_V1_FORMAL_REPLAY_V1",
        "replay_count": replay_count,
        "matched": len(set(digests)) == 1,
        "evidence_digests": digests,
    }
    return {**payload, "replay_digest": generate_digest(payload)}
