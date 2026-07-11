from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from sbp_lex.execution.capability import STATES as H7_CAPABILITY_STATES
from sbp_lex.security.pqc import generate_digest

FORMAL_MODEL_VERSION = "PHQ_DESKTOP_V1_FORMAL_MODEL_V1"
FORMAL_EVIDENCE_VERSION = "PHQ_DESKTOP_V1_FORMAL_EVIDENCE_V1"

PIPELINE_MODES = (
    "MODE_1_FULL_MIRRORED",
    "MODE_2_SPLIT_VALIDATOR",
    "MODE_3_SINGLE_CONSTRAINED",
)

CANONICAL_CONTROL_STATES = (
    "EXTERNAL_REQUEST_RECEIVED",
    "NATIVE_FORMAT_VALIDATED",
    "ADAPTER_TRANSLATED",
    "EIE_CONSTRUCTED",
    "SKG_VERIFIED",
    "DTN_VERIFIED",
    "HARD_ENTRY_ACCEPTED",
    "CANONICAL_STATE_CONSTRUCTED",
    "COLLECTIVE_SIGNALS_ATTACHED",
    "ROOT_OF_TRUST_ESTABLISHED",
    "PROCEDURAL_TRUTH_CERTIFIED",
    "CLASSIFIED",
    "LICENSED",
    "GOVERNANCE_RESOLVED",
    "GRC_RESOLVED",
    "DOMAIN_RESOLVED",
    "AURION_RESOLVED",
    "EXECUTION_GATE_RESOLVED",
)

EXECUTION_STATES = (
    "EXECUTION_CAPABILITY_ISSUED",
    "EXECUTION_RESERVED",
    "EXECUTION_ACTIVE",
    "EXECUTION_COMPLETED",
    "EXECUTION_FAILED",
    "EXECUTION_CANCELLED",
    "EXECUTION_AMBIGUOUS",
)

SAFE_TERMINAL_STATES = (
    "DENIED",
    "ESCALATED",
    "HALTED",
    "PERSISTENTLY_INOPERABLE",
)

ARCHITECTURAL_STATES = frozenset(
    CANONICAL_CONTROL_STATES + EXECUTION_STATES + SAFE_TERMINAL_STATES + ("AUDIT_FINALISED",)
)

DECISION_STATES = frozenset({"UNRESOLVED", "ALLOW", "DENY", "ESCALATE", "HALT"})
TERMINAL_OUTCOMES = frozenset({
    "NONE", "COMPLETED", "FAILED", "CANCELLED", "AMBIGUOUS", "DENIED",
    "ESCALATED", "HALTED", "PERSISTENTLY_INOPERABLE",
})
CONVERGENCE_STATES = frozenset({"UNRESOLVED", "MATCHED", "FAILED", "NOT_APPLICABLE"})

REQUIRED_TOKEN_NAMES = (
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
)

EXTERNAL_NON_AUTHORITY_COMPONENTS = frozenset({
    "EXTERNAL_SYSTEM", "ADAPTER", "EIE", "SKG", "DTN", "UI", "VIEWER",
    "APK", "ODA", "PVPL",
})

AUTHORITY_CAPABILITIES = frozenset({
    "CANONICAL_STATE_CONSTRUCTION", "CLASSIFICATION", "LICENSING", "GOVERNANCE",
    "GRC", "DOMAIN", "AURION", "EXECUTION",
})

FORMAL_STATE_FIELDS = frozenset({
    "model_version", "architectural_state", "decision_state", "capability_state",
    "terminal_outcome", "audit_complete", "pipeline_mode", "convergence_state",
    "required_evidence", "causal_predecessor", "request_fingerprint",
    "canonical_state_hash", "eie_digest", "runtime_identity",
    "measured_baseline_identity", "measurement_digest", "stage_history", "tokens",
    "authority_scope", "permission_scope", "constraints", "identities", "evidence",
    "pipeline_a", "pipeline_b", "measured_startup_status", "execution_capability",
    "capability_consumed", "capability_cancelled", "capability_revoked",
    "capability_expired", "execution_attestation", "component_authorities",
    "state_constructor", "collective_attachment_count", "topology", "node_count",
    "active_pipeline_count", "stronger_mode_required", "classification_rank",
    "licensing_scope", "consequence_tier", "corroboration_required",
    "audit_lineage", "fresh_traversal", "formal_flags",
})


@dataclass(frozen=True)
class FormalState:
    architectural_state: str
    decision_state: str = "UNRESOLVED"
    capability_state: str | None = None
    terminal_outcome: str = "NONE"
    audit_complete: bool = False
    pipeline_mode: str = "MODE_3_SINGLE_CONSTRAINED"
    convergence_state: str = "UNRESOLVED"
    required_evidence: tuple[str, ...] = ()
    causal_predecessor: str | None = None
    request_fingerprint: str = ""
    canonical_state_hash: str = ""
    eie_digest: str = ""
    runtime_identity: str = ""
    measured_baseline_identity: str = ""
    measurement_digest: str = ""
    stage_history: tuple[str, ...] = ()
    tokens: Mapping[str, Any] | None = None
    authority_scope: tuple[str, ...] = ()
    permission_scope: tuple[str, ...] = ()
    constraints: Mapping[str, Any] | None = None
    identities: Mapping[str, str] | None = None
    evidence: Mapping[str, Any] | None = None
    pipeline_a: Mapping[str, Any] | None = None
    pipeline_b: Mapping[str, Any] | None = None
    measured_startup_status: str = "UNSET"
    execution_capability: Mapping[str, Any] | None = None
    capability_consumed: bool = False
    capability_cancelled: bool = False
    capability_revoked: bool = False
    capability_expired: bool = False
    execution_attestation: Mapping[str, Any] | None = None
    component_authorities: Mapping[str, tuple[str, ...]] | None = None
    state_constructor: str = "SBP_LEX_CANONICAL_STATE_CONSTRUCTION"
    collective_attachment_count: int = 0
    topology: str = "DESKTOP_V1_LOCAL_PRIVATE_SINGLE_HOST"
    node_count: int = 0
    active_pipeline_count: int = 1
    stronger_mode_required: bool = False
    classification_rank: int = 0
    licensing_scope: tuple[str, ...] = ()
    consequence_tier: int = 0
    corroboration_required: int = 0
    audit_lineage: tuple[str, ...] = ()
    fresh_traversal: bool = True
    formal_flags: Mapping[str, Any] | None = None
    model_version: str = FORMAL_MODEL_VERSION

    def as_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["tokens"] = dict(self.tokens or {})
        payload["constraints"] = dict(self.constraints or {})
        payload["identities"] = dict(self.identities or {})
        payload["evidence"] = dict(self.evidence or {})
        payload["pipeline_a"] = dict(self.pipeline_a or {})
        payload["pipeline_b"] = dict(self.pipeline_b or {}) if self.pipeline_b is not None else None
        payload["execution_capability"] = dict(self.execution_capability or {}) if self.execution_capability else None
        payload["execution_attestation"] = dict(self.execution_attestation or {}) if self.execution_attestation else None
        payload["component_authorities"] = {
            key: list(value) for key, value in (self.component_authorities or {}).items()
        }
        payload["formal_flags"] = dict(self.formal_flags or {})
        return payload

    @property
    def digest(self) -> str:
        return generate_digest(self.as_payload())


@dataclass(frozen=True)
class TransitionRecord:
    transition_identifier: str
    source_state: str
    destination_state: str
    required_preconditions: tuple[str, ...]
    required_evidence: tuple[str, ...]
    required_tokens: tuple[str, ...]
    required_bindings: tuple[str, ...]
    permitted_pipeline_modes: tuple[str, ...]
    failure_destination: str
    terminal_status: bool
    authority_owner: str
    audit_requirement: str

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LineageNode:
    node_identifier: str
    node_type: str
    predecessor_identifiers: tuple[str, ...]
    request_fingerprint: str
    canonical_state_hash: str
    eie_digest: str
    runtime_identity: str
    measured_baseline_identity: str
    evidence_digest: str
    token_stage: str | None = None
    capability_id: str | None = None
    attested_capability_id: str | None = None
    fresh: bool = True
    node_digest: str = ""

    def payload_without_digest(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("node_digest", None)
        return payload

    def with_digest(self) -> "LineageNode":
        return LineageNode(**{**self.payload_without_digest(), "node_digest": generate_digest(self.payload_without_digest())})


def formal_state_from_mapping(value: Mapping[str, Any]) -> FormalState:
    unknown = set(value) - FORMAL_STATE_FIELDS
    if unknown:
        raise ValueError("unknown_formal_state_fields:" + ",".join(sorted(unknown)))
    return FormalState(**dict(value))


def transition_identifier(source: str, destination: str) -> str:
    return f"PHQ_{source}_TO_{destination}"


def canonical_transition_records() -> tuple[TransitionRecord, ...]:
    records: list[TransitionRecord] = []
    binding_names = (
        "request_fingerprint", "canonical_state_hash", "eie_digest",
        "runtime_identity", "measured_baseline_identity",
    )
    for source, destination in zip(CANONICAL_CONTROL_STATES, CANONICAL_CONTROL_STATES[1:]):
        records.append(TransitionRecord(
            transition_identifier(source, destination), source, destination,
            ("source_state_valid", "prior_failure_absent"),
            (f"evidence:{source}",), (), binding_names, PIPELINE_MODES,
            "HALTED", False, "SBP_LEX_V1_CANONICAL_RUNTIME", "REQUIRED",
        ))
    execution_edges = (
        ("EXECUTION_GATE_RESOLVED", "EXECUTION_CAPABILITY_ISSUED"),
        ("EXECUTION_CAPABILITY_ISSUED", "EXECUTION_RESERVED"),
        ("EXECUTION_RESERVED", "EXECUTION_ACTIVE"),
        ("EXECUTION_ACTIVE", "EXECUTION_ACTIVE"),
        ("EXECUTION_ACTIVE", "EXECUTION_COMPLETED"),
        ("EXECUTION_ACTIVE", "EXECUTION_FAILED"),
        ("EXECUTION_ACTIVE", "EXECUTION_CANCELLED"),
        ("EXECUTION_ACTIVE", "EXECUTION_AMBIGUOUS"),
    )
    for source, destination in execution_edges:
        records.append(TransitionRecord(
            transition_identifier(source, destination), source, destination,
            ("execution_gate_approved", "h7_lifecycle_valid"),
            ("h7_capability_evidence",), REQUIRED_TOKEN_NAMES, binding_names,
            PIPELINE_MODES, "HALTED", destination in {
                "EXECUTION_COMPLETED", "EXECUTION_FAILED", "EXECUTION_CANCELLED", "EXECUTION_AMBIGUOUS"
            }, "SBP_LEX_DESKTOP_V1_EXECUTION_INTEGRITY", "REQUIRED",
        ))
    audit_sources = EXECUTION_STATES[-4:] + SAFE_TERMINAL_STATES
    for source in audit_sources:
        records.append(TransitionRecord(
            transition_identifier(source, "AUDIT_FINALISED"), source, "AUDIT_FINALISED",
            ("terminal_outcome_stable",), ("audit_lineage",), (), binding_names,
            PIPELINE_MODES, "PERSISTENTLY_INOPERABLE", True,
            "SBP_LEX_V1_CANONICAL_RUNTIME", "REQUIRED",
        ))
    for source in CANONICAL_CONTROL_STATES:
        for destination in SAFE_TERMINAL_STATES:
            records.append(TransitionRecord(
                transition_identifier(source, destination), source, destination,
                ("binding_failure_recorded",), ("failure_evidence",), (), binding_names,
                PIPELINE_MODES, destination, True, "SBP_LEX_V1_CANONICAL_RUNTIME", "REQUIRED",
            ))
    return tuple(records)


TRANSITION_RECORDS = canonical_transition_records()
TRANSITION_INDEX = {(item.source_state, item.destination_state): item for item in TRANSITION_RECORDS}
