from __future__ import annotations

from copy import deepcopy
import json
from threading import Lock
from typing import Any, Dict, Mapping

from external_substrates.shared.canonical_json import canonical_dumps
from sbp_lex.execution.controlled_outcome import verify_controlled_outcome
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.governed_stage_evidence import (
    audit_lineage_projection,
)
from sbp_lex.security.threshold_tokens import required_threshold_token_names
from sbp_lex.shared.hash_chain import (
    append_hash_entry,
    current_chain_hash,
    rebuild_state_hash,
    verify_hash_chain,
)


EVIDENCE_SCHEMA_VERSION = "desktop-v1.domain-aurion-stage-evidence.v1"
HANDOFF_SCHEMA_VERSION = "desktop-v1.execution-convergence-handoff.v1"
CONTROLLED_REENTRY_USE_SCHEMA_VERSION = (
    "desktop-v1.controlled-reentry-proof-use.v1"
)
DEFAULT_CONTROLLED_REENTRY_REGISTRY_CAPACITY = 4096
CONTROLLED_STAGES = ("domain", "aurion")
EVIDENCE_FIELD = {
    "domain": "domain_evidence",
    "aurion": "aurion_evidence",
}
RESULT_FIELD = {
    "domain": "domain_result",
    "aurion": "aurion15_result",
}
REASON_FIELD = {
    "domain": "domain_reason",
    "aurion": "aurion_reason",
}
HASH_STAGE = {
    "domain": "domain_wrap",
    "aurion": "aurion_runtime",
}

EVIDENCE_WRAPPER_FIELDS = {
    "schema_version",
    "payload",
    "evidence_digest",
    "signature",
    "verified",
}
EVIDENCE_PAYLOAD_FIELDS = {
    "schema_version",
    "stage",
    "result",
    "reason",
    "request_fingerprint",
    "eie_digest",
    "collective_signal_digest",
    "traversal_id",
    "state_hash_entering_stage",
    "state_hash_before_token",
    "chain_hash_entering_finalisation",
    "tier",
    "corroboration_required",
    "authority_scope",
    "upstream_token_digests",
    "upstream_evidence_digests",
    "stage_state",
    "stage_state_digest",
    "decision_state_digest",
    "logical_index",
    "timestamp_authority",
    "nonce",
}
HANDOFF_WRAPPER_FIELDS = {
    "schema_version",
    "payload",
    "handoff_digest",
    "signature",
    "verified",
}
HANDOFF_PAYLOAD_FIELDS = {
    "schema_version",
    "boundary",
    "request_fingerprint",
    "eie_digest",
    "collective_signal_digest",
    "traversal_id",
    "state_hash_entering_handoff",
    "aurion_finalisation_hash",
    "integration_stage_prefix",
    "domain_evidence_digest",
    "aurion_evidence_digest",
    "domain_stage_state_digest",
    "aurion_stage_state_digest",
    "domain_token_digest",
    "aurion_token_digest",
    "selected_candidate_digest",
    "selected_pathway_digest",
    "ordered_candidate_set_digest",
    "constraint_snapshot_digest",
    "governed_reentry_digest",
    "domain_history_digest",
    "aurion_history_digest",
    "timestamp_authority",
    "nonce",
}

_UPSTREAM_TOKENS = {
    "domain": (
        "authority",
        "procedural_truth",
        "classification",
        "licensing",
        "governance",
        "grc",
    ),
    "aurion": (
        "authority",
        "procedural_truth",
        "classification",
        "licensing",
        "governance",
        "grc",
        "domain",
    ),
}
_UPSTREAM_GOVERNED_EVIDENCE = (
    "classification",
    "licensing",
    "governance",
    "grc",
)
_PIPELINE_PREFIX_THROUGH_AURION = (
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
)

_DOWNSTREAM_TOKENS = {
    "domain": (
        "domain",
        "aurion",
        "execution_boundary",
        "execution_attestation",
        "token_bundle",
        "master_convergence",
    ),
    "aurion": (
        "aurion",
        "execution_boundary",
        "execution_attestation",
        "token_bundle",
        "master_convergence",
    ),
}
_DOWNSTREAM_FIELDS = {
    "domain": (
        "domain_result",
        "domain_reason",
        "domain_candidate",
        "domain_evidence",
        "aurion15_result",
        "aurion_reason",
        "aurion_evidence",
        "candidate_attempt_count",
        "current_candidate",
        "execution_convergence_handoff",
    ),
    "aurion": (
        "aurion15_result",
        "aurion_reason",
        "aurion_evidence",
        "candidate_attempt_count",
        "current_candidate",
        "execution_convergence_handoff",
    ),
}
_TERMINAL_FIELDS = (
    "execution_verified",
    "execution_timestamp",
    "execution_convergence",
    "convergence_hash",
    "execution_attestation",
    "audit_record",
    "audit_hash",
    "audit_finalisation",
    "controlled_outcome",
    "final_outcome",
    "pipeline_convergence",
    "pipeline_b_summary",
    "pipeline_domain_aurion_parity",
)

PRE_EXECUTION_PERMISSION_FIELDS = (
    "execution_permission",
    "allow_execution",
    "runtime_authority",
    "final_admissibility",
    "external_allow",
    "external_deny",
    "external_escalate",
    "_".join(("external", "governance_result")),
)


class _ControlledReentryReplayRegistry:
    """Bounded process-local single-use registry for signed denial proofs."""

    def __init__(
        self,
        *,
        capacity: int = DEFAULT_CONTROLLED_REENTRY_REGISTRY_CAPACITY,
    ) -> None:
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise ValueError("controlled_reentry_registry_capacity_invalid")
        self.capacity = capacity
        self._proof_digests: set[str] = set()
        self._lock = Lock()

    def check_and_record(self, proof_digest: object) -> str:
        if not isinstance(proof_digest, str) or not proof_digest:
            return "INVALID"
        with self._lock:
            if proof_digest in self._proof_digests:
                return "REPLAYED"
            if len(self._proof_digests) >= self.capacity:
                return "CAPACITY_EXHAUSTED"
            self._proof_digests.add(proof_digest)
            return "ACCEPTED"


_CONTROLLED_REENTRY_REPLAY_REGISTRY = _ControlledReentryReplayRegistry()

_PRE_EXECUTION_NEUTRAL_FIELDS = {
    "operational_state": "UNSET",
    "execution_reason": "",
    "token_stack_valid": False,
    "token_verification_failures": [],
    "persistent_inoperability": False,
    "controlled_return_required": False,
    "last_denied_fingerprint": None,
}


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _strip_pre_execution_permission_fields(value: object) -> object:
    prohibited = set(PRE_EXECUTION_PERMISSION_FIELDS)
    if isinstance(value, Mapping):
        return {
            key: _strip_pre_execution_permission_fields(item)
            for key, item in value.items()
            if key not in prohibited
        }
    if isinstance(value, list):
        return [
            _strip_pre_execution_permission_fields(item) for item in value
        ]
    return deepcopy(value)


def _record_digest(record: object, *names: str) -> object:
    if not isinstance(record, Mapping):
        return None
    for name in names:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return None


def _history(state: Mapping[str, Any], stage: str) -> list[Any]:
    histories = _mapping(state.get("domain_aurion_history"))
    value = histories.get(stage, [])
    return deepcopy(list(value)) if isinstance(value, list) else []


def normalized_governed_reentry(state: Mapping[str, Any]) -> Dict[str, Any]:
    reentry = dict(_mapping(state.get("governed_reentry")))
    # Completion is a later controlled-return fact; GRC owns eligibility.
    reentry.pop("reentry_completed", None)
    return deepcopy(reentry)


def controlled_denial_proof_details(
    state: Mapping[str, Any],
) -> Dict[str, Any]:
    context = _mapping(state.get("context"))
    evidence = context.get("evidence", [])
    proof_items = [
        item
        for item in evidence
        if isinstance(item, Mapping)
        and item.get("source") == "controlled_denial_proof"
    ] if isinstance(evidence, list) else []
    details: Dict[str, Any] = {
        "present_count": len(proof_items),
        "valid": False,
        "proof_digest": None,
        "prior_denied_fingerprint": context.get(
            "prior_denied_fingerprint"
        ),
    }
    if len(proof_items) != 1:
        return details
    proof_item = proof_items[0]
    content = proof_item.get("content")
    details["proof_digest"] = (
        generate_digest(content) if isinstance(content, str) else None
    )
    try:
        proof = json.loads(content) if isinstance(content, str) else None
        proof_payload = (
            proof.get("payload", {}) if isinstance(proof, Mapping) else {}
        )
        details["valid"] = bool(
            isinstance(proof, Mapping)
            and canonical_dumps(proof) == content
            and proof.get("valid") is True
            and verify_controlled_outcome(proof)
            and proof_payload.get("request_fingerprint")
            == details["prior_denied_fingerprint"]
            and proof_payload.get("decision")
            in {"DENY", "ESCALATE", "PERSISTENT_INOPERABILITY"}
            and proof_payload.get("execution_verified") is False
            and proof_payload.get("persistent_inoperability") is True
            and proof_payload.get("operational_state")
            == "PERSISTENT_INOPERABILITY"
            and isinstance(proof_payload.get("audit_hash"), str)
            and bool(proof_payload.get("audit_hash"))
            and isinstance(proof_payload.get("convergence_hash"), str)
            and bool(proof_payload.get("convergence_hash"))
            and isinstance(proof_payload.get("state_hash"), str)
            and bool(proof_payload.get("state_hash"))
            and all(
                proof_item.get(field) is True
                for field in (
                    "verified",
                    "attested",
                    "freshness_valid",
                    "consistency_valid",
                )
            )
        )
    except Exception:
        details["valid"] = False
    return details


def apply_controlled_reentry_proof_use_guard(
    state: Mapping[str, Any],
) -> Dict[str, Any]:
    """Record one canonical live use before the prepared state is cloned."""
    working_state = deepcopy(dict(state))
    details = controlled_denial_proof_details(working_state)
    if details.get("present_count") == 0:
        return working_state
    selected_registry = _CONTROLLED_REENTRY_REPLAY_REGISTRY
    status = "INVALID"
    if details.get("valid") is True:
        status = selected_registry.check_and_record(
            details.get("proof_digest")
        )
    record = {
        "schema_version": CONTROLLED_REENTRY_USE_SCHEMA_VERSION,
        "status": status,
        "proof_digest": details.get("proof_digest"),
        "prior_denied_fingerprint": details.get(
            "prior_denied_fingerprint"
        ),
        "current_request_fingerprint": working_state.get(
            "request_fingerprint"
        ),
        "registry_scope": "DESKTOP_V1_PROCESS",
        "single_use": True,
        "registry_capacity": selected_registry.capacity,
    }
    working_state["controlled_reentry_proof_use"] = record
    trace = working_state.get("audit_trace", [])
    trace = deepcopy(trace) if isinstance(trace, list) else []
    trace.append(
        {
            "stage": "controlled_reentry_proof_use",
            "status": status,
            "proof_digest": details.get("proof_digest"),
            "request_fingerprint": working_state.get(
                "request_fingerprint"
            ),
        }
    )
    working_state["audit_trace"] = trace
    working_state["state_hash"] = rebuild_state_hash(working_state)
    return working_state


def domain_effective_scope(state: Mapping[str, Any]) -> object:
    candidate = _mapping(state.get("domain_candidate"))
    adjustments = _mapping(candidate.get("context_adjustments"))
    if adjustments.get("operational_scope") not in (None, ""):
        return adjustments.get("operational_scope")
    return _mapping(state.get("classification")).get("operational_scope")


def constraint_snapshot(state: Mapping[str, Any]) -> Dict[str, Any]:
    classification = _mapping(state.get("classification"))
    return {
        "computed_tier": _mapping(state.get("safety_profile")).get(
            "computed_tier"
        ),
        "corroboration_required": state.get("corroboration_required"),
        "resolved_authority": state.get("resolved_authority"),
        "jurisdiction": state.get("jurisdiction"),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "procedural_truth_outcome": state.get("procedural_truth_outcome"),
        "classification_result": state.get("classification_result"),
        "licensing_result": state.get("licensing_result"),
        "governance_result": state.get("governance_result"),
        "grc_result": state.get("grc_result"),
        "domain_result": state.get("domain_result"),
        "classification": classification.get("ap_acf_class"),
        "autonomy_level": classification.get("autonomy_level"),
        "autonomy_ceiling": classification.get("autonomy_ceiling"),
        "classification_operational_scope": classification.get(
            "operational_scope"
        ),
        "licensing_scope": state.get("licensing_scope"),
        "domain_operational_scope": domain_effective_scope(state),
    }


def candidate_bindings(state: Mapping[str, Any]) -> Dict[str, Any]:
    tokens = _mapping(state.get("tokens"))
    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            state.get("collective_signals")
        ).get("digest"),
        "traversal_id": state.get("traversal_id"),
        "state_hash_entering_aurion": state.get("state_hash"),
        "domain_evidence_digest": _record_digest(
            state.get("domain_evidence"), "evidence_digest"
        ),
        "domain_token_digest": _mapping(tokens.get("domain")).get("digest"),
        "domain_candidate_digest": generate_digest(
            dict(_mapping(state.get("domain_candidate")))
        ),
        "constraint_snapshot_digest": generate_digest(
            constraint_snapshot(state)
        ),
    }


def stage_projection(state: Mapping[str, Any], stage: str) -> Dict[str, Any]:
    if stage not in CONTROLLED_STAGES:
        raise ValueError(f"unsupported_domain_aurion_stage:{stage}")
    feedback = _mapping(state.get("governance_feedback"))
    projection: Dict[str, Any] = {
        "result": state.get(RESULT_FIELD[stage]),
        "reason": state.get(REASON_FIELD[stage]),
        "constraint_snapshot": constraint_snapshot(state),
        "governed_reentry": normalized_governed_reentry(state),
        "stage_history": _history(state, stage),
        "audit_lineage": audit_lineage_projection(
            state, terminal_stage=HASH_STAGE[stage]
        ),
    }
    if stage == "domain":
        projection.update(
            {
                "domain_feedback": deepcopy(
                    dict(_mapping(feedback.get("domain_wrap")))
                ),
                "domain_candidate": deepcopy(
                    dict(_mapping(state.get("domain_candidate")))
                ),
            }
        )
    else:
        projection.update(
            {
                "domain_evidence_digest": _record_digest(
                    state.get("domain_evidence"), "evidence_digest"
                ),
                "domain_candidate_digest": generate_digest(
                    dict(_mapping(state.get("domain_candidate")))
                ),
                "candidate_attempt_count": state.get(
                    "candidate_attempt_count"
                ),
                "selected_candidate": deepcopy(
                    dict(_mapping(state.get("current_candidate")))
                ),
                "aurion_feedback": deepcopy(
                    dict(_mapping(feedback.get("aurion")))
                ),
            }
        )
    return projection


def evidence_digest(state: Mapping[str, Any], stage: str) -> object:
    return _record_digest(state.get(EVIDENCE_FIELD[stage]), "evidence_digest")


def _upstream_token_digests(
    state: Mapping[str, Any], stage: str
) -> Dict[str, object]:
    tokens = _mapping(state.get("tokens"))
    return {
        name: _mapping(tokens.get(name)).get("digest")
        for name in _UPSTREAM_TOKENS[stage]
    }


def _upstream_evidence_digests(
    state: Mapping[str, Any], stage: str
) -> Dict[str, object]:
    values: Dict[str, object] = {
        "root_of_trust": _record_digest(
            state.get("root_of_trust_evidence"),
            "root_evidence_digest",
            "evidence_digest",
        ),
        "procedural_truth": _record_digest(
            state.get("procedural_truth_evidence"),
            "pt_evidence_digest",
            "procedural_truth_evidence_digest",
            "evidence_digest",
        ),
    }
    for name in _UPSTREAM_GOVERNED_EVIDENCE:
        values[name] = _record_digest(
            state.get(f"{name}_evidence"), "evidence_digest"
        )
    if stage == "aurion":
        values["domain"] = evidence_digest(state, "domain")
    return values


def _decision_state_basis(payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: payload.get(key)
        for key in (
            "schema_version",
            "stage",
            "result",
            "reason",
            "request_fingerprint",
            "eie_digest",
            "collective_signal_digest",
            "traversal_id",
            "state_hash_entering_stage",
            "state_hash_before_token",
            "chain_hash_entering_finalisation",
            "tier",
            "corroboration_required",
            "authority_scope",
            "upstream_token_digests",
            "upstream_evidence_digests",
            "stage_state_digest",
        )
    }


def _nonce_basis(payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: payload.get(key)
        for key in (
            "stage",
            "request_fingerprint",
            "eie_digest",
            "collective_signal_digest",
            "traversal_id",
            "state_hash_entering_stage",
            "state_hash_before_token",
            "chain_hash_entering_finalisation",
            "stage_state_digest",
            "decision_state_digest",
            "logical_index",
            "upstream_token_digests",
            "upstream_evidence_digests",
        )
    }


def build_stage_evidence(
    state: Mapping[str, Any],
    *,
    stage: str,
    state_hash_entering_stage: object,
) -> Dict[str, Any]:
    projection = stage_projection(state, stage)
    chain = state.get("hash_chain", [])
    chain_valid = hash_chain_valid(state)
    payload: Dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "stage": stage,
        "result": state.get(RESULT_FIELD[stage]),
        "reason": state.get(REASON_FIELD[stage]),
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            state.get("collective_signals")
        ).get("digest"),
        "traversal_id": state.get("traversal_id"),
        "state_hash_entering_stage": state_hash_entering_stage,
        "state_hash_before_token": state.get("state_hash"),
        "chain_hash_entering_finalisation": (
            current_chain_hash(state) if chain_valid else "INVALID_HASH_CHAIN"
        ),
        "tier": _mapping(state.get("safety_profile")).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "authority_scope": {
            "resolved_authority": state.get("resolved_authority"),
            "jurisdiction": state.get("jurisdiction"),
        },
        "upstream_token_digests": _upstream_token_digests(state, stage),
        "upstream_evidence_digests": _upstream_evidence_digests(
            state, stage
        ),
        "stage_state": projection,
        "stage_state_digest": generate_digest(projection),
        "decision_state_digest": "",
        "logical_index": len(chain) + 1 if chain_valid else None,
        "timestamp_authority": "CANONICAL_RUNTIME",
        "nonce": "",
    }
    payload["decision_state_digest"] = generate_digest(
        _decision_state_basis(payload)
    )
    payload["nonce"] = generate_digest(_nonce_basis(payload))
    digest = generate_digest(payload)
    signature = sign_payload(payload)
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "payload": payload,
        "evidence_digest": digest,
        "signature": signature,
        "verified": verify_signature(payload, signature),
    }


def stage_finalisation_payload(
    stage: str, evidence: Mapping[str, Any]
) -> Dict[str, Any]:
    payload = _mapping(evidence.get("payload"))
    return {
        "substage": "pass6_finalisation",
        "stage": stage,
        "result": payload.get("result"),
        "reason": payload.get("reason"),
        "evidence_digest": evidence.get("evidence_digest"),
        "stage_state_digest": payload.get("stage_state_digest"),
    }


def append_stage_finalisation(
    state: Mapping[str, Any], *, stage: str
) -> Dict[str, Any]:
    if not hash_chain_valid(state):
        working_state = deepcopy(dict(state))
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state.setdefault("audit_trace", []).append(
            {
                "stage": HASH_STAGE[stage],
                "result": "DENY",
                "reason": "hash_chain_finalisation_rejected",
            }
        )
        return working_state
    evidence = _mapping(state.get(EVIDENCE_FIELD[stage]))
    return append_hash_entry(
        state,
        stage=HASH_STAGE[stage],
        payload=stage_finalisation_payload(stage, evidence),
    )


def stage_token_payload(state: Mapping[str, Any], stage: str) -> Dict[str, Any]:
    evidence = _mapping(state.get(EVIDENCE_FIELD[stage]))
    evidence_payload = _mapping(evidence.get("payload"))
    projection = stage_projection(state, stage)
    payload: Dict[str, Any] = {
        f"{stage}_result": state.get(RESULT_FIELD[stage]),
        f"{stage}_reason": state.get(REASON_FIELD[stage]),
        "stage_evidence_digest": evidence.get("evidence_digest"),
        "stage_state_digest": generate_digest(projection),
        "decision_state_digest": evidence_payload.get(
            "decision_state_digest"
        ),
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            state.get("collective_signals")
        ).get("digest"),
        "traversal_id": state.get("traversal_id"),
        "tier": _mapping(state.get("safety_profile")).get("computed_tier"),
        "upstream_token_digests": evidence_payload.get(
            "upstream_token_digests"
        ),
        "upstream_evidence_digests": evidence_payload.get(
            "upstream_evidence_digests"
        ),
        "constraint_snapshot": projection.get("constraint_snapshot"),
    }
    if stage == "domain":
        feedback = _mapping(projection.get("domain_feedback"))
        payload.update(
            {
                "domain_candidate_digest": generate_digest(
                    dict(_mapping(projection.get("domain_candidate")))
                ),
                "domain_attempts_digest": generate_digest(
                    feedback.get("attempts", [])
                ),
                "domain_results_digest": generate_digest(
                    feedback.get("domain_results", [])
                ),
            }
        )
    else:
        feedback = _mapping(projection.get("aurion_feedback"))
        candidate = _mapping(projection.get("selected_candidate"))
        payload.update(
            {
                "domain_evidence_digest": projection.get(
                    "domain_evidence_digest"
                ),
                "domain_candidate_digest": projection.get(
                    "domain_candidate_digest"
                ),
                "selected_candidate_digest": generate_digest(
                    dict(candidate)
                ),
                "selected_pathway_digest": generate_digest(
                    dict(_mapping(candidate.get("pathway")))
                ),
                "ordered_candidate_set_digest": feedback.get(
                    "ordered_candidate_set_digest"
                ),
                "rejected_candidates_digest": generate_digest(
                    feedback.get("rejected_candidates", [])
                ),
            }
        )
    return payload


def validate_stage_token_semantics(
    state: Mapping[str, Any], stage: str, payload: Mapping[str, Any]
) -> bool:
    evidence_valid, _ = validate_stage_evidence(state, stage)
    return evidence_valid and dict(payload) == stage_token_payload(state, stage)


def validate_stage_evidence(
    state: Mapping[str, Any], stage: str
) -> tuple[bool, list[str]]:
    if stage not in CONTROLLED_STAGES:
        return False, [f"unsupported_domain_aurion_stage:{stage}"]
    failures: list[str] = []
    evidence = state.get(EVIDENCE_FIELD[stage])
    if not isinstance(evidence, Mapping):
        return False, [f"{stage}_evidence_missing"]
    if set(evidence) != EVIDENCE_WRAPPER_FIELDS:
        failures.append(f"{stage}_evidence_wrapper_invalid")
    payload = evidence.get("payload")
    if not isinstance(payload, Mapping):
        return False, sorted(
            set(failures + [f"{stage}_evidence_payload_missing"])
        )
    if set(payload) != EVIDENCE_PAYLOAD_FIELDS:
        failures.append(f"{stage}_evidence_payload_schema_invalid")
    if (
        evidence.get("schema_version") != EVIDENCE_SCHEMA_VERSION
        or payload.get("schema_version") != EVIDENCE_SCHEMA_VERSION
    ):
        failures.append(f"{stage}_evidence_version_invalid")
    if evidence.get("evidence_digest") != generate_digest(dict(payload)):
        failures.append(f"{stage}_evidence_digest_invalid")
    try:
        signature_valid = verify_signature(
            payload, evidence.get("signature", {})
        )
    except (AttributeError, TypeError, ValueError):
        signature_valid = False
    if evidence.get("verified") is not True or not signature_valid:
        failures.append(f"{stage}_evidence_signature_invalid")

    expected_common = {
        "stage": stage,
        "result": state.get(RESULT_FIELD[stage]),
        "reason": state.get(REASON_FIELD[stage]),
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            state.get("collective_signals")
        ).get("digest"),
        "traversal_id": state.get("traversal_id"),
        "tier": _mapping(state.get("safety_profile")).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "authority_scope": {
            "resolved_authority": state.get("resolved_authority"),
            "jurisdiction": state.get("jurisdiction"),
        },
        "upstream_token_digests": _upstream_token_digests(state, stage),
        "upstream_evidence_digests": _upstream_evidence_digests(
            state, stage
        ),
        "timestamp_authority": "CANONICAL_RUNTIME",
    }
    for field, expected in expected_common.items():
        if payload.get(field) != expected:
            failures.append(f"{stage}_evidence_mismatch:{field}")
    projection = stage_projection(state, stage)
    audit_lineage = _mapping(projection.get("audit_lineage"))
    if (
        audit_lineage.get("terminal_present") is not True
        or audit_lineage.get("terminal_entry_count") != 1
        or not isinstance(audit_lineage.get("entry_count"), int)
        or audit_lineage.get("entry_count", 0) < 1
    ):
        failures.append(f"{stage}_audit_lineage_invalid")
    if payload.get("stage_state") != projection:
        failures.append(f"{stage}_evidence_mismatch:stage_state")
    if payload.get("stage_state_digest") != generate_digest(projection):
        failures.append(f"{stage}_evidence_mismatch:stage_state_digest")
    if payload.get("decision_state_digest") != generate_digest(
        _decision_state_basis(payload)
    ):
        failures.append(f"{stage}_evidence_mismatch:decision_state_digest")
    for field in ("state_hash_entering_stage", "state_hash_before_token"):
        if not isinstance(payload.get(field), str) or not payload.get(field):
            failures.append(f"{stage}_evidence_{field}_invalid")
    if not isinstance(payload.get("logical_index"), int) or isinstance(
        payload.get("logical_index"), bool
    ):
        failures.append(f"{stage}_evidence_logical_index_invalid")
    if payload.get("nonce") != generate_digest(_nonce_basis(payload)):
        failures.append(f"{stage}_evidence_nonce_invalid")
    if not hash_chain_valid(state):
        failures.append(f"{stage}_hash_chain_invalid")

    expected_hash_payload = stage_finalisation_payload(stage, evidence)
    expected_payload_hash = generate_digest(expected_hash_payload)
    chain = state.get("hash_chain", [])
    chain = chain if isinstance(chain, list) else []
    matches = [
        (index, entry)
        for index, entry in enumerate(chain, start=1)
        if isinstance(entry, Mapping)
        and entry.get("stage") == HASH_STAGE[stage]
        and entry.get("previous_hash")
        == payload.get("chain_hash_entering_finalisation")
        and entry.get("payload_hash") == expected_payload_hash
    ]
    if len(matches) != 1:
        failures.append(f"{stage}_evidence_hash_lineage_invalid")
    elif matches[0][0] != payload.get("logical_index"):
        failures.append(f"{stage}_evidence_logical_index_mismatch")
    stage_indexes = [
        index
        for index, entry in enumerate(chain, start=1)
        if isinstance(entry, Mapping)
        and entry.get("stage") == HASH_STAGE[stage]
    ]
    if matches and stage_indexes and matches[0][0] != max(stage_indexes):
        failures.append(f"{stage}_evidence_superseded")
    history_valid, history_failures = validate_stage_history(state, stage)
    if not history_valid:
        failures.extend(history_failures)
    return not failures, sorted(set(failures))


def stage_already_completed(state: Mapping[str, Any], stage: str) -> bool:
    if isinstance(state.get(EVIDENCE_FIELD[stage]), Mapping):
        return True
    if isinstance(_mapping(state.get("tokens")).get(stage), Mapping):
        return True
    order = state.get("integration_stage_order", [])
    if isinstance(order, list) and HASH_STAGE[stage] in order:
        return True
    chain = state.get("hash_chain", [])
    return isinstance(chain, list) and any(
        isinstance(entry, Mapping)
        and entry.get("stage") == HASH_STAGE[stage]
        for entry in chain
    )


def invalidate_from_stage(
    state: Mapping[str, Any], stage: str
) -> Dict[str, Any]:
    stripped_state = _strip_pre_execution_permission_fields(dict(state))
    working_state = (
        dict(stripped_state) if isinstance(stripped_state, Mapping) else {}
    )
    tokens = dict(_mapping(working_state.get("tokens")))
    for name in _DOWNSTREAM_TOKENS[stage]:
        tokens.pop(name, None)
    working_state["tokens"] = tokens
    for field in _DOWNSTREAM_FIELDS[stage]:
        working_state.pop(field, None)
    for field in _TERMINAL_FIELDS:
        working_state.pop(field, None)
    feedback = dict(_mapping(working_state.get("governance_feedback")))
    if stage == "domain":
        feedback.pop("domain_wrap", None)
    feedback.pop("aurion", None)
    working_state["governance_feedback"] = feedback
    order = working_state.get("integration_stage_order", [])
    if isinstance(order, list):
        cutoff = HASH_STAGE[stage]
        if cutoff in order:
            order = order[: order.index(cutoff)]
        working_state["integration_stage_order"] = order
    return working_state


def neutralize_denied_execution_state(
    state: Mapping[str, Any],
    *,
    permitted_stage_tokens: tuple[str, ...],
    decision: str = "DENY",
) -> Dict[str, Any]:
    """Return an unambiguously non-authorizing Pass 6 denial state."""
    working_state = deepcopy(dict(state))
    working_state["decision"] = (
        decision if decision in {"DENY", "ESCALATE"} else "DENY"
    )
    working_state["execution_result"] = "HALT"
    for field, value in _PRE_EXECUTION_NEUTRAL_FIELDS.items():
        working_state[field] = deepcopy(value)
    permitted_tokens = set(required_threshold_token_names()) | {
        "threshold_bundle",
        *permitted_stage_tokens,
    }
    tokens = dict(_mapping(working_state.get("tokens")))
    working_state["tokens"] = {
        name: token
        for name, token in tokens.items()
        if name in permitted_tokens
    }
    trace = working_state.get("token_trace", [])
    if isinstance(trace, list):
        working_state["token_trace"] = [
            deepcopy(entry)
            for entry in trace
            if not isinstance(entry, Mapping)
            or entry.get("name") in permitted_tokens
        ]
    else:
        working_state["token_trace"] = []

    reentry = dict(_mapping(working_state.get("governed_reentry")))
    reentry.pop("reentry_completed", None)
    working_state["governed_reentry"] = reentry
    return working_state


def append_stage_history(
    state: Mapping[str, Any],
    *,
    stage: str,
    result: str,
    reason: str,
    failures: list[str],
) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    histories = dict(_mapping(working_state.get("domain_aurion_history")))
    histories.setdefault("domain", [])
    histories.setdefault("aurion", [])
    history = _history({"domain_aurion_history": histories}, stage)
    core = {
        "sequence": len(history) + 1,
        "stage": stage,
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            working_state.get("collective_signals")
        ).get("digest"),
        "traversal_id": working_state.get("traversal_id"),
        "result": result,
        "reason": reason,
        "failures": sorted(set(str(item) for item in failures)),
        "prior_history_digest": generate_digest(history),
    }
    history.append({**core, "entry_digest": generate_digest(core)})
    histories[stage] = history
    working_state["domain_aurion_history"] = histories
    return working_state


def validate_stage_history(
    state: Mapping[str, Any], stage: str
) -> tuple[bool, list[str]]:
    history = _history(state, stage)
    if not history:
        return False, [f"{stage}_history_missing"]
    failures: list[str] = []
    prior: list[Any] = []
    for index, entry in enumerate(history, start=1):
        if not isinstance(entry, Mapping):
            failures.append(f"{stage}_history_entry_invalid:{index}")
            prior.append(entry)
            continue
        core = {
            key: entry.get(key)
            for key in (
                "sequence",
                "stage",
                "request_fingerprint",
                "eie_digest",
                "collective_signal_digest",
                "traversal_id",
                "result",
                "reason",
                "failures",
                "prior_history_digest",
            )
        }
        if entry.get("sequence") != index or entry.get("stage") != stage:
            failures.append(f"{stage}_history_sequence_invalid:{index}")
        if entry.get("prior_history_digest") != generate_digest(prior):
            failures.append(f"{stage}_history_link_invalid:{index}")
        if entry.get("entry_digest") != generate_digest(core):
            failures.append(f"{stage}_history_digest_invalid:{index}")
        prior.append(dict(entry))
    latest = _mapping(history[-1])
    expected = {
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            state.get("collective_signals")
        ).get("digest"),
        "traversal_id": state.get("traversal_id"),
        "result": state.get(RESULT_FIELD[stage]),
        "reason": state.get(REASON_FIELD[stage]),
    }
    for field, value in expected.items():
        if latest.get(field) != value:
            failures.append(f"{stage}_history_{field}_mismatch")
    return not failures, sorted(set(failures))


def hash_chain_valid(state: Mapping[str, Any]) -> bool:
    chain = state.get("hash_chain", [])
    if not isinstance(chain, list) or any(
        not isinstance(entry, Mapping) for entry in chain
    ):
        return False
    try:
        return verify_hash_chain(state)
    except (AttributeError, TypeError, ValueError):
        return False


def live_state_hash_valid(state: Mapping[str, Any]) -> bool:
    try:
        return hash_chain_valid(state) and state.get(
            "state_hash"
        ) == rebuild_state_hash(state)
    except Exception:
        return False


def _aurion_finalisation_hash(state: Mapping[str, Any]) -> object:
    evidence = _mapping(state.get("aurion_evidence"))
    payload = _mapping(evidence.get("payload"))
    index = payload.get("logical_index")
    chain = state.get("hash_chain", [])
    if (
        isinstance(index, int)
        and not isinstance(index, bool)
        and isinstance(chain, list)
        and 1 <= index <= len(chain)
        and isinstance(chain[index - 1], Mapping)
    ):
        return chain[index - 1].get("hash")
    return None


def _handoff_immutable_payload(state: Mapping[str, Any]) -> Dict[str, Any]:
    tokens = _mapping(state.get("tokens"))
    domain_evidence = _mapping(state.get("domain_evidence"))
    aurion_evidence = _mapping(state.get("aurion_evidence"))
    domain_payload = _mapping(domain_evidence.get("payload"))
    aurion_payload = _mapping(aurion_evidence.get("payload"))
    candidate = _mapping(state.get("current_candidate"))
    feedback = _mapping(_mapping(state.get("governance_feedback")).get("aurion"))
    order = state.get("integration_stage_order", [])
    prefix = (
        list(order[: len(_PIPELINE_PREFIX_THROUGH_AURION)])
        if isinstance(order, list)
        else []
    )
    return {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "boundary": "execution_convergence_entry",
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "collective_signal_digest": _mapping(
            state.get("collective_signals")
        ).get("digest"),
        "traversal_id": state.get("traversal_id"),
        "aurion_finalisation_hash": _aurion_finalisation_hash(state),
        "integration_stage_prefix": prefix,
        "domain_evidence_digest": domain_evidence.get("evidence_digest"),
        "aurion_evidence_digest": aurion_evidence.get("evidence_digest"),
        "domain_stage_state_digest": domain_payload.get("stage_state_digest"),
        "aurion_stage_state_digest": aurion_payload.get("stage_state_digest"),
        "domain_token_digest": _mapping(tokens.get("domain")).get("digest"),
        "aurion_token_digest": _mapping(tokens.get("aurion")).get("digest"),
        "selected_candidate_digest": generate_digest(dict(candidate)),
        "selected_pathway_digest": generate_digest(
            dict(_mapping(candidate.get("pathway")))
        ),
        "ordered_candidate_set_digest": feedback.get(
            "ordered_candidate_set_digest"
        ),
        "constraint_snapshot_digest": generate_digest(
            constraint_snapshot(state)
        ),
        "governed_reentry_digest": generate_digest(
            normalized_governed_reentry(state)
        ),
        "domain_history_digest": generate_digest(_history(state, "domain")),
        "aurion_history_digest": generate_digest(_history(state, "aurion")),
        "timestamp_authority": "CANONICAL_RUNTIME",
    }


def build_execution_convergence_handoff(
    state: Mapping[str, Any]
) -> Dict[str, Any]:
    payload = {
        **_handoff_immutable_payload(state),
        "state_hash_entering_handoff": state.get("state_hash"),
        "nonce": "",
    }
    payload["nonce"] = generate_digest(
        {key: value for key, value in payload.items() if key != "nonce"}
    )
    digest = generate_digest(payload)
    signature = sign_payload(payload)
    return {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "payload": payload,
        "handoff_digest": digest,
        "signature": signature,
        "verified": verify_signature(payload, signature),
    }


def validate_handoff_evidence(
    state: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    record = state.get("execution_convergence_handoff")
    if not isinstance(record, Mapping):
        return False, ["execution_convergence_handoff_missing"]
    if set(record) != HANDOFF_WRAPPER_FIELDS:
        failures.append("execution_convergence_handoff_wrapper_invalid")
    payload = record.get("payload")
    if not isinstance(payload, Mapping):
        return False, sorted(
            set(failures + ["execution_convergence_handoff_payload_missing"])
        )
    if set(payload) != HANDOFF_PAYLOAD_FIELDS:
        failures.append("execution_convergence_handoff_schema_invalid")
    if (
        record.get("schema_version") != HANDOFF_SCHEMA_VERSION
        or payload.get("schema_version") != HANDOFF_SCHEMA_VERSION
    ):
        failures.append("execution_convergence_handoff_version_invalid")
    if record.get("handoff_digest") != generate_digest(dict(payload)):
        failures.append("execution_convergence_handoff_digest_invalid")
    try:
        signature_valid = verify_signature(payload, record.get("signature", {}))
    except (AttributeError, TypeError, ValueError):
        signature_valid = False
    if record.get("verified") is not True or not signature_valid:
        failures.append("execution_convergence_handoff_signature_invalid")
    expected = _handoff_immutable_payload(state)
    for field, value in expected.items():
        if payload.get(field) != value:
            failures.append(f"execution_convergence_handoff_mismatch:{field}")
    if payload.get("integration_stage_prefix") != list(
        _PIPELINE_PREFIX_THROUGH_AURION
    ):
        failures.append("execution_convergence_handoff_stage_order_invalid")
    if payload.get("nonce") != generate_digest(
        {key: value for key, value in payload.items() if key != "nonce"}
    ):
        failures.append("execution_convergence_handoff_nonce_invalid")
    if not isinstance(payload.get("state_hash_entering_handoff"), str) or not payload.get(
        "state_hash_entering_handoff"
    ):
        failures.append("execution_convergence_handoff_state_hash_invalid")
    execution_token = _mapping(_mapping(state.get("tokens")).get("execution_boundary"))
    if not execution_token:
        pre_handoff = deepcopy(dict(state))
        pre_handoff.pop("execution_convergence_handoff", None)
        if payload.get("state_hash_entering_handoff") != rebuild_state_hash(
            pre_handoff
        ):
            failures.append("execution_convergence_handoff_state_hash_mismatch")
    return not failures, sorted(set(failures))
