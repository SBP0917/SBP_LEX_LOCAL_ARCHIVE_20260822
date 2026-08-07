from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.shared.hash_chain import (
    append_hash_entry,
    current_chain_hash,
    rebuild_state_hash,
    verify_hash_chain,
)


EVIDENCE_SCHEMA_VERSION = "desktop-v1.governed-stage-evidence.v1"
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

GOVERNED_STAGES = ("classification", "licensing", "governance", "grc")
EVIDENCE_FIELD = {stage: f"{stage}_evidence" for stage in GOVERNED_STAGES}
RESULT_FIELD = {
    "classification": "classification_result",
    "licensing": "licensing_result",
    "governance": "governance_result",
    "grc": "grc_result",
}
REASON_FIELD = {
    "classification": "classification_reason",
    "licensing": "licensing_reason",
    "governance": "governance_reason",
    "grc": "grc_reason",
}

_UPSTREAM_TOKENS = {
    "classification": ("authority", "procedural_truth"),
    "licensing": ("authority", "procedural_truth", "classification"),
    "governance": (
        "authority",
        "procedural_truth",
        "classification",
        "licensing",
    ),
    "grc": (
        "authority",
        "procedural_truth",
        "classification",
        "licensing",
        "governance",
    ),
}

_DOWNSTREAM_TOKENS = {
    "classification": (
        "classification",
        "licensing",
        "governance",
        "grc",
        "domain",
        "aurion",
        "execution_boundary",
        "execution_attestation",
        "token_bundle",
    ),
    "licensing": (
        "licensing",
        "governance",
        "grc",
        "domain",
        "aurion",
        "execution_boundary",
        "execution_attestation",
        "token_bundle",
    ),
    "governance": (
        "governance",
        "grc",
        "domain",
        "aurion",
        "execution_boundary",
        "execution_attestation",
        "token_bundle",
    ),
    "grc": (
        "grc",
        "domain",
        "aurion",
        "execution_boundary",
        "execution_attestation",
        "token_bundle",
    ),
}

_DOWNSTREAM_FIELDS = {
    "classification": (
        "classification",
        "classification_result",
        "classification_reason",
        "classification_evidence",
        "pipeline_mode",
        "licensing",
        "licensing_result",
        "licensing_reason",
        "licensing_scope",
        "licensing_evidence",
        "governance_state",
        "governance_result",
        "governance_reason",
        "governance_evidence",
        "grc_state",
        "grc_result",
        "grc_reason",
        "governed_reentry",
        "grc_evidence",
        "domain_result",
        "aurion15_result",
    ),
    "licensing": (
        "licensing",
        "licensing_result",
        "licensing_reason",
        "licensing_scope",
        "licensing_evidence",
        "governance_state",
        "governance_result",
        "governance_reason",
        "governance_evidence",
        "grc_state",
        "grc_result",
        "grc_reason",
        "governed_reentry",
        "grc_evidence",
        "domain_result",
        "aurion15_result",
    ),
    "governance": (
        "governance_state",
        "governance_result",
        "governance_reason",
        "governance_evidence",
        "grc_state",
        "grc_result",
        "grc_reason",
        "governed_reentry",
        "grc_evidence",
        "domain_result",
        "aurion15_result",
    ),
    "grc": (
        "grc_state",
        "grc_result",
        "grc_reason",
        "governed_reentry",
        "grc_evidence",
        "domain_result",
        "aurion15_result",
    ),
}

_TERMINAL_FIELDS = (
    "audit_record",
    "audit_hash",
    "audit_finalisation",
    "controlled_outcome",
    "final_outcome",
    "pipeline_convergence",
    "pipeline_b_summary",
    "pipeline_governed_stage_parity",
    "execution_attestation",
    "execution_verified",
)

_STAGE_COMPLETION_TAILS = {
    "classification": {
        "classification",
        "licensing",
        "governance",
        "grc",
        "domain_wrap",
        "aurion_runtime",
        "execution_gate",
        "audit",
    },
    "licensing": {
        "licensing",
        "governance",
        "grc",
        "domain_wrap",
        "aurion_runtime",
        "execution_gate",
        "audit",
    },
    "governance": {
        "governance",
        "grc",
        "domain_wrap",
        "aurion_runtime",
        "execution_gate",
        "audit",
    },
    "grc": {
        "grc",
        "domain_wrap",
        "aurion_runtime",
        "execution_gate",
        "audit",
    },
}


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _record_digest(record: object, *names: str) -> object:
    if not isinstance(record, Mapping):
        return None
    for name in names:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return None


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
    stage_index = GOVERNED_STAGES.index(stage)
    for prior in GOVERNED_STAGES[:stage_index]:
        values[prior] = evidence_digest(state, prior)
    return values


def _constraint_snapshot(
    state: Mapping[str, Any], stage: str
) -> Dict[str, Any]:
    classification = _mapping(state.get("classification"))
    snapshot: Dict[str, Any] = {
        "computed_tier": _mapping(state.get("safety_profile")).get(
            "computed_tier"
        ),
        "corroboration_required": state.get("corroboration_required"),
        "resolved_authority": state.get("resolved_authority"),
        "jurisdiction": state.get("jurisdiction"),
        "autonomy_level": classification.get("autonomy_level"),
        "autonomy_ceiling": classification.get("autonomy_ceiling"),
        "operational_scope": classification.get("operational_scope"),
        "pt_result": state.get("procedural_truth_result"),
        "pt_outcome": state.get("procedural_truth_outcome"),
    }
    if GOVERNED_STAGES.index(stage) >= GOVERNED_STAGES.index("licensing"):
        snapshot["licensing_scope"] = state.get("licensing_scope")
    return snapshot


def stage_projection(state: Mapping[str, Any], stage: str) -> Dict[str, Any]:
    if stage not in GOVERNED_STAGES:
        raise ValueError(f"unsupported_governed_stage:{stage}")
    projection: Dict[str, Any] = {
        "result": state.get(RESULT_FIELD[stage]),
        "reason": state.get(REASON_FIELD[stage]),
        "constraint_snapshot": _constraint_snapshot(state, stage),
    }
    if stage == "classification":
        projection.update(
            {
                "classification": deepcopy(dict(_mapping(state.get("classification")))),
                "pipeline_mode": state.get("pipeline_mode"),
                "ap_acf_declaration_hash": state.get(
                    "ap_acf_declaration_hash"
                ),
            }
        )
    elif stage == "licensing":
        projection.update(
            {
                "licensing": deepcopy(dict(_mapping(state.get("licensing")))),
                "licensing_scope": state.get("licensing_scope"),
            }
        )
    elif stage == "governance":
        feedback = _mapping(state.get("governance_feedback"))
        projection.update(
            {
                "governance_state": deepcopy(
                    dict(_mapping(state.get("governance_state")))
                ),
                "governance_history": deepcopy(
                    list(feedback.get("history", []))
                    if isinstance(feedback.get("history", []), list)
                    else []
                ),
                "last_denied_fingerprint": state.get(
                    "last_denied_fingerprint"
                ),
            }
        )
    else:
        feedback = _mapping(state.get("governance_feedback"))
        governed_reentry = dict(_mapping(state.get("governed_reentry")))
        # Completion is a later controlled-return fact.  GRC owns and signs
        # eligibility, while the downstream controlled-outcome layer may append
        # this single completion marker without rewriting GRC truth.
        governed_reentry.pop("reentry_completed", None)
        projection.update(
            {
                "grc_state": deepcopy(dict(_mapping(state.get("grc_state")))),
                "governed_reentry": deepcopy(governed_reentry),
                "governance_history": deepcopy(
                    list(feedback.get("history", []))
                    if isinstance(feedback.get("history", []), list)
                    else []
                ),
                "reentry_input_snapshot": {
                    "last_denied_fingerprint": state.get(
                        "last_denied_fingerprint"
                    ),
                    "prior_denied_fingerprint": _mapping(
                        state.get("context")
                    ).get("prior_denied_fingerprint"),
                    "material_change_declared": _mapping(
                        state.get("context")
                    ).get("material_change_declared", False),
                    "material_change_reason": _mapping(
                        state.get("context")
                    ).get("material_change_reason"),
                    "escalation_path_available": _mapping(
                        state.get("context")
                    ).get("escalation_path_available", False),
                },
            }
        )
    return projection


def _decision_state_basis(payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": payload.get("schema_version"),
        "stage": payload.get("stage"),
        "result": payload.get("result"),
        "reason": payload.get("reason"),
        "request_fingerprint": payload.get("request_fingerprint"),
        "eie_digest": payload.get("eie_digest"),
        "traversal_id": payload.get("traversal_id"),
        "state_hash_entering_stage": payload.get("state_hash_entering_stage"),
        "state_hash_before_token": payload.get("state_hash_before_token"),
        "chain_hash_entering_finalisation": payload.get(
            "chain_hash_entering_finalisation"
        ),
        "tier": payload.get("tier"),
        "corroboration_required": payload.get("corroboration_required"),
        "authority_scope": payload.get("authority_scope"),
        "upstream_token_digests": payload.get("upstream_token_digests"),
        "upstream_evidence_digests": payload.get(
            "upstream_evidence_digests"
        ),
        "stage_state_digest": payload.get("stage_state_digest"),
    }


def _nonce_basis(payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "stage": payload.get("stage"),
        "request_fingerprint": payload.get("request_fingerprint"),
        "eie_digest": payload.get("eie_digest"),
        "traversal_id": payload.get("traversal_id"),
        "state_hash_entering_stage": payload.get("state_hash_entering_stage"),
        "state_hash_before_token": payload.get("state_hash_before_token"),
        "chain_hash_entering_finalisation": payload.get(
            "chain_hash_entering_finalisation"
        ),
        "stage_state_digest": payload.get("stage_state_digest"),
        "decision_state_digest": payload.get("decision_state_digest"),
        "logical_index": payload.get("logical_index"),
        "upstream_token_digests": payload.get("upstream_token_digests"),
        "upstream_evidence_digests": payload.get(
            "upstream_evidence_digests"
        ),
    }


def build_stage_evidence(
    state: Mapping[str, Any],
    *,
    stage: str,
    state_hash_entering_stage: object,
) -> Dict[str, Any]:
    projection = stage_projection(state, stage)
    chain = state.get("hash_chain", [])
    chain_valid = governed_hash_chain_valid(state)
    logical_index = len(chain) + 1 if chain_valid else None
    chain_head = current_chain_hash(state) if chain_valid else "INVALID_HASH_CHAIN"
    payload: Dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "stage": stage,
        "result": state.get(RESULT_FIELD[stage]),
        "reason": state.get(REASON_FIELD[stage]),
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "traversal_id": state.get("traversal_id"),
        "state_hash_entering_stage": state_hash_entering_stage,
        "state_hash_before_token": state.get("state_hash"),
        "chain_hash_entering_finalisation": chain_head,
        "tier": _mapping(state.get("safety_profile")).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "authority_scope": {
            "resolved_authority": state.get("resolved_authority"),
            "jurisdiction": state.get("jurisdiction"),
        },
        "upstream_token_digests": _upstream_token_digests(state, stage),
        "upstream_evidence_digests": _upstream_evidence_digests(state, stage),
        "stage_state": projection,
        "stage_state_digest": generate_digest(projection),
        "decision_state_digest": "",
        "logical_index": logical_index,
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
        "substage": "pass5_finalisation",
        "stage": stage,
        "result": payload.get("result"),
        "reason": payload.get("reason"),
        "evidence_digest": evidence.get("evidence_digest"),
        "stage_state_digest": payload.get("stage_state_digest"),
    }


def append_stage_finalisation(
    state: Mapping[str, Any], *, stage: str
) -> Dict[str, Any]:
    evidence = _mapping(state.get(EVIDENCE_FIELD[stage]))
    if not governed_hash_chain_valid(state):
        working_state = deepcopy(dict(state))
        working_state["decision"] = "DENY"
        working_state["execution_result"] = "HALT"
        working_state.setdefault("audit_trace", []).append(
            {
                "stage": stage,
                "result": "DENY",
                "reason": "hash_chain_finalisation_rejected",
            }
        )
        return working_state
    return append_hash_entry(
        state,
        stage=stage,
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
    if stage == "classification":
        classification = _mapping(state.get("classification"))
        payload.update(
            {
                "ap_acf_class": classification.get("ap_acf_class"),
                "subclass": classification.get("subclass"),
                "autonomy_level": classification.get("autonomy_level"),
                "autonomy_ceiling": classification.get("autonomy_ceiling"),
                "public_exposure": classification.get("public_exposure"),
                "operational_scope": classification.get("operational_scope"),
                "pipeline_mode": state.get("pipeline_mode"),
            }
        )
    elif stage == "licensing":
        licensing = _mapping(state.get("licensing"))
        payload.update(
            {
                "licence_state": licensing.get("licence_state"),
                "autonomy_check": licensing.get("autonomy_check"),
                "scope_check": licensing.get("scope_check"),
            }
        )
    elif stage == "governance":
        payload.update(
            {
                "authority_first_result": state.get("authority_first_result"),
                "procedural_truth_result": state.get(
                    "procedural_truth_result"
                ),
                "classification_result": state.get("classification_result"),
                "licensing_result": state.get("licensing_result"),
            }
        )
    else:
        governed_reentry = projection.get("governed_reentry", {})
        payload.update(
            {
                "governance_result": state.get("governance_result"),
                "reentry_digest": generate_digest(
                    dict(_mapping(governed_reentry))
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
    failures: list[str] = []
    evidence = state.get(EVIDENCE_FIELD[stage])
    if not isinstance(evidence, Mapping):
        return False, [f"{stage}_evidence_missing"]
    if set(evidence) != EVIDENCE_WRAPPER_FIELDS:
        failures.append(f"{stage}_evidence_wrapper_invalid")
    payload = evidence.get("payload")
    if not isinstance(payload, Mapping):
        return False, sorted(set(failures + [f"{stage}_evidence_payload_missing"]))
    if set(payload) != EVIDENCE_PAYLOAD_FIELDS:
        failures.append(f"{stage}_evidence_payload_schema_invalid")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA_VERSION or payload.get(
        "schema_version"
    ) != EVIDENCE_SCHEMA_VERSION:
        failures.append(f"{stage}_evidence_version_invalid")
    if evidence.get("evidence_digest") != generate_digest(dict(payload)):
        failures.append(f"{stage}_evidence_digest_invalid")
    if evidence.get("verified") is not True or not verify_signature(
        payload, evidence.get("signature", {})
    ):
        failures.append(f"{stage}_evidence_signature_invalid")
    expected_common = {
        "stage": stage,
        "result": state.get(RESULT_FIELD[stage]),
        "reason": state.get(REASON_FIELD[stage]),
        "request_fingerprint": state.get("request_fingerprint"),
        "eie_digest": state.get("eie_hash"),
        "traversal_id": state.get("traversal_id"),
        "tier": _mapping(state.get("safety_profile")).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "authority_scope": {
            "resolved_authority": state.get("resolved_authority"),
            "jurisdiction": state.get("jurisdiction"),
        },
        "upstream_token_digests": _upstream_token_digests(state, stage),
        "upstream_evidence_digests": _upstream_evidence_digests(state, stage),
        "timestamp_authority": "CANONICAL_RUNTIME",
    }
    for field, expected in expected_common.items():
        if payload.get(field) != expected:
            failures.append(f"{stage}_evidence_mismatch:{field}")
    projection = stage_projection(state, stage)
    if payload.get("stage_state") != projection:
        failures.append(f"{stage}_evidence_mismatch:stage_state")
    if payload.get("stage_state_digest") != generate_digest(projection):
        failures.append(f"{stage}_evidence_mismatch:stage_state_digest")
    if payload.get("decision_state_digest") != generate_digest(
        _decision_state_basis(payload)
    ):
        failures.append(f"{stage}_evidence_mismatch:decision_state_digest")
    if not isinstance(payload.get("state_hash_entering_stage"), str) or not payload.get(
        "state_hash_entering_stage"
    ):
        failures.append(f"{stage}_evidence_state_hash_entering_stage_invalid")
    if not isinstance(payload.get("state_hash_before_token"), str) or not payload.get(
        "state_hash_before_token"
    ):
        failures.append(f"{stage}_evidence_state_hash_before_token_invalid")
    if not isinstance(payload.get("logical_index"), int) or isinstance(
        payload.get("logical_index"), bool
    ):
        failures.append(f"{stage}_evidence_logical_index_invalid")
    if payload.get("nonce") != generate_digest(_nonce_basis(payload)):
        failures.append(f"{stage}_evidence_nonce_invalid")
    if not governed_hash_chain_valid(state):
        failures.append(f"{stage}_hash_chain_invalid")
    expected_hash_payload = stage_finalisation_payload(stage, evidence)
    expected_payload_hash = generate_digest(expected_hash_payload)
    chain = state.get("hash_chain", [])
    chain = chain if isinstance(chain, list) else []
    matches = [
        (index, entry)
        for index, entry in enumerate(chain, start=1)
        if isinstance(entry, Mapping)
        and entry.get("stage") == stage
        and entry.get("previous_hash")
        == payload.get("chain_hash_entering_finalisation")
        and entry.get("payload_hash") == expected_payload_hash
    ]
    if len(matches) != 1:
        failures.append(f"{stage}_evidence_hash_lineage_invalid")
    elif matches[0][0] != payload.get("logical_index"):
        failures.append(f"{stage}_evidence_logical_index_mismatch")
    stage_entry_indexes = [
        index
        for index, entry in enumerate(chain, start=1)
        if isinstance(entry, Mapping) and entry.get("stage") == stage
    ]
    if matches and stage_entry_indexes and matches[0][0] != max(stage_entry_indexes):
        failures.append(f"{stage}_evidence_superseded")
    return not failures, sorted(set(failures))


def stage_already_completed(state: Mapping[str, Any], stage: str) -> bool:
    if isinstance(state.get(EVIDENCE_FIELD[stage]), Mapping):
        return True
    tokens = _mapping(state.get("tokens"))
    if isinstance(tokens.get(stage), Mapping):
        return True
    chain = state.get("hash_chain", [])
    if not isinstance(chain, list):
        return False
    return any(
        isinstance(entry, Mapping)
        and entry.get("stage") in _STAGE_COMPLETION_TAILS[stage]
        for entry in chain
    )


def invalidate_from_stage(
    state: Mapping[str, Any], stage: str
) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    tokens = dict(_mapping(working_state.get("tokens")))
    for name in _DOWNSTREAM_TOKENS[stage]:
        tokens.pop(name, None)
    working_state["tokens"] = tokens
    for field in _DOWNSTREAM_FIELDS[stage]:
        working_state.pop(field, None)
    for field in _TERMINAL_FIELDS:
        working_state.pop(field, None)
    feedback = dict(_mapping(working_state.get("governance_feedback")))
    start = GOVERNED_STAGES.index(stage)
    for name in GOVERNED_STAGES[start:]:
        feedback.pop(name, None)
    feedback.pop("domain_wrap", None)
    working_state["governance_feedback"] = feedback
    return working_state


def append_governance_history(
    state: Mapping[str, Any],
    *,
    result: str,
    reason: str,
    failures: list[str],
) -> Dict[str, Any]:
    working_state = deepcopy(dict(state))
    feedback = dict(_mapping(working_state.get("governance_feedback")))
    history = (
        deepcopy(list(feedback.get("history", [])))
        if isinstance(feedback.get("history", []), list)
        else []
    )
    prior_digest = generate_digest(history)
    entry_core = {
        "sequence": len(history) + 1,
        "request_fingerprint": working_state.get("request_fingerprint"),
        "eie_digest": working_state.get("eie_hash"),
        "traversal_id": working_state.get("traversal_id"),
        "result": result,
        "reason": reason,
        "failures": sorted(set(failures)),
        "prior_history_digest": prior_digest,
    }
    history.append({**entry_core, "entry_digest": generate_digest(entry_core)})
    feedback["history"] = history
    working_state["governance_feedback"] = feedback
    return working_state


def validate_governance_history(
    state: Mapping[str, Any]
) -> tuple[bool, list[str]]:
    feedback = _mapping(state.get("governance_feedback"))
    history = feedback.get("history")
    if not isinstance(history, list) or not history:
        return False, ["governance_history_missing"]
    failures: list[str] = []
    prior: list[object] = []
    for index, entry in enumerate(history, start=1):
        if not isinstance(entry, Mapping):
            failures.append(f"governance_history_entry_invalid:{index}")
            prior.append(entry)
            continue
        core = {
            key: entry.get(key)
            for key in (
                "sequence",
                "request_fingerprint",
                "eie_digest",
                "traversal_id",
                "result",
                "reason",
                "failures",
                "prior_history_digest",
            )
        }
        if entry.get("sequence") != index:
            failures.append(f"governance_history_sequence_invalid:{index}")
        if entry.get("prior_history_digest") != generate_digest(prior):
            failures.append(f"governance_history_link_invalid:{index}")
        if entry.get("entry_digest") != generate_digest(core):
            failures.append(f"governance_history_digest_invalid:{index}")
        prior.append(dict(entry))
    latest = _mapping(history[-1])
    if latest.get("request_fingerprint") != state.get("request_fingerprint"):
        failures.append("governance_history_request_mismatch")
    if latest.get("eie_digest") != state.get("eie_hash"):
        failures.append("governance_history_eie_mismatch")
    if latest.get("traversal_id") != state.get("traversal_id"):
        failures.append("governance_history_traversal_mismatch")
    if latest.get("result") != state.get("governance_result"):
        failures.append("governance_history_result_mismatch")
    if latest.get("reason") != state.get("governance_reason"):
        failures.append("governance_history_reason_mismatch")
    return not failures, sorted(set(failures))


def validate_constraint_continuity(
    state: Mapping[str, Any], *, through_stage: str
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    classification = _mapping(state.get("classification"))
    level = classification.get("autonomy_level")
    ceiling = classification.get("autonomy_ceiling")
    if (
        isinstance(level, bool)
        or not isinstance(level, int)
        or level < 0
        or level > 100
    ):
        failures.append("constraint_continuity:autonomy_level_invalid")
    if (
        isinstance(ceiling, bool)
        or not isinstance(ceiling, int)
        or ceiling < 0
        or ceiling > 100
    ):
        failures.append("constraint_continuity:autonomy_ceiling_invalid")
    if isinstance(level, int) and isinstance(ceiling, int) and not isinstance(
        level, bool
    ) and not isinstance(ceiling, bool):
        if level > ceiling:
            failures.append("constraint_continuity:autonomy_ceiling_exceeded")
    profile = _mapping(classification.get("class_profile"))
    profile_ceiling = profile.get("default_autonomy_ceiling")
    if isinstance(ceiling, int) and isinstance(profile_ceiling, int):
        if ceiling > profile_ceiling:
            failures.append("constraint_continuity:profile_ceiling_escalated")
    context = _mapping(state.get("context"))
    classified_scope = classification.get("operational_scope")
    if context.get("operational_scope") not in (None, classified_scope):
        failures.append("constraint_continuity:classification_scope_substituted")
    if GOVERNED_STAGES.index(through_stage) >= GOVERNED_STAGES.index(
        "licensing"
    ):
        requested_scope = context.get("requested_scope", classified_scope)
        if requested_scope != classified_scope:
            failures.append("constraint_continuity:licensing_scope_broadened")
        if state.get("licensing_scope") != classified_scope:
            failures.append("constraint_continuity:licensing_scope_mismatch")
        permitted_scopes = context.get("permitted_scopes", [])
        if permitted_scopes and classified_scope not in permitted_scopes:
            failures.append("constraint_continuity:scope_not_permitted")
        environment = _mapping(
            classification.get("environment_modifiers")
        ).get("environment")
        permitted_environments = context.get("permitted_environments", [])
        if permitted_environments and environment not in permitted_environments:
            failures.append("constraint_continuity:environment_not_permitted")
    snapshot = _mapping(state.get("request_identity_snapshot"))
    if state.get("resolved_authority") != snapshot.get("resolved_authority"):
        failures.append("constraint_continuity:authority_expanded")
    if state.get("jurisdiction") != snapshot.get("jurisdiction"):
        failures.append("constraint_continuity:jurisdiction_substituted")
    return not failures, sorted(set(failures))


def live_state_hash_valid(state: Mapping[str, Any]) -> bool:
    return governed_hash_chain_valid(state) and (
        state.get("state_hash") == rebuild_state_hash(state)
    )


def governed_hash_chain_valid(state: Mapping[str, Any]) -> bool:
    chain = state.get("hash_chain", [])
    if not isinstance(chain, list) or any(
        not isinstance(entry, Mapping) for entry in chain
    ):
        return False
    try:
        return verify_hash_chain(state)
    except (AttributeError, TypeError):
        return False
