from __future__ import annotations

from typing import Any, Mapping

from sbp_lex.security.pqc import generate_digest
from sbp_lex.security.token_stack import verify_token
from sbp_lex.config.security_config import STATE_VERSION

TOKEN_STAGE = {
    "authority": "root_of_trust",
    "procedural_truth": "procedural_truth",
    "classification": "classification",
    "licensing": "licensing",
    "governance": "governance",
    "domain": "domain_wrap",
    "aurion": "aurion_runtime",
    "execution_boundary": "execution_gate",
    "execution_attestation": "execution_gate",
}

CANONICAL_STAGE_SEQUENCE = (
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
    "execution_gate",
)


def verify_canonical_stage_lineage(
    state: Mapping[str, Any], *, required_tokens: tuple[str, ...]
) -> tuple[bool, list[str]]:
    order = state.get("integration_stage_order", [])
    if not isinstance(order, list):
        return False, ["traversal_bypass_detected:stage_order_missing"]
    required_stages = ["hard_ingress", "state_construction", "collective_attach", "ap_acf_precheck"]
    failures: list[str] = []
    if state.get("hard_entry_gate", {}).get("accepted") is not True:
        failures.append("traversal_bypass_detected:hard_entry_gate")
    for token_name in required_tokens:
        stage = TOKEN_STAGE.get(token_name)
        if stage and stage not in required_stages:
            required_stages.append(stage)
        if token_name == "governance" and "grc" not in required_stages:
            required_stages.append("grc")
    positions: list[int] = []
    for stage in required_stages:
        if order.count(stage) != 1:
            failures.append(f"traversal_bypass_detected:{stage}")
        else:
            positions.append(order.index(stage))
    if positions != sorted(positions):
        failures.append("traversal_bypass_detected:stage_order")
    canonical_positions = [CANONICAL_STAGE_SEQUENCE.index(stage) for stage in required_stages]
    if canonical_positions != sorted(canonical_positions):
        failures.append("traversal_bypass_detected:canonical_sequence")
    return not failures, sorted(set(failures))


def verify_request_identity_binding(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    snapshot = state.get("request_identity_snapshot")
    if not isinstance(snapshot, Mapping):
        return False, ["toctou_state_mismatch:request_snapshot_missing"]
    digest = generate_digest(dict(snapshot))
    if digest != state.get("request_identity_digest") or digest != state.get("request_fingerprint"):
        failures.append("toctou_state_mismatch:request_digest")
    for field in ("action", "payload", "context", "resolved_authority", "jurisdiction"):
        if state.get(field) != snapshot.get(field):
            failures.append(f"toctou_state_mismatch:{field}")
    return not failures, failures


def _semantic_token_matches(state: Mapping[str, Any], name: str, payload: Mapping[str, Any]) -> bool:
    if name == "authority":
        return (
            payload.get("authority_result") == state.get("authority_first_result")
            and payload.get("evidence_anchor_digest")
            == state.get("root_of_trust_evidence_anchor", {}).get("anchor_digest")
        )
    if name == "procedural_truth":
        return (
            payload.get("procedural_truth_result") == state.get("procedural_truth_result")
            and payload.get("procedural_truth_outcome") == state.get("procedural_truth_outcome")
            and payload.get("pt_evidence_envelope_digest")
            == state.get("pt_evidence_envelope_digest")
        )
    if name == "classification":
        classification = state.get("classification", {})
        return (
            state.get("classification_result") == "ALLOW"
            and payload.get("ap_acf_class") == classification.get("ap_acf_class")
            and payload.get("autonomy_level") == classification.get("autonomy_level")
            and payload.get("autonomy_ceiling") == classification.get("autonomy_ceiling")
            and payload.get("pipeline_mode") == state.get("pipeline_mode")
        )
    if name == "licensing":
        return payload.get("licensing_result") == state.get("licensing_result")
    if name == "governance":
        return (
            payload.get("governance_result") == state.get("governance_result")
            and payload.get("authority_first_result") == state.get("authority_first_result")
            and payload.get("procedural_truth_result") == state.get("procedural_truth_result")
            and payload.get("classification_result") == state.get("classification_result")
            and payload.get("licensing_result") == state.get("licensing_result")
        )
    if name == "domain":
        return payload.get("domain_result") == state.get("domain_result")
    if name == "aurion":
        return (
            payload.get("aurion15_result") == state.get("aurion15_result")
            and payload.get("candidate_id") == state.get("current_candidate", {}).get("candidate_id")
        )
    return False


def validate_canonical_upstream(
    state: Mapping[str, Any], *, required_tokens: tuple[str, ...]
) -> tuple[bool, list[str]]:
    _, failures = verify_request_identity_binding(state)
    _, stage_failures = verify_canonical_stage_lineage(state, required_tokens=required_tokens)
    failures.extend(stage_failures)
    if state.get("state_version") != STATE_VERSION:
        failures.append("protocol_downgrade_rejected:state_version")
    tokens = state.get("tokens", {})
    if not isinstance(tokens, Mapping):
        return False, sorted(set(failures + ["confused_deputy_rejected:tokens_missing"]))
    for name in required_tokens:
        token = tokens.get(name)
        if not isinstance(token, Mapping):
            failures.append(f"confused_deputy_rejected:missing_token:{name}")
            continue
        if token.get("name") != name or token.get("issued_at_stage") != TOKEN_STAGE.get(name):
            failures.append(f"signed_field_substitution_detected:{name}")
            continue
        if not verify_token(token, expected_request_fingerprint=state.get("request_fingerprint")):
            failures.append(f"signature_payload_mismatch:{name}")
            continue
        payload = token.get("payload", {})
        if not isinstance(payload, Mapping) or not _semantic_token_matches(state, name, payload):
            failures.append(f"validation_state_mismatch:{name}")
            continue
        matching_trace = [
            entry
            for entry in state.get("token_trace", [])
            if isinstance(entry, Mapping)
            and entry.get("event") == "ISSUED"
            and entry.get("name") == name
            and entry.get("stage") == token.get("issued_at_stage")
            and entry.get("issued_at") == token.get("issued_at")
            and entry.get("digest") == token.get("digest")
        ]
        if len(matching_trace) != 1:
            failures.append(f"token_lineage_mismatch:{name}")
    return not failures, sorted(set(failures))
