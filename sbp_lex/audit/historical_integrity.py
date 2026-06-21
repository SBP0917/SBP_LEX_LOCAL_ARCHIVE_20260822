from __future__ import annotations

from typing import Any, Mapping

from sbp_lex.audit.audit_finalisation import verify_audit_record
from sbp_lex.security.execution_attestation import verify_execution_attestation
from sbp_lex.security.pqc import generate_digest, verify_signature
from sbp_lex.shared.hash_chain import verify_hash_chain

AUDIT_CORRUPTION_DETECTED = "AUDIT_CORRUPTION_DETECTED"
HASH_CHAIN_MISMATCH = "HASH_CHAIN_MISMATCH"
LINEAGE_MISMATCH = "LINEAGE_MISMATCH"
ROOT_OF_TRUST_MISMATCH = "ROOT_OF_TRUST_MISMATCH"
REQUEST_IDENTITY_MISMATCH = "REQUEST_IDENTITY_MISMATCH"
PT_ENVELOPE_MISMATCH = "PT_ENVELOPE_MISMATCH"


def _append(failures: list[str], reason: str) -> None:
    if reason not in failures:
        failures.append(reason)


def verify_historical_state(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    audit_record = state.get("audit_record", {})
    audit_payload = audit_record.get("payload", {}) if isinstance(audit_record, Mapping) else {}
    integration = audit_payload.get("integration_evidence", {}) if isinstance(audit_payload, Mapping) else {}
    binding = integration.get("procedural_truth_binding", {}) if isinstance(integration, Mapping) else {}

    if not verify_audit_record(audit_record):
        _append(failures, AUDIT_CORRUPTION_DETECTED)
    if state.get("audit_hash") != audit_record.get("audit_hash"):
        _append(failures, AUDIT_CORRUPTION_DETECTED)

    if not verify_hash_chain(state):
        _append(failures, HASH_CHAIN_MISMATCH)
    audit_chain = audit_payload.get("audit_chain", []) if isinstance(audit_payload, Mapping) else []
    if not isinstance(audit_chain, list) or not verify_hash_chain({"hash_chain": audit_chain}):
        _append(failures, HASH_CHAIN_MISMATCH)
    state_chain = state.get("hash_chain", [])
    if not isinstance(state_chain, list) or state_chain[: len(audit_chain)] != audit_chain:
        _append(failures, HASH_CHAIN_MISMATCH)

    request_fingerprint = state.get("request_fingerprint")
    envelope = state.get("pt_evidence_envelope", {})
    if not isinstance(envelope, Mapping):
        envelope = {}
        _append(failures, PT_ENVELOPE_MISMATCH)
    if state.get("pt_evidence_envelope_digest") != generate_digest(dict(envelope)):
        _append(failures, PT_ENVELOPE_MISMATCH)
    if (
        not request_fingerprint
        or audit_payload.get("request_fingerprint") != request_fingerprint
        or envelope.get("request_fingerprint") != request_fingerprint
        or any(entry.get("request_fingerprint") != request_fingerprint for entry in state_chain)
    ):
        _append(failures, REQUEST_IDENTITY_MISMATCH)

    anchor = state.get("root_of_trust_evidence_anchor", {})
    anchor_payload = anchor.get("payload", {}) if isinstance(anchor, Mapping) else {}
    anchor_valid = (
        isinstance(anchor, Mapping)
        and isinstance(anchor_payload, Mapping)
        and anchor.get("valid") is True
        and anchor.get("anchor_digest") == generate_digest(dict(anchor_payload))
        and verify_signature(anchor_payload, anchor.get("signature", {}))
    )
    expected_anchor = {
        "request_fingerprint": request_fingerprint,
        "skg_digest": envelope.get("skg_digest"),
        "dtn_digest": envelope.get("dtn_digest"),
        "pre_context_digest": envelope.get("pre_context_digest"),
        "pt_evidence_envelope_digest": state.get("pt_evidence_envelope_digest"),
    }
    if not anchor_valid or dict(anchor_payload) != expected_anchor:
        _append(failures, ROOT_OF_TRUST_MISMATCH)
    if binding.get("root_of_trust_evidence_anchor") != anchor:
        _append(failures, ROOT_OF_TRUST_MISMATCH)

    if (
        binding.get("pt_envelope_digest") != state.get("pt_evidence_envelope_digest")
        or binding.get("pt_outcome") != state.get("procedural_truth_outcome")
        or integration.get("procedural_truth_result") != state.get("procedural_truth_result")
    ):
        _append(failures, LINEAGE_MISMATCH)
    expected_audit_stages = [
        stage for stage in state.get("integration_stage_order", []) if stage != "controlled_return"
    ]
    if integration.get("stage_order") != expected_audit_stages:
        _append(failures, LINEAGE_MISMATCH)
    for field in ("decision", "execution_verified", "pipeline_mode"):
        if audit_payload.get(field) != state.get(field):
            _append(failures, LINEAGE_MISMATCH)
    if not verify_execution_attestation(state, state.get("execution_attestation", {})):
        _append(failures, LINEAGE_MISMATCH)

    return not failures, failures
