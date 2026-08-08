from __future__ import annotations

from typing import Any, Dict, Mapping

from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature
from sbp_lex.security.token_stack import verify_token
from sbp_lex.shared.hash_chain import verify_hash_chain


EXECUTION_ATTESTATION_VERSION = "SBP_LEX_V6_EXECUTION_ATTESTATION_2"
EXECUTION_ATTESTATION_WRAPPER_FIELDS = {
    "valid",
    "attestation_hash",
    "signature",
    "payload",
}
EXECUTION_BOUNDARY_PAYLOAD_FIELDS = {
    "clearance",
    "pre_gate_failures",
    "request_fingerprint",
    "eie_digest",
    "traversal_id",
    "tier",
    "collective_attachment_hash",
    "provider_mode",
    "execution_runtime_binding_digest",
    "audit_readiness_digest",
    "pre_gate_chain_tail",
}
MEASURED_RUNTIME_FIELDS = (
    "runtime_identity",
    "approved_baseline_identifier",
    "measurement_digest",
    "startup_attestation_digest",
    "startup_sequence",
)
AUDIT_READINESS_FIELDS = {
    "readiness_version",
    "ready",
    "request_fingerprint",
    "eie_digest",
    "gate_input_state_hash",
    "pre_gate_chain_tail",
    "audit_trace_digest",
    "expected_terminal_stage",
    "authority_role",
    "readiness_digest",
}
REQUIRED_EXECUTION_FIELDS = [
    "request_fingerprint",
    "decision",
    "pipeline_mode",
    "convergence_hash",
    "master_token",
    "execution_result",
    "execution_verified",
]
EXECUTION_ATTESTATION_PAYLOAD_FIELDS = {
    "version",
    "request_fingerprint",
    "historical_gate_state_hash",
    "execution_boundary_token_digest",
    "execution_boundary_state_hash",
    "execution_boundary_issued_at",
    "eie_digest",
    "traversal_id",
    "tier",
    "collective_attachment_hash",
    "execution_runtime_binding_digest",
    "runtime_identity",
    "approved_baseline_identifier",
    "measurement_digest",
    "startup_attestation_digest",
    "startup_sequence",
    "audit_readiness_digest",
    "decision",
    "pipeline_mode",
    "convergence_hash",
    "master_token",
    "execution_result",
    "execution_verified",
    "timestamp",
    "timestamp_authority",
}


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _is_digest(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _invalid(reason: str, missing: list[str] | None = None) -> Dict[str, Any]:
    record: Dict[str, Any] = {"valid": False, "reason": reason}
    if missing:
        record["missing"] = sorted(set(missing))
    return record


def _pre_gate_chain_tail(
    state: Mapping[str, Any], *, require_unentered_gate: bool
) -> tuple[str | None, list[str]]:
    if not verify_hash_chain(state):
        return None, ["execution_boundary_hash_chain_invalid"]
    chain = state.get("hash_chain", [])
    gate_entries = [
        entry
        for entry in chain
        if isinstance(entry, Mapping)
        and entry.get("stage") == "execution_gate"
    ]
    if require_unentered_gate:
        if gate_entries or chain[-1].get("stage") != "aurion_runtime":
            return None, ["execution_boundary_pre_gate_chain_invalid"]
        return str(chain[-1].get("hash")), []
    if not gate_entries:
        if chain[-1].get("stage") != "aurion_runtime":
            return None, ["execution_boundary_pre_gate_chain_invalid"]
        return str(chain[-1].get("hash")), []
    if len(gate_entries) != 1:
        return None, ["execution_boundary_gate_chain_duplicate"]
    return str(gate_entries[0].get("previous_hash")), []


def _execution_boundary_payload(
    state: Mapping[str, Any], *, require_unentered_gate: bool
) -> tuple[Dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    request_fingerprint = state.get("request_fingerprint")
    eie_digest = state.get("eie_hash")
    traversal_id = state.get("traversal_id")
    tier = _mapping(state.get("safety_profile")).get("computed_tier")
    collective_attachment_hash = _mapping(
        state.get("collective_attachment")
    ).get("attachment_hash")
    provider_mode = _mapping(
        state.get("verified_substrate_references")
    ).get("provider_mode")
    runtime_binding = state.get("execution_runtime_binding")
    audit_readiness = state.get("audit_readiness")
    chain_tail, chain_failures = _pre_gate_chain_tail(
        state, require_unentered_gate=require_unentered_gate
    )
    failures.extend(chain_failures)
    for field, value in (
        ("request_fingerprint", request_fingerprint),
        ("eie_digest", eie_digest),
        ("collective_attachment_hash", collective_attachment_hash),
        ("pre_gate_chain_tail", chain_tail),
    ):
        if not _is_digest(value):
            failures.append(f"execution_boundary_invalid:{field}")
    if not isinstance(traversal_id, str) or not traversal_id:
        failures.append("execution_boundary_invalid:traversal_id")
    if tier in (None, ""):
        failures.append("execution_boundary_invalid:tier")
    if provider_mode != "synthetic_local":
        failures.append("execution_boundary_provider_mode_invalid")
    if not isinstance(runtime_binding, Mapping) or not runtime_binding:
        failures.append("execution_boundary_runtime_binding_invalid")
        runtime_binding = {}
    if (
        not isinstance(audit_readiness, Mapping)
        or set(audit_readiness) != AUDIT_READINESS_FIELDS
        or audit_readiness.get("ready") is not True
        or audit_readiness.get("readiness_version")
        != "PASS7_AUDIT_READINESS_V1"
        or audit_readiness.get("request_fingerprint") != request_fingerprint
        or audit_readiness.get("eie_digest") != eie_digest
        or audit_readiness.get("pre_gate_chain_tail") != chain_tail
        or not _is_digest(audit_readiness.get("gate_input_state_hash"))
        or not _is_digest(audit_readiness.get("audit_trace_digest"))
        or audit_readiness.get("expected_terminal_stage") != "audit"
        or audit_readiness.get("authority_role")
        != "evidence_only_non_authoritative"
        or audit_readiness.get("readiness_digest")
        != generate_digest(
            {
                key: audit_readiness.get(key)
                for key in AUDIT_READINESS_FIELDS
                if key != "readiness_digest"
            }
        )
    ):
        failures.append("execution_boundary_audit_readiness_invalid")
        audit_readiness = {}
    if failures:
        return None, sorted(set(failures))
    payload = {
        "clearance": "CLEARED",
        "pre_gate_failures": [],
        "request_fingerprint": request_fingerprint,
        "eie_digest": eie_digest,
        "traversal_id": traversal_id,
        "tier": tier,
        "collective_attachment_hash": collective_attachment_hash,
        "provider_mode": provider_mode,
        "execution_runtime_binding_digest": generate_digest(
            dict(runtime_binding)
        ),
        "audit_readiness_digest": generate_digest(dict(audit_readiness)),
        "pre_gate_chain_tail": chain_tail,
    }
    return payload, []


def build_execution_boundary_payload(
    state: Mapping[str, Any],
) -> tuple[Dict[str, Any] | None, list[str]]:
    """Return the exact success-only boundary payload for token issuance."""

    if not isinstance(state, Mapping):
        return None, ["execution_boundary_state_invalid"]
    try:
        return _execution_boundary_payload(state, require_unentered_gate=True)
    except Exception:
        return None, ["execution_boundary_structure_invalid"]


def verify_execution_boundary_token(
    state: Mapping[str, Any],
    *,
    require_live_state_hash: bool = False,
) -> tuple[bool, list[str]]:
    """Verify exact clearance semantics and its pre-Gate chain/runtime bindings."""

    if not isinstance(state, Mapping):
        return False, ["execution_boundary_state_invalid"]
    try:
        tokens = state.get("tokens")
        if not isinstance(tokens, Mapping):
            return False, ["execution_boundary_token_store_invalid"]
        token = tokens.get("execution_boundary")
        if not isinstance(token, Mapping):
            return False, ["execution_boundary_token_missing"]
        expected_payload, payload_failures = _execution_boundary_payload(
            state, require_unentered_gate=False
        )
        failures = list(payload_failures)
        tier = _mapping(state.get("safety_profile")).get("computed_tier")
        if not verify_token(
            token,
            expected_request_fingerprint=state.get("request_fingerprint"),
            expected_name="execution_boundary",
            expected_stage="execution_gate",
            expected_state_hash=(
                state.get("state_hash") if require_live_state_hash else None
            ),
            expected_tier=tier,
        ):
            failures.append("execution_boundary_token_invalid")
        payload = token.get("payload")
        if (
            expected_payload is None
            or not isinstance(payload, Mapping)
            or set(payload) != EXECUTION_BOUNDARY_PAYLOAD_FIELDS
            or dict(payload) != expected_payload
        ):
            failures.append("execution_boundary_payload_invalid")
        return not failures, sorted(set(failures))
    except Exception:
        return False, ["execution_boundary_structure_invalid"]


def _expected_attestation_payload(
    state: Mapping[str, Any], *, require_live_gate_state: bool
) -> tuple[Dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    tokens = state.get("tokens")
    if not isinstance(tokens, Mapping):
        return None, ["execution_token_store_invalid"]

    request_fingerprint = state.get("request_fingerprint")
    tier = _mapping(state.get("safety_profile")).get("computed_tier")
    boundary = tokens.get("execution_boundary")
    if not isinstance(boundary, Mapping):
        return None, ["execution_boundary_token_missing"]
    boundary_valid, boundary_failures = verify_execution_boundary_token(
        state, require_live_state_hash=require_live_gate_state
    )
    if not boundary_valid:
        failures.extend(boundary_failures)
    historical_state_hash = boundary.get("state_hash")
    if not _is_digest(historical_state_hash):
        failures.append("execution_boundary_state_hash_invalid")
    if require_live_gate_state and state.get("state_hash") != historical_state_hash:
        failures.append("execution_boundary_live_state_hash_mismatch")

    convergence = _mapping(state.get("execution_convergence"))
    convergence_payload = _mapping(convergence.get("payload"))
    if convergence_payload.get("state_hash") != historical_state_hash:
        failures.append("execution_convergence_state_hash_mismatch")
    if convergence.get("convergence_hash") != state.get("convergence_hash"):
        failures.append("execution_convergence_digest_mismatch")

    master = tokens.get("master_convergence")
    master_payload = _mapping(
        master.get("payload") if isinstance(master, Mapping) else None
    )
    if not isinstance(master, Mapping):
        failures.append("master_convergence_token_missing")
    else:
        if master.get("state_hash") != historical_state_hash:
            failures.append("master_convergence_state_hash_mismatch")
        if master_payload.get("state_hash") != historical_state_hash:
            failures.append("master_convergence_payload_state_hash_mismatch")
        if master.get("digest") != state.get("master_token"):
            failures.append("master_convergence_digest_mismatch")

    eie_digest = state.get("eie_hash")
    traversal_id = state.get("traversal_id")
    collective_attachment_hash = _mapping(
        state.get("collective_attachment")
    ).get("attachment_hash")
    if not _is_digest(request_fingerprint):
        failures.append("execution_request_fingerprint_invalid")
    if not _is_digest(eie_digest):
        failures.append("execution_eie_digest_invalid")
    if not isinstance(traversal_id, str) or not traversal_id:
        failures.append("execution_traversal_id_invalid")
    if tier in (None, ""):
        failures.append("execution_tier_invalid")
    if not _is_digest(collective_attachment_hash):
        failures.append("execution_collective_attachment_hash_invalid")

    runtime_binding = state.get("execution_runtime_binding")
    if not isinstance(runtime_binding, Mapping) or not runtime_binding:
        failures.append("execution_runtime_binding_missing")
        runtime_binding = {}
    runtime_binding_digest = generate_digest(dict(runtime_binding))
    for field in MEASURED_RUNTIME_FIELDS:
        value = runtime_binding.get(field)
        if field == "approved_baseline_identifier":
            if not isinstance(value, str) or not value:
                failures.append(f"execution_runtime_binding_invalid:{field}")
        elif field == "startup_sequence":
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                failures.append(f"execution_runtime_binding_invalid:{field}")
        elif not _is_digest(value):
            failures.append(f"execution_runtime_binding_invalid:{field}")

    audit_readiness = state.get("audit_readiness")
    if not isinstance(audit_readiness, Mapping) or not audit_readiness:
        failures.append("audit_readiness_missing")
        audit_readiness = {}
    audit_readiness_digest = generate_digest(dict(audit_readiness))

    missing = [field for field in REQUIRED_EXECUTION_FIELDS if state.get(field) is None]
    if missing:
        failures.extend(f"execution_field_missing:{field}" for field in missing)
    timestamp = state.get("execution_timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        failures.append("execution_timestamp_invalid")

    if failures:
        return None, sorted(set(failures))
    payload: Dict[str, Any] = {
        "version": EXECUTION_ATTESTATION_VERSION,
        "request_fingerprint": request_fingerprint,
        "historical_gate_state_hash": historical_state_hash,
        "execution_boundary_token_digest": boundary.get("digest"),
        "execution_boundary_state_hash": historical_state_hash,
        "execution_boundary_issued_at": boundary.get("issued_at"),
        "eie_digest": eie_digest,
        "traversal_id": traversal_id,
        "tier": tier,
        "collective_attachment_hash": collective_attachment_hash,
        "execution_runtime_binding_digest": runtime_binding_digest,
        **{
            field: runtime_binding.get(field)
            for field in MEASURED_RUNTIME_FIELDS
        },
        "audit_readiness_digest": audit_readiness_digest,
        "decision": state.get("decision"),
        "pipeline_mode": state.get("pipeline_mode"),
        "convergence_hash": state.get("convergence_hash"),
        "master_token": state.get("master_token"),
        "execution_result": state.get("execution_result"),
        "execution_verified": state.get("execution_verified"),
        "timestamp": timestamp,
        "timestamp_authority": "CANONICAL_RUNTIME",
    }
    return payload, []


def build_execution_attestation(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Build an exact signed Gate attestation or a non-raising invalid record."""

    if not isinstance(state, Mapping):
        return _invalid("EXECUTION_STATE_INVALID")
    try:
        payload, failures = _expected_attestation_payload(
            state, require_live_gate_state=True
        )
        if payload is None:
            return _invalid("EXECUTION_BINDING_INVALID", failures)
        if set(payload) != EXECUTION_ATTESTATION_PAYLOAD_FIELDS:
            return _invalid("EXECUTION_ATTESTATION_SCHEMA_INVALID")
        digest = generate_digest(payload)
        signature = sign_payload(payload)
        return {
            "valid": verify_signature(payload, signature),
            "attestation_hash": digest,
            "signature": signature,
            "payload": payload,
        }
    except Exception:
        return _invalid("EXECUTION_ATTESTATION_BUILD_FAILED")


def verify_execution_attestation(
    state: Mapping[str, Any], attestation: Mapping[str, Any]
) -> bool:
    """Verify the exact attestation against its historical Gate state."""

    if not isinstance(state, Mapping) or not isinstance(attestation, Mapping):
        return False
    if set(attestation) != EXECUTION_ATTESTATION_WRAPPER_FIELDS:
        return False
    if attestation.get("valid") is not True:
        return False
    payload = attestation.get("payload")
    if not isinstance(payload, Mapping):
        return False
    if set(payload) != EXECUTION_ATTESTATION_PAYLOAD_FIELDS:
        return False
    try:
        expected, failures = _expected_attestation_payload(
            state, require_live_gate_state=False
        )
        if expected is None or failures or dict(payload) != expected:
            return False
        if attestation.get("attestation_hash") != generate_digest(payload):
            return False
        return verify_signature(payload, attestation.get("signature", {}))
    except Exception:
        return False
