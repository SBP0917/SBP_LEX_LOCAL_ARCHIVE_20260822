from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from sbp_lex.execution.capability import STATES as H7_CAPABILITY_STATES, TRANSITIONS as H7_TRANSITIONS
from sbp_lex.formal.model import (
    ARCHITECTURAL_STATES,
    CANONICAL_CONTROL_STATES,
    FORMAL_EVIDENCE_VERSION,
    FORMAL_MODEL_VERSION,
    PIPELINE_MODES,
    TRANSITION_RECORDS,
)
from sbp_lex.formal.verifier import (
    ASSURANCE_DOMAIN,
    ASSURANCE_OWNER,
    LINEAGE_ORDER,
    SAFE_CONVERGENCE,
)
from sbp_lex.security.pqc import generate_digest, sign_payload, verify_signature

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPOSITORY_ROOT / "outputs" / "phq_formal_architecture_assurance.json"
ARTIFACT_VERSION = "PHQ_DESKTOP_V1_FORMAL_ASSURANCE_ARTIFACT_V1"
SOURCE_PATHS = (
    "sbp_lex/formal/__init__.py",
    "sbp_lex/formal/model.py",
    "sbp_lex/formal/verifier.py",
    "sbp_lex/formal/assurance.py",
    "sbp_lex/formal/schemas/formal_state.schema.json",
    "sbp_lex/formal/schemas/transition_record.schema.json",
    "sbp_lex/formal/schemas/lineage_node.schema.json",
)
INVARIANT_IDENTIFIERS = (
    "external_non_authority", "canonical_state_singularity", "attachment_order",
    "trust_precedence", "procedural_precedence", "classification_licensing_separation",
    "governance_grc_precedence", "domain_limitation", "aurion_limitation",
    "execution_gate_finality", "h7_execution_integrity", "audit_continuity",
    "desktop_v1_no_node_boundary",
)
CONSERVATION_IDENTIFIERS = (
    "authority", "permission", "constraint", "denial", "identity", "request", "state",
    "evidence", "classification", "licensing", "consequentiality", "corroboration",
    "token_scope", "audit",
)
MUTATION_IDENTIFIERS = (
    "classification_before_licensing", "governance_before_grc",
    "domain_cannot_restore_governance_deny", "aurion_cannot_self_authorize",
    "mode1_exact_parity", "request_fingerprint_binding", "canonical_state_hash_binding",
    "token_stage_validation", "h7_single_use", "h7_cancellation", "constraint_continuity",
    "audit_required", "external_state_construction_denied", "attachment_after_state",
    "procedural_truth_after_root", "direct_downstream_reentry_denied",
)


class FormalAssuranceError(RuntimeError):
    pass


def _source_measurements(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for relative in SOURCE_PATHS:
        path = root / relative
        if not path.is_file():
            raise FormalAssuranceError(f"formal_assurance_source_missing:{relative}")
        data = path.read_bytes()
        records.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    return records


def build_payload(root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    transitions = [item.as_payload() for item in TRANSITION_RECORDS]
    payload = {
        "artifact_version": ARTIFACT_VERSION,
        "model_version": FORMAL_MODEL_VERSION,
        "evidence_version": FORMAL_EVIDENCE_VERSION,
        "assurance_owner": ASSURANCE_OWNER,
        "authority_granted": False,
        "formalisation_boundary": "DETACHED_NON_AUTHORITATIVE_ASSURANCE_ONLY",
        "architecture": "SBP_LEX_DUAL_V6_DESKTOP_V1",
        "topology": "LOCAL_PRIVATE_SINGLE_HOST_NO_NODE",
        "canonical_control_states": list(CANONICAL_CONTROL_STATES),
        "architectural_states": sorted(ARCHITECTURAL_STATES),
        "transition_records": transitions,
        "pipeline_modes": list(PIPELINE_MODES),
        "lineage_order": list(LINEAGE_ORDER),
        "safe_convergence": dict(sorted(SAFE_CONVERGENCE.items())),
        "architectural_invariants": list(INVARIANT_IDENTIFIERS),
        "conservation_laws": list(CONSERVATION_IDENTIFIERS),
        "mutation_protection": list(MUTATION_IDENTIFIERS),
        "h7_capability_states": sorted(H7_CAPABILITY_STATES),
        "h7_capability_transitions": {key: sorted(value) for key, value in sorted(H7_TRANSITIONS.items())},
        "source_measurements": _source_measurements(root),
    }
    normalized = json.loads(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    normalized["formal_specification_digest"] = generate_digest(normalized)
    return normalized


def build_artifact(root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    payload = build_payload(root)
    signed = {"integrity_domain": ASSURANCE_DOMAIN, "payload": payload}
    return {
        "payload": payload,
        "payload_digest": generate_digest(payload),
        "integrity_signature": sign_payload(signed),
    }


def validate_artifact(value: Mapping[str, Any], root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    if set(value) != {"payload", "payload_digest", "integrity_signature"}:
        raise FormalAssuranceError("formal_assurance_wrapper_schema_invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise FormalAssuranceError("formal_assurance_payload_invalid")
    if value.get("payload_digest") != generate_digest(payload):
        raise FormalAssuranceError("formal_assurance_digest_invalid")
    if not verify_signature(
        {"integrity_domain": ASSURANCE_DOMAIN, "payload": dict(payload)},
        value.get("integrity_signature", {}),
    ):
        raise FormalAssuranceError("formal_assurance_signature_invalid")
    expected = build_payload(root)
    if dict(payload) != expected:
        raise FormalAssuranceError("formal_assurance_stale_or_substituted")
    if payload.get("authority_granted") is not False:
        raise FormalAssuranceError("formal_assurance_authority_boundary_invalid")
    return dict(payload)


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    data = (json.dumps(dict(value), indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise FormalAssuranceError("formal_assurance_atomic_write_failed") from exc


def write_artifact(path: Path = DEFAULT_OUTPUT, root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    artifact = build_artifact(root)
    _atomic_write(path, artifact)
    validate_artifact(artifact, root)
    return artifact


def load_artifact(path: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FormalAssuranceError("formal_assurance_artifact_unreadable") from exc
    if not isinstance(value, dict):
        raise FormalAssuranceError("formal_assurance_artifact_invalid")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PHQ formal architectural assurance evidence")
    parser.add_argument("command", choices=("build", "validate", "show"))
    parser.add_argument("--path", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if args.command == "build":
        artifact = write_artifact(args.path)
    else:
        artifact = load_artifact(args.path)
        validate_artifact(artifact)
    payload = artifact["payload"]
    print("PHQ_FORMAL_ASSURANCE_VALID")
    if args.command in {"build", "show"}:
        print(f"formal_specification_digest={payload['formal_specification_digest']}")
        print(f"architectural_states={len(payload['architectural_states'])}")
        print(f"transition_records={len(payload['transition_records'])}")
        print(f"authority_granted={str(payload['authority_granted']).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
