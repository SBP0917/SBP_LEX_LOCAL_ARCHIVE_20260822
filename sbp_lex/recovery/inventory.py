from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from sbp_lex.runtime.measured_startup import load_baseline_store
from sbp_lex.formal.assurance import validate_artifact
from sbp_lex.security.pqc import generate_digest

from .common import (
    AUTHORITY_DOMAINS,
    DESKTOP_SCOPE,
    DOMAIN_ORDER,
    FORMATS,
    HEX64,
    LOGICAL_NAME,
    MAX_ARTIFACTS,
    MAX_ARTIFACT_BYTES,
    RECOVERY_VERSION,
    REQUIRED_STATUSES,
    SENSITIVITY_CLASSES,
    VALIDATION_METHODS,
    RecoveryError,
    portable_path,
    read_strict_json,
    resolve_beneath,
    scan_for_secrets,
    sha256_bytes,
    strict_json_bytes,
    atomic_json,
)

INVENTORY_VERSION = "R1_DESKTOP_V1_RECOVERY_INVENTORY_V1"
ARTEFACT_FIELDS = frozenset({
    "logical_name", "authority_domain", "source_path", "relative_recovery_path",
    "required_status", "sensitivity_class", "format", "current_digest",
    "size_bytes", "sequence", "predecessor_identity", "restore_order",
    "validation_method", "writer_authority",
})


@dataclass(frozen=True)
class ArtifactSpec:
    logical_name: str
    authority_domain: str
    source_path: str
    relative_recovery_path: str
    required_status: str
    sensitivity_class: str
    format: str
    sequence: int
    predecessor_identity: str | None
    restore_order: int
    validation_method: str
    writer_authority: str


DEFAULT_ARTIFACT_SPECS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec("configuration.version", "configuration", "VERSION", "configuration/VERSION", "REQUIRED", "PUBLIC_EVIDENCE", "text", 1, None, 100, "sha256", "repository_release_authority"),
    ArtifactSpec("configuration.requirements", "configuration", "requirements.txt", "configuration/requirements.txt", "REQUIRED", "PUBLIC_EVIDENCE", "text", 1, None, 110, "sha256", "repository_release_authority"),
    ArtifactSpec("configuration.environment_template", "configuration", ".env.example", "configuration/.env.example", "REQUIRED", "PUBLIC_EVIDENCE", "text", 1, None, 120, "sha256", "repository_configuration_authority"),
    ArtifactSpec("configuration.pytest_discovery", "configuration", "pytest.ini", "configuration/pytest.ini", "REQUIRED", "PUBLIC_EVIDENCE", "text", 1, None, 125, "sha256", "repository_test_authority"),
    ArtifactSpec("configuration.canonical_readme", "configuration", "README.md", "configuration/README.md", "REQUIRED", "PUBLIC_EVIDENCE", "text", 1, None, 130, "sha256", "repository_document_authority"),
    ArtifactSpec("configuration.protected_registry", "configuration", "sbp_lex/local_trust/critical_paths.py", "configuration/critical_paths.py", "REQUIRED", "PUBLIC_EVIDENCE", "text", 1, None, 140, "sha256", "local_trust_authority"),
    ArtifactSpec("security.integrity_ledger", "audit_attestations", "runtime_artifacts/integrity_store.jsonl", "audit/integrity_store.jsonl", "REQUIRED", "PROTECTED_PRIVATE", "jsonl", 1, None, 500, "integrity_store", "runtime_integrity_store"),
    ArtifactSpec("security.integrity_checkpoint", "audit_attestations", "runtime_artifacts/integrity_store.jsonl.checkpoint.json", "audit/integrity_store.checkpoint.json", "REQUIRED", "PROTECTED_PRIVATE", "json", 1, None, 510, "strict_json", "runtime_integrity_store"),
    ArtifactSpec("security.api_state_ledger", "security_state", "runtime_artifacts/api_security_state/security_state.jsonl", "security/security_state.jsonl", "OPTIONAL", "PROTECTED_PRIVATE", "jsonl", 1, None, 200, "jsonl_hash_chain", "api_security_state_store"),
    ArtifactSpec("external.replay_ledger", "external_identity_replay", "runtime_artifacts/external_boundary/external_replay_ledger.jsonl", "external/external_replay_ledger.jsonl", "OPTIONAL", "PROTECTED_PRIVATE", "jsonl", 1, None, 300, "jsonl_hash_chain", "external_replay_store"),
    ArtifactSpec("execution.capability_lifecycle", "execution_integrity", "runtime_artifacts/execution_integrity/capability_lifecycle.jsonl", "execution/capability_lifecycle.jsonl", "OPTIONAL", "PROTECTED_PRIVATE", "jsonl", 1, None, 400, "jsonl_hash_chain", "execution_capability_store"),
    ArtifactSpec("measured.baseline_store", "measured_startup", "sbp_lex/runtime/approved_runtime_baselines.json", "measured/approved_runtime_baselines.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 600, "measured_baseline_store", "measured_startup_authority"),
    ArtifactSpec("measured.rollback_anchor", "measured_startup", "runtime_artifacts/measured_startup/measurement.anchor.json", "measured/measurement.anchor.json", "REQUIRED", "PROTECTED_PRIVATE", "json", 1, None, 610, "strict_json", "measured_startup_authority"),
    ArtifactSpec("measured.startup_attestation", "measured_startup", "runtime_artifacts/measured_startup/startup.attestation.json", "measured/startup.attestation.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 620, "strict_json", "measured_startup_authority"),
    ArtifactSpec("local_trust.root_manifest", "local_trust", "outputs/local_trust_root_manifest.json", "local_trust/root_manifest.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 700, "strict_json", "local_trust_authority"),
    ArtifactSpec("local_trust.execution_envelope", "local_trust", "outputs/local_execution_environment_trust_envelope.json", "local_trust/execution_envelope.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 710, "strict_json", "local_trust_authority"),
    ArtifactSpec("local_trust.evidence_chain", "local_trust", "outputs/local_evidence_chain.json", "local_trust/evidence_chain.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 720, "strict_json", "local_trust_authority"),
    ArtifactSpec("local_trust.constitutional_gates", "local_trust", "outputs/local_constitutional_gates.json", "local_trust/constitutional_gates.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 730, "strict_json", "constitutional_gate_authority"),
    ArtifactSpec("local_trust.toolchain_guard", "local_trust", "outputs/local_toolchain_guard.json", "local_trust/toolchain_guard.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 740, "strict_json", "toolchain_guard_authority"),
    ArtifactSpec("local_trust.capstone", "local_trust", "outputs/local_trust_25_year_capstone.json", "local_trust/capstone.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 750, "strict_json", "local_trust_capstone_authority"),
    ArtifactSpec("local_trust.release_manifest", "local_trust", "outputs/release_integrity_bundle/RELEASE_MANIFEST.json", "local_trust/release_manifest.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 760, "strict_json", "release_integrity_authority"),
    ArtifactSpec("formal.phq_assurance", "formal_assurance", "outputs/phq_formal_architecture_assurance.json", "formal/phq_formal_architecture_assurance.json", "REQUIRED", "PUBLIC_EVIDENCE", "json", 1, None, 800, "formal_assurance", "formal_assurance_authority"),
)


def _validate_content(raw: bytes, *, method: str, root: Path, source: Path) -> None:
    if method == "sha256":
        return
    if method == "strict_json":
        strict_json_bytes(raw, label="recovery_artefact")
        return
    if method == "measured_baseline_store":
        load_baseline_store(source)
        return
    if method == "formal_assurance":
        validate_artifact(read_strict_json(source, label="formal_assurance"), root=root)
        return
    if method == "jsonl_hash_chain":
        _validate_jsonl(raw)
        return
    if method == "integrity_store":
        from sbp_lex.persistence.integrity_store import verify_integrity_records

        records = _jsonl_records(raw)
        checkpoint_path = source.with_suffix(source.suffix + ".checkpoint.json")
        checkpoint = read_strict_json(checkpoint_path, label="integrity_checkpoint")
        valid, failures = verify_integrity_records(records, checkpoint)
        if not valid:
            reason = failures[0] if failures else "unknown"
            raise RecoveryError(f"integrity_store_invalid:{reason}")
        return
    raise RecoveryError("artefact_validation_method_unknown")


def _jsonl_records(raw: bytes) -> list[dict[str, Any]]:
    if not raw:
        raise RecoveryError("jsonl_empty")
    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            raise RecoveryError("jsonl_blank_record")
        records.append(strict_json_bytes(line, label="jsonl_record"))
    return records


def _validate_jsonl(raw: bytes) -> None:
    records = _jsonl_records(raw)
    sequences = [item.get("sequence") for item in records if "sequence" in item]
    if sequences:
        if any(not isinstance(value, int) or value <= 0 for value in sequences):
            raise RecoveryError("ledger_sequence_invalid")
        if sequences != sorted(sequences) or len(set(sequences)) != len(sequences):
            raise RecoveryError("ledger_sequence_invalid")
    previous: str | None = None
    for item in records:
        if "previous_hash" not in item:
            continue
        expected = item.get("previous_hash")
        if expected != previous and not (previous is None and expected == "GENESIS"):
            raise RecoveryError("ledger_linkage_invalid")
        claimed = item.get("record_hash")
        payload = {key: value for key, value in item.items() if key not in {"record_hash", "signature"}}
        calculated = generate_digest(payload)
        if claimed != calculated:
            raise RecoveryError("ledger_record_hash_invalid")
        previous = claimed


def validate_artefact_content(
    raw: bytes, record: Mapping[str, Any], *, validation_root: Path | None = None,
) -> None:
    """Validate a packaged artefact without trusting its filename or domain."""
    method = record.get("validation_method")
    if method == "sha256":
        return
    if method == "strict_json":
        strict_json_bytes(raw, label="restored_artefact")
        return
    if method == "jsonl_hash_chain":
        _validate_jsonl(raw)
        return
    if method == "integrity_store":
        _validate_jsonl(raw)
        return
    if method == "measured_baseline_store":
        from sbp_lex.runtime.measured_startup import validate_baseline_store

        validate_baseline_store(strict_json_bytes(raw, label="restored_measured_baseline"))
        return
    if method == "formal_assurance":
        value = strict_json_bytes(raw, label="restored_formal_assurance")
        if validation_root is not None:
            validate_artifact(value, root=validation_root.resolve())
        return
    raise RecoveryError("artefact_validation_method_unknown")


def build_inventory(
    source_root: Path,
    specs: Sequence[ArtifactSpec] = DEFAULT_ARTIFACT_SPECS,
    *,
    expected_required: Iterable[str] | None = None,
) -> dict[str, Any]:
    root = source_root.resolve()
    records: list[dict[str, Any]] = []
    for spec in specs:
        portable_path(spec.source_path, label="source_path")
        portable_path(spec.relative_recovery_path, label="recovery_path")
        source = resolve_beneath(root, spec.source_path, label="source_path")
        if not source.is_file():
            if spec.required_status == "OPTIONAL":
                continue
            raise RecoveryError(f"required_artefact_missing:{spec.logical_name}")
        if source.is_symlink():
            raise RecoveryError(f"source_symlink_rejected:{spec.logical_name}")
        raw = source.read_bytes()
        if not raw or len(raw) > MAX_ARTIFACT_BYTES:
            raise RecoveryError(f"artefact_size_invalid:{spec.logical_name}")
        scan_for_secrets(raw, logical_name=spec.logical_name)
        _validate_content(raw, method=spec.validation_method, root=root, source=source)
        records.append({
            "logical_name": spec.logical_name,
            "authority_domain": spec.authority_domain,
            "source_path": spec.source_path,
            "relative_recovery_path": spec.relative_recovery_path,
            "required_status": spec.required_status,
            "sensitivity_class": spec.sensitivity_class,
            "format": spec.format,
            "current_digest": sha256_bytes(raw),
            "size_bytes": len(raw),
            "sequence": spec.sequence,
            "predecessor_identity": spec.predecessor_identity,
            "restore_order": spec.restore_order,
            "validation_method": spec.validation_method,
            "writer_authority": spec.writer_authority,
        })
    records.sort(key=lambda item: (item["restore_order"], item["logical_name"]))
    payload = {
        "inventory_version": INVENTORY_VERSION,
        "recovery_version": RECOVERY_VERSION,
        "desktop_scope": DESKTOP_SCOPE,
        "artefacts": records,
    }
    payload["aggregate_digest"] = generate_digest(payload)
    return validate_inventory(payload, expected_required=expected_required)


def validate_inventory(
    value: Mapping[str, Any], *, expected_required: Iterable[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "inventory_version", "recovery_version", "desktop_scope", "artefacts", "aggregate_digest"
    }:
        raise RecoveryError("inventory_schema_invalid")
    if value.get("inventory_version") != INVENTORY_VERSION or value.get("recovery_version") != RECOVERY_VERSION:
        raise RecoveryError("inventory_version_invalid")
    if value.get("desktop_scope") != DESKTOP_SCOPE:
        raise RecoveryError("foreign_desktop_scope")
    artefacts = value.get("artefacts")
    if not isinstance(artefacts, list) or not artefacts or len(artefacts) > MAX_ARTIFACTS:
        raise RecoveryError("inventory_cardinality_invalid")
    logical_names: set[str] = set()
    recovery_paths: set[str] = set()
    required_names: set[str] = set()
    prior_order = 0
    for record in artefacts:
        if not isinstance(record, Mapping) or set(record) != ARTEFACT_FIELDS:
            raise RecoveryError("artefact_record_schema_invalid")
        name = record.get("logical_name")
        domain = record.get("authority_domain")
        if not isinstance(name, str) or not LOGICAL_NAME.fullmatch(name) or name in logical_names:
            raise RecoveryError("duplicate_logical_identity")
        if domain not in AUTHORITY_DOMAINS:
            raise RecoveryError("ambiguous_authority_domain")
        source_path = portable_path(record.get("source_path"), label="source_path")
        recovery_path = portable_path(record.get("relative_recovery_path"), label="recovery_path")
        if recovery_path in recovery_paths:
            raise RecoveryError("conflicting_restore_location")
        if record.get("required_status") not in REQUIRED_STATUSES:
            raise RecoveryError("required_status_invalid")
        if record.get("sensitivity_class") not in SENSITIVITY_CLASSES:
            raise RecoveryError("sensitivity_class_invalid")
        if record.get("format") not in FORMATS or record.get("validation_method") not in VALIDATION_METHODS:
            raise RecoveryError("artefact_format_invalid")
        digest = record.get("current_digest")
        predecessor = record.get("predecessor_identity")
        sequence = record.get("sequence")
        order = record.get("restore_order")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise RecoveryError("artefact_digest_invalid")
        if predecessor is not None and (not isinstance(predecessor, str) or not HEX64.fullmatch(predecessor)):
            raise RecoveryError("predecessor_identity_invalid")
        if not isinstance(sequence, int) or sequence <= 0:
            raise RecoveryError("artefact_sequence_invalid")
        if not isinstance(order, int) or order <= prior_order or order < DOMAIN_ORDER[domain] or order >= DOMAIN_ORDER[domain] + 100:
            raise RecoveryError("restore_order_invalid")
        if not isinstance(record.get("size_bytes"), int) or not 0 < record["size_bytes"] <= MAX_ARTIFACT_BYTES:
            raise RecoveryError("artefact_size_invalid")
        if not isinstance(record.get("writer_authority"), str) or not record["writer_authority"].strip():
            raise RecoveryError("writer_authority_invalid")
        if record["required_status"] == "REQUIRED":
            required_names.add(name)
        logical_names.add(name)
        recovery_paths.add(recovery_path)
        prior_order = order
        del source_path
    expected = set(expected_required) if expected_required is not None else required_names
    if required_names != expected:
        if required_names - expected:
            raise RecoveryError("unknown_required_artefact")
        raise RecoveryError("required_artefact_inventory_incomplete")
    payload = {key: json.loads(json.dumps(item)) for key, item in value.items() if key != "aggregate_digest"}
    if value.get("aggregate_digest") != generate_digest(payload):
        raise RecoveryError("inventory_aggregate_digest_invalid")
    return json.loads(json.dumps(value))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Desktop V1 recovery-critical inventory")
    parser.add_argument("command", choices=("build", "validate"))
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output).resolve(strict=False)
    if args.command == "build":
        inventory = build_inventory(Path(args.root))
        atomic_json(output, inventory)
        print("RECOVERY_INVENTORY_BUILT")
        print(f"artefacts={len(inventory['artefacts'])}")
        print(f"aggregate_digest={inventory['aggregate_digest']}")
        return 0
    value = read_strict_json(output, label="recovery_inventory")
    inventory = validate_inventory(value)
    print("RECOVERY_INVENTORY_VALID")
    print(f"artefacts={len(inventory['artefacts'])}")
    print(f"aggregate_digest={inventory['aggregate_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
